//! Roster `apply_*` methods for the [`Coordinator`].
//!
//! These methods mutate the in-memory roster ONLY — no event publication,
//! no SSE broadcast. `register` / `heartbeat` / `deregister` publish the
//! corresponding event first, then call the matching `apply_*` so the
//! in-memory state is derived from the same data that was emitted to the
//! roster-change sink.
//!
//! Keeping mutation behind a single apply seam means the in-memory roster
//! never diverges from a hypothetical "fold over the event stream"
//! derivation — useful if a durable loader is added behind the same
//! [`crate::publisher::EventPublisher`] seam later.

use crate::roster::coordinator::{Coordinator, CoordinatorError, PeerEntry};
use crate::roster::events::{PeerHeartbeat, PeerJoined, PeerLeft};
use std::net::Ipv6Addr;
use std::time::Instant;
use uuid::Uuid;

impl Coordinator {
    /// Apply a `PeerJoined` event to in-memory roster (without re-publishing).
    /// Called after a successful event publication; also reusable by a
    /// future durable loader.
    ///
    /// # Errors
    /// `InvalidPeerId` if the event's `peer_id` or `ula` is malformed.
    pub fn apply_peer_joined(&self, event: &PeerJoined) -> Result<PeerEntry, CoordinatorError> {
        let peer_id = Uuid::parse_str(&event.peer_id)
            .map_err(|e| CoordinatorError::InvalidPeerId(e.to_string()))?;
        let ula: Ipv6Addr = event.ula.parse().map_err(|e: std::net::AddrParseError| {
            CoordinatorError::InvalidPeerId(e.to_string())
        })?;
        // ULA layout is fd5a:1f00:<network16>:<idx>::1 — the network slot
        // lives in the 3rd hextet, the per-network index in the 4th.
        let network_slot = ula.segments()[2];
        let peer_index = ula.segments()[3];
        let entry = PeerEntry {
            peer_id,
            wg_public_key: event.wg_public_key.clone(),
            ula,
            peer_index,
            listen_endpoint: if event.listen_endpoint.is_empty() {
                None
            } else {
                Some(event.listen_endpoint.clone())
            },
            display_name: event.display_name.clone(),
            network: event.network.clone(),
            tags: event.tags.clone(),
            hosted_app_ulas: event.hosted_app_ulas.clone(),
            joined_at_micros: event.joined_at_micros,
            last_heartbeat: Instant::now(),
            // No heartbeat has been recorded yet; the heartbeat path
            // populates this. Empty string means "unknown" — the Stage 2
            // hole-punch logic checks `is_empty()` to skip.
            observed_external: String::new(),
            // Conservative default: the apply layer derives state purely
            // from the `PeerJoined` event, which doesn't carry the
            // reflexive discriminator. `register_authenticated` overwrites
            // this with the true value immediately after apply; a hostname
            // / public endpoint loaded by a future durable replayer is
            // therefore treated as sticky (the safe choice — it just
            // means a replayed endpoint won't auto-roam until the next
            // live register).
            endpoint_is_reflexive: false,
            kind: event.kind.clone(),
            parent: event.parent.clone(),
            app_uuid: event.app_uuid.clone(),
            software_version: event.software_version.clone(),
            mesh_version: event.mesh_version.clone(),
            relay_only: event.relay_only,
            // Connectivity edges are ephemeral live-state, not carried in the
            // durable `PeerJoined` event: a freshly-joined (or restored) peer
            // starts with none and populates them on its first heartbeat.
            paths: std::collections::HashMap::new(),
        };
        self.inner.roster.insert(peer_id, entry.clone());
        self.inner
            .by_pubkey
            .insert(event.wg_public_key.clone(), peer_id);
        // Advance the allocator past this index *within this network's
        // block* so a future allocate() in the same network won't collide.
        self.inner
            .allocator
            .bump_slot_at_least(network_slot, peer_index);
        Ok(entry)
    }

    /// Apply a `PeerHeartbeat` event to in-memory roster (without re-publishing).
    /// Unknown peer ids and malformed UUIDs are silently dropped — a
    /// heartbeat can race a deregister for a peer that already left.
    pub fn apply_peer_heartbeat(&self, event: &PeerHeartbeat) {
        let Ok(peer_id) = Uuid::parse_str(&event.peer_id) else {
            return;
        };
        if let Some(mut entry) = self.inner.roster.get_mut(&peer_id) {
            entry.last_heartbeat = Instant::now();
            // Stamp the observed external too so the Stage 2 hole-punch
            // logic can iterate over the roster and emit pairs without
            // re-reading the event.
            entry.observed_external.clone_from(&event.observed_external);
            // REPLACE the hosted app-ULA set with the heartbeat's set: a
            // supervisor re-sends its full hosted set every tick, so the
            // stored set tracks exactly what the peer hosts right now —
            // adds and removals both fall out of the wholesale replace
            // (per-app-ULA routing). The change-detection + re-broadcast
            // lives in [`Coordinator::heartbeat`], which compares before
            // and after this apply.
            entry.hosted_app_ulas.clone_from(&event.hosted_app_ulas);
            // A heartbeat that omits the version (`None`) must NOT clobber
            // the stored value — only a present value updates it (spec P0:
            // `None` is unknown, never a downgrade).
            if event.software_version.is_some() {
                entry.software_version.clone_from(&event.software_version);
            }
            // Same no-clobber rule for the mesh-joiner version.
            if event.mesh_version.is_some() {
                entry.mesh_version.clone_from(&event.mesh_version);
            }
        }
    }

    /// Apply a `PeerLeft` event to in-memory roster (without re-publishing).
    /// Unknown peer ids and malformed UUIDs are silently dropped.
    pub fn apply_peer_left(&self, event: &PeerLeft) {
        let Ok(peer_id) = Uuid::parse_str(&event.peer_id) else {
            return;
        };
        if let Some((_, entry)) = self.inner.roster.remove(&peer_id) {
            self.inner.by_pubkey.remove(&entry.wg_public_key);
            // Tear down any live relay connection for this pubkey — a peer
            // that left the roster must no longer be a relay endpoint.
            self.inner.relay.drop_pubkey(&entry.wg_public_key);
            // Drop this peer's hole-punch pairs immediately (the precise path;
            // the TTL reaper is only a backstop for peers that vanish without
            // a clean deregister) so the tracker doesn't accumulate dead pairs.
            self.inner.punch_tracker.remove_peer(peer_id);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::publisher::NoopPublisher;
    use std::sync::Arc;
    use std::time::Duration;

    /// Exercises the public apply_* surface directly: a joined peer lands
    /// in the roster, a heartbeat for it (and an unknown one) behaves, and
    /// a left removes it.
    #[tokio::test]
    async fn apply_methods_can_be_called_directly() {
        let coord = Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(60));
        let peer_id = uuid::Uuid::now_v7();
        let joined = PeerJoined {
            peer_id: peer_id.to_string(),
            wg_public_key: vec![1; 32],
            ula: "fd5a:1f00:1:5::1".into(),
            listen_endpoint: "127.0.0.1:51820".into(),
            display_name: "test".into(),
            network: "n1".into(),
            tags: vec!["t1".into()],
            hosted_app_ulas: vec![],
            joined_at_micros: 1,
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            software_version: None,
            mesh_version: None,
            relay_only: false,
        };
        let entry = coord.apply_peer_joined(&joined).expect("apply joined");
        assert_eq!(entry.peer_index, 5);
        assert_eq!(coord.snapshot().len(), 1);

        // Heartbeat for the known peer should land without error.
        let hb = PeerHeartbeat {
            peer_id: peer_id.to_string(),
            observed_external: "203.0.113.1:51820".into(),
            hosted_app_ulas: vec![],
            software_version: None,
            mesh_version: None,
            at_micros: 2,
        };
        coord.apply_peer_heartbeat(&hb);
        // Heartbeat for unknown peer is silently dropped.
        let unknown_hb = PeerHeartbeat {
            peer_id: uuid::Uuid::now_v7().to_string(),
            observed_external: String::new(),
            hosted_app_ulas: vec![],
            software_version: None,
            mesh_version: None,
            at_micros: 3,
        };
        coord.apply_peer_heartbeat(&unknown_hb);
        assert_eq!(coord.snapshot().len(), 1);

        // PeerLeft removes the entry from roster + by_pubkey.
        let left = PeerLeft {
            peer_id: peer_id.to_string(),
            reason: "shutdown".into(),
            left_at_micros: 4,
        };
        coord.apply_peer_left(&left);
        assert_eq!(coord.snapshot().len(), 0);
    }

    /// A relay connection registered for a peer's pubkey must be torn down
    /// when that peer leaves the roster — otherwise a stale connection could
    /// keep receiving relayed frames for a pubkey that is no longer a peer.
    #[tokio::test]
    async fn apply_peer_left_drops_relay_conn() {
        let coord = Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(60));
        let peer_id = uuid::Uuid::now_v7();
        let pubkey = vec![1u8; 32];
        let joined = PeerJoined {
            peer_id: peer_id.to_string(),
            wg_public_key: pubkey.clone(),
            ula: "fd5a:1f00:1:5::1".into(),
            listen_endpoint: String::new(),
            display_name: "test".into(),
            network: "n1".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            joined_at_micros: 1,
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            software_version: None,
            mesh_version: None,
            relay_only: false,
        };
        coord.apply_peer_joined(&joined).expect("apply joined");
        // Register a live relay connection (lo lane) for this peer's pubkey.
        let (lo, _lo_rx) = tokio::sync::mpsc::channel(16);
        coord
            .relay()
            .register(&pubkey, crate::relay::Lane::Lo, lo);
        assert!(
            coord.relay().forward(&pubkey, vec![1, 2, 3], false),
            "relay forward should reach the live conn before peer-left"
        );
        // Peer leaves -> its relay conn must be dropped.
        let left = PeerLeft {
            peer_id: peer_id.to_string(),
            reason: "shutdown".into(),
            left_at_micros: 2,
        };
        coord.apply_peer_left(&left);
        assert!(
            !coord.relay().forward(&pubkey, vec![4, 5, 6], false),
            "relay conn must be gone after peer-left"
        );
    }

    #[tokio::test]
    async fn apply_peer_joined_advances_allocator_within_network() {
        use crate::roster::allocator::{UlaAllocator, network_slot};
        let coord = Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(60));
        // Apply a peer at index 7 in network "net7" — a subsequent register
        // in the SAME network must NOT collide. Build the ULA from the
        // allocator's own layout so the network slot in the address matches
        // what `network_slot("net7")` will compute on register.
        let slot = network_slot("net7");
        let ula = UlaAllocator::address_for(slot, 7);
        let joined = PeerJoined {
            peer_id: uuid::Uuid::now_v7().to_string(),
            wg_public_key: vec![9; 32],
            ula: ula.to_string(),
            listen_endpoint: String::new(),
            display_name: "applied".into(),
            network: "net7".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            joined_at_micros: 1,
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            software_version: None,
            mesh_version: None,
            relay_only: false,
        };
        coord.apply_peer_joined(&joined).expect("apply");
        // Next live register in net7 should land on index 8.
        let req = crate::http::api::RegisterRequest {
            wg_public_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [42_u8; 32],
            ),
            listen_endpoint: None,
            wg_listen_port: None,
            display_name: "fresh".into(),
            network: "net7".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            requested_ula: None,
            software_version: None,
            mesh_version: None,
            relay_only: false,
        };
        let (entry, _) = coord.register(req).await.expect("register");
        assert_eq!(entry.peer_index, 8);
    }

    #[tokio::test]
    async fn apply_peer_joined_rejects_invalid_uuid() {
        let coord = Coordinator::new(Arc::new(NoopPublisher), Duration::from_secs(60));
        let bad = PeerJoined {
            peer_id: "not-a-uuid".into(),
            wg_public_key: vec![1; 32],
            ula: "fd5a:1f00:1:5::1".into(),
            listen_endpoint: String::new(),
            display_name: "x".into(),
            network: "n1".into(),
            tags: vec![],
            hosted_app_ulas: vec![],
            joined_at_micros: 1,
            kind: "peer".into(),
            parent: None,
            app_uuid: None,
            software_version: None,
            mesh_version: None,
            relay_only: false,
        };
        let err = coord.apply_peer_joined(&bad).expect_err("bad uuid");
        assert!(matches!(
            err,
            crate::roster::coordinator::CoordinatorError::InvalidPeerId(_)
        ));
    }
}
