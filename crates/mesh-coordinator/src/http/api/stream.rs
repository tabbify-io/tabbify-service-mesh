//! SSE stream handler + per-viewer ACL filter for
//! `GET /v1/mesh/peers/stream`.
//!
//! The broadcast channel is shared across all subscribers, so filtering
//! is per-subscriber here rather than at broadcast time. The
//! [`ViewerFilter`] is *stateful*: it remembers which peer ids it has
//! currently revealed to this viewer so policy changes converge with
//! synthetic add/remove frames.

use super::RosterApiState;
use super::dto::{PeerInfo, StreamQuery};
use crate::http::admin_auth::{check_admin_bearer, err};
use crate::http::sse::PeerEvent;
use crate::roster::coordinator::Coordinator;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event as SseFrame, KeepAlive, Sse},
    },
};
use futures::stream::{Stream, StreamExt};
use std::collections::HashSet;
use std::convert::Infallible;
use std::str::FromStr;
use std::time::Duration;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tracing::warn;
use uuid::Uuid;

/// Live SSE stream of peer-lifecycle + hole-punch events. The connection
/// opens with a bootstrap burst of the current roster (one `peer_added`
/// frame per peer), then forwards `peer_added` / `peer_updated` /
/// `peer_removed` / `holepunch_initiate` frames as they happen.
///
/// # Auth — viewer resolution fails CLOSED
///
/// - `peer_id` names a peer in the roster → per-viewer ACL-filtered stream,
///   hole-punch frames routed by initiator. This is the joiner's path and
///   needs no bearer: the identity is checked against the live roster.
/// - `peer_id` is malformed, or names a peer that is not (or no longer) in
///   the roster → `401`. An identity the coordinator cannot resolve must
///   never WIDEN the view; previously all three of these collapsed to "no
///   filter" and streamed the entire multi-tenant roster.
/// - `peer_id` omitted → the deliberate unfiltered admin/debug view,
///   requiring `Authorization: Bearer <MESH_ADMIN_TOKEN>`, else `401`.
///
/// A joiner whose peer was swept re-registers and reconnects with the fresh
/// id; the `401` is the signal, and its reconnect loop already treats a
/// non-success status as a retryable error.
///
/// SSE wire format: `event: <kind>` + `data: <json>` per frame. The
/// per-event payload schema is [`PeerEvent`] (mirrored here as a
/// documentation-only schema — the streaming body itself can't be a
/// single `OpenAPI` body type).
#[utoipa::path(
    get,
    path = "/v1/mesh/peers/stream",
    tag = "mesh",
    params(
        ("peer_id" = Option<String>, Query,
            description = "Subscribing viewer's peer-id; must name a peer currently in the roster, and the stream is then ACL-filtered to peers this viewer may see with hole-punch frames routed by initiator. Omit AND present the admin bearer for the unfiltered admin/debug view."),
    ),
    responses(
        (status = 200, description = "SSE stream of peer events (text/event-stream)",
            content_type = "text/event-stream",
            body = PeerEvent),
        (status = 401, description = "Unresolvable peer_id, or unfiltered view requested without a valid admin token", body = crate::http::api::ApiError),
    ),
    security(("bearer" = []))
)]
#[tracing::instrument(
    skip_all,
    fields(peer_id = ?query.peer_id),
)]
pub async fn stream_handler(
    State(state): State<RosterApiState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Response {
    let coordinator = state.coordinator;
    // Resolve the viewer's identity BEFORE subscribing, so a rejected
    // caller never holds a broadcast receiver.
    let viewer = if let Some(raw) = query.peer_id.as_deref() {
        // An asserted identity must resolve to a live roster entry.
        let Some(resolved) = Uuid::from_str(raw)
            .ok()
            .and_then(|id| coordinator.peer_tags(id).map(|tags| (id, tags)))
        else {
            warn!(
                peer_id = %raw,
                "rejected peer-stream: viewer id is malformed or absent from the roster"
            );
            return err(
                StatusCode::UNAUTHORIZED,
                "unknown peer_id; re-register before subscribing to the peer stream",
            );
        };
        Some(resolved)
    } else {
        // No asserted identity → the unfiltered admin view, admin-gated.
        if let Some(resp) = check_admin_bearer(state.admin_token.as_deref(), &headers, "roster") {
            warn!("rejected unauthenticated unfiltered peer-stream subscription");
            return resp;
        }
        None
    };

    // Bootstrap the subscriber with the current roster, THEN attach to
    // the live broadcast. The subscribe-then-snapshot ordering would
    // race — between subscribe and snapshot a peer could leave and the
    // remove frame would arrive before the bootstrap "added" frame.
    let receiver = coordinator.broadcaster().subscribe();
    let snapshot = coordinator.snapshot();
    let stream = peer_event_stream(coordinator, viewer, snapshot, receiver);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// Per-viewer ACL filter for the SSE stream.
///
/// The broadcast channel is shared across all subscribers, so filtering is
/// per-subscriber here rather than at broadcast time. The filter is
/// **stateful**: it remembers which peer ids it has currently revealed to
/// this viewer. That statefulness is what makes policy changes converge —
/// when a `PUT /v1/policy` re-broadcasts every peer as `Updated`
/// ([`Coordinator::resync_all_peers`]), this filter re-evaluates each peer
/// and synthesises the right frame:
///
/// - newly visible (not previously revealed) → `peer_added`
/// - still visible (already revealed)        → `peer_updated`
/// - newly hidden (was revealed)             → synthetic `peer_removed`
/// - still hidden                            → dropped
///
/// Visibility is evaluated against the *current* policy on every frame, so
/// the filter needs the coordinator handle and the viewer's tags.
pub(super) struct ViewerFilter {
    pub(super) coordinator: Coordinator,
    pub(super) viewer_id: Uuid,
    pub(super) viewer_tags: Vec<String>,
    /// Peer ids currently revealed to this viewer.
    pub(super) revealed: HashSet<String>,
}

impl ViewerFilter {
    /// Apply the filter to one broadcast event, returning the SSE frame the
    /// viewer should receive (or `None` to drop it).
    pub(super) fn apply(&mut self, event: PeerEvent) -> Option<SseFrame> {
        match event {
            PeerEvent::Added(info) | PeerEvent::Updated(info) => {
                // Never reveal the viewer to itself.
                if info.peer_id == self.viewer_id.to_string() {
                    return None;
                }
                let visible = self
                    .coordinator
                    .viewer_can_see(&self.viewer_tags, &info.tags);
                if visible {
                    // Added if first time we reveal this peer, else Updated.
                    let frame = if self.revealed.insert(info.peer_id.clone()) {
                        to_sse_frame(&PeerEvent::Added(info))
                    } else {
                        to_sse_frame(&PeerEvent::Updated(info))
                    };
                    Some(frame)
                } else if self.revealed.remove(&info.peer_id) {
                    // Was visible, now denied → synthetic removal.
                    Some(to_sse_frame(&PeerEvent::Removed {
                        peer_id: info.peer_id,
                        tags: info.tags,
                    }))
                } else {
                    None
                }
            }
            PeerEvent::Removed { peer_id, tags } => {
                // Only forward a removal for a peer the viewer had been
                // shown (and was allowed to see).
                if self.revealed.remove(&peer_id) {
                    Some(to_sse_frame(&PeerEvent::Removed { peer_id, tags }))
                } else {
                    None
                }
            }
            // A hole-punch instruction goes only to the peer told to fire
            // (its initiator). Routed by id, not tags — and never gated by
            // `revealed`, since a punch can be needed before either peer
            // has appeared in the other's roster view.
            PeerEvent::HolePunch(ref hp) => {
                if hp.initiator_peer_id == self.viewer_id.to_string() {
                    Some(to_sse_frame(&event))
                } else {
                    None
                }
            }
            // A relay-rendezvous wake goes only to the cold destination told to
            // kick back. Routed by recipient id, not tags — and never gated by
            // `revealed`, since the wake can be needed before either peer has
            // appeared in the other's roster view (the passive-peer case).
            PeerEvent::RelayWake(ref rw) => {
                if rw.recipient_peer_id == self.viewer_id.to_string() {
                    Some(to_sse_frame(&event))
                } else {
                    None
                }
            }
        }
    }
}

/// Translate the broadcast channel into SSE frames, optionally ACL-filtered
/// for a specific viewer. Lagged subscribers see their dropped frames
/// counted (via a warn log) and the stream continues — that matches the
/// contract "drop oldest if slow consumer".
fn peer_event_stream(
    coordinator: Coordinator,
    viewer: Option<(Uuid, Vec<String>)>,
    bootstrap: Vec<PeerInfo>,
    receiver: tokio::sync::broadcast::Receiver<PeerEvent>,
) -> impl Stream<Item = Result<SseFrame, Infallible>> {
    // Seed the per-viewer filter (if any) from the bootstrap snapshot so
    // the initial `peer_added` burst is itself ACL-filtered and the
    // `revealed` set is primed for later convergence.
    let mut filter = viewer.map(|(viewer_id, viewer_tags)| ViewerFilter {
        coordinator,
        viewer_id,
        viewer_tags,
        revealed: HashSet::new(),
    });

    let initial_frames: Vec<SseFrame> = bootstrap
        .into_iter()
        .filter_map(|p| match filter.as_mut() {
            Some(f) => f.apply(PeerEvent::Added(p)),
            None => Some(to_sse_frame(&PeerEvent::Added(p))),
        })
        .collect();
    let initial = futures::stream::iter(initial_frames.into_iter().map(Ok::<SseFrame, Infallible>));

    let live = BroadcastStream::new(receiver).filter_map(move |next| {
        // `filter` is moved into the closure; updated in place per frame.
        let frame = match next {
            Ok(event) => match filter.as_mut() {
                Some(f) => f.apply(event),
                None => Some(to_sse_frame(&event)),
            },
            Err(BroadcastStreamRecvError::Lagged(n)) => {
                warn!(dropped = n, "SSE subscriber lagged, dropping frames");
                None
            }
        };
        async move { frame.map(Ok::<SseFrame, Infallible>) }
    });
    initial.chain(live)
}

/// Build an SSE frame for a single peer event. Falls back to a generic
/// error frame if the payload fails to serialise — that path should be
/// unreachable, but a single bad event must never poison the stream.
fn to_sse_frame(event: &PeerEvent) -> SseFrame {
    match event.data_payload() {
        Ok(json) => SseFrame::default().event(event.event_name()).data(json),
        Err(e) => {
            warn!(error = %e, "failed to serialise peer event");
            SseFrame::default()
                .event("error")
                .data("serialisation failed")
        }
    }
}
