//! Relay client: the cheap-clone handle the WG TX seams use to relay a
//! packet, plus (in [`run`]) the persistent WebSocket task that connects
//! to the coordinator's `/v1/mesh/relay` endpoint, drains queued
//! outbound datagrams, and injects relayed inbound datagrams back into
//! boringtun.

use tokio::sync::mpsc;

/// One outbound relayed datagram: where to send + the already-WG-encrypted
/// bytes.
///
// The fields are read by the WG TX seams (B4) and the relay write-task
// (B5); allow dead_code until those land in the next tasks.
#[allow(dead_code)]
pub struct RelayOutbound {
    /// Destination peer's raw 32-byte X25519 WG public key.
    pub dst_pubkey: [u8; 32],
    /// Opaque, already-encrypted WG transport datagram.
    pub payload: Vec<u8>,
}

/// Cheap-clone handle the WG TX seams use to relay a packet when no direct
/// endpoint is known.
///
/// Backed by an unbounded channel drained by the relay client task.
/// [`Self::try_relay`] never blocks and never fails loudly — if the relay
/// task is gone the packet is dropped (the same outcome as the pre-relay
/// silent drop).
#[derive(Clone)]
pub struct RelayHandle {
    tx: mpsc::UnboundedSender<RelayOutbound>,
}

impl RelayHandle {
    /// Create a handle paired with the receiver the relay task drains.
    // Wired into `Joiner::join` in B5; allow dead_code until then.
    #[allow(dead_code)]
    pub(crate) fn new() -> (Self, mpsc::UnboundedReceiver<RelayOutbound>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }

    /// Queue an already-encrypted WG datagram for relay to `dst_pubkey`.
    /// Best-effort: a send to a closed channel (relay task gone) is
    /// silently dropped.
    pub fn try_relay(&self, dst_pubkey: [u8; 32], payload: Vec<u8>) {
        let _ = self.tx.send(RelayOutbound { dst_pubkey, payload });
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// A queued datagram arrives on the receiver verbatim — the channel
    /// the relay task drains carries the destination pubkey + payload.
    #[tokio::test]
    async fn try_relay_queues_outbound() {
        let (handle, mut rx) = RelayHandle::new();
        handle.try_relay([9u8; 32], vec![1, 2, 3]);
        let got = rx.recv().await.expect("queued outbound");
        assert_eq!(got.dst_pubkey, [9u8; 32]);
        assert_eq!(got.payload, vec![1, 2, 3]);
    }

    /// `try_relay` after the receiver is dropped does not panic — the
    /// packet is silently dropped (relay task gone == pre-relay drop).
    #[tokio::test]
    async fn try_relay_after_rx_dropped_is_silent() {
        let (handle, rx) = RelayHandle::new();
        drop(rx);
        handle.try_relay([1u8; 32], vec![0]); // must not panic
    }
}
