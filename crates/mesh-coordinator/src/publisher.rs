//! Trait + impls for a roster-change sink.
//!
//! The coordinator hides its roster-change persistence behind an
//! object-safe [`EventPublisher`] so the wiring is pluggable: tests use
//! [`NoopPublisher`], and a deployment that wants durability can add a
//! backend (e.g. an embedded `redb` store) behind the same trait without
//! touching the coordinator state machine.

use crate::roster::events::MeshEvent;
use async_trait::async_trait;
use serde::Serialize;
use std::sync::Arc;
use tracing::warn;

/// Object-safe publisher contract. Implementations ship one already-
/// encoded event payload at a time, leaving event-type + segment routing
/// to the caller.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish a single event. `payload` is the serialized event body
    /// (the implementation decides how to frame / store it).
    async fn publish(
        &self,
        event_type: &str,
        segment: &str,
        payload: Vec<u8>,
    ) -> Result<(), String>;
}

/// Convenience helper: serialize a mesh event and ship it. Lives outside
/// the trait so the trait stays object-safe.
///
/// Publish failures are logged at warn level instead of bubbling up,
/// because the coordinator already responded "200 OK" to the joiner and
/// can't unwind that response — losing one event is preferable to
/// poisoning the in-memory roster.
pub async fn publish_event<E>(publisher: &dyn EventPublisher, segment: &str, payload: &E)
where
    E: Serialize + MeshEvent + Sync,
{
    let buf = match serde_json::to_vec(payload) {
        Ok(buf) => buf,
        Err(e) => {
            warn!(error = %e, segment, event_type = E::event_type(), "event serialize failed");
            return;
        }
    };
    if let Err(e) = publisher.publish(E::event_type(), segment, buf).await {
        warn!(error = %e, segment, event_type = E::event_type(), "publish failed");
    }
}

/// Publisher used by unit tests + the default standalone configuration —
/// drops everything and records nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPublisher;

#[async_trait]
impl EventPublisher for NoopPublisher {
    async fn publish(
        &self,
        _event_type: &str,
        _segment: &str,
        _payload: Vec<u8>,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Type-erased handle a `Coordinator` can hold.
pub type SharedPublisher = Arc<dyn EventPublisher>;
