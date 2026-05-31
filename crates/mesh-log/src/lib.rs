#![warn(missing_docs)]

//! `tabbify-mesh-log` — the ONE logging-init crate for the whole mesh.
//!
//! Every binary in the workspace (the coordinator, the `tabbify-mesh`
//! joiner CLI) and every host application that embeds
//! `tabbify_mesh_joiner` initialises its tracing subscriber through the
//! single entry point [`init_logging`]. That guarantees one consistent,
//! Loki-friendly JSON shape across the fleet:
//!
//! * a JSON formatter (one object per line, no ANSI),
//! * an [`EnvFilter`] sourced from `RUST_LOG`, defaulting to `info`,
//! * a constant, FLAT top-level `service=<name>` field stamped onto EVERY
//!   line, so a Loki query can slice logs by service without parsing the
//!   message.
//!
//! # Why a constant `service` field
//!
//! The mesh is several cooperating processes (coordinator, joiner CLI,
//! supervisor / node host apps). When their logs land in the same Loki
//! stream, `service` is the discriminator that lets an operator filter
//! `{service="mesh-coordinator"}` or trace one peer's re-peer attempt
//! across the joiner without grepping free-form message text.
//!
//! The field is emitted by a custom [`FormatEvent`] that writes `service`
//! as a flat, top-level JSON key on every event (not nested under a
//! `span` object), so a downstream JSON parser sees a plain `service`
//! label.
//!
//! # Idempotency
//!
//! [`init_logging`] guards the global-subscriber install, so calling it
//! more than once — or after some other code already installed a global
//! subscriber — is a quiet no-op rather than a panic. Host applications
//! that already set up their own tracing therefore stay safe even if they
//! also call this.

use std::fmt;

use tracing::subscriber::set_global_default;
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::{JsonFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Registry};

/// Default `RUST_LOG` directive when the environment does not set one.
const DEFAULT_FILTER: &str = "info";

/// Event formatter that wraps the stock JSON formatter and guarantees a
/// flat, top-level `service` field on every line.
///
/// `tracing_subscriber`'s built-in JSON formatter can render the current
/// span's fields, but only nested under a `span` object. Loki filtering
/// is cleaner when `service` is a flat top-level key, so this formatter
/// owns the service name and delegates the rest of the line (timestamp,
/// level, target, message, event fields) to the inner JSON formatter,
/// merging the two single-line JSON objects into one.
struct ServiceJson {
    /// The constant service name stamped onto every line.
    service: String,
    /// Inner stock JSON formatter — produces the timestamp / level /
    /// target / message / fields object we splice our `service` key into.
    inner: tracing_subscriber::fmt::format::Format<tracing_subscriber::fmt::format::Json>,
}

impl<S, N> FormatEvent<S, N> for ServiceJson
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Render the stock JSON object into a scratch buffer first so we
        // can inject our `service` key right after the opening brace —
        // keeping `service` a flat, top-level field on every line.
        let mut buf = String::new();
        self.inner
            .format_event(ctx, Writer::new(&mut buf), event)?;

        let trimmed = buf.trim_end_matches(['\n', '\r']);
        if let Some(rest) = trimmed.strip_prefix('{') {
            // Escape the service value so a name with a quote/backslash
            // can't break the JSON. Service names are operator-chosen and
            // tame, but correctness here is cheap.
            let escaped = rest_escape(&self.service);
            if rest.starts_with('}') {
                // Empty object `{}` → just our field.
                write!(writer, "{{\"service\":\"{escaped}\"{rest}")?;
            } else {
                write!(writer, "{{\"service\":\"{escaped}\",{rest}")?;
            }
        } else {
            // Inner formatter produced something unexpected (not a JSON
            // object) — fall back to emitting it verbatim so we never
            // drop a log line.
            write!(writer, "{trimmed}")?;
        }
        writeln!(writer)
    }
}

/// Minimal JSON string-escape for the service name.
fn rest_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Initialise the global tracing subscriber for `service`.
///
/// Installs a JSON-formatting subscriber with:
///
/// * an [`EnvFilter`] read from `RUST_LOG` (default [`DEFAULT_FILTER`] =
///   `"info"`),
/// * a flat, constant `service=<service>` field on every emitted line.
///
/// # Idempotent
///
/// Safe to call multiple times and safe to call when another global
/// subscriber is already installed: the underlying `set_global_default`
/// call is guarded and a failure (subscriber already set) is swallowed.
/// This makes it composable with host apps that may have their own
/// tracing setup.
///
/// The `service` name should be stable per process — e.g.
/// `"mesh-coordinator"`, `"tabbify-mesh"`, or the host-app name a
/// supervisor / node passes when it embeds the joiner.
pub fn init_logging(service: &str) {
    // EnvFilter from RUST_LOG; fall back to a plain `info` directive when
    // the env var is missing or unparseable (a bad RUST_LOG must not take
    // the whole process down at boot).
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));

    // Stock JSON event format, flattening the event's own fields to the
    // top level. We wrap it in `ServiceJson` to also splice in a flat
    // `service` key on every line.
    let inner = tracing_subscriber::fmt::format()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false);

    let event_format = ServiceJson {
        service: service.to_owned(),
        inner,
    };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .event_format(event_format)
        .fmt_fields(JsonFields::new());

    let subscriber = Registry::default().with(filter).with(fmt_layer);

    // `set_global_default` returns `Err` if a subscriber is already
    // installed — swallow it so a double-init (or a host app that already
    // set tracing up) is a quiet no-op rather than a panic.
    let _ = set_global_default(subscriber);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `init_logging` must be safe to call twice — the second call is a
    /// quiet no-op, never a panic. A global subscriber can only be set
    /// once per process, so this also covers the "already initialised"
    /// path (whichever test in the process wins the race installs it;
    /// every later call falls through the guarded `set_global_default`).
    #[test]
    fn init_logging_is_idempotent() {
        init_logging("mesh-log-test");
        // Second call must not panic.
        init_logging("mesh-log-test");
    }

    /// The default filter directive is `info` when `RUST_LOG` is unset —
    /// pin the constant so a future edit can't silently change the
    /// fleet-wide default level.
    #[test]
    fn default_filter_is_info() {
        assert_eq!(DEFAULT_FILTER, "info");
        // And the constant actually parses as a valid EnvFilter directive.
        let _filter = EnvFilter::new(DEFAULT_FILTER);
    }

    /// The service-name escaper must neutralise quotes / backslashes so a
    /// pathological name can't produce malformed JSON.
    #[test]
    fn rest_escape_neutralises_json_breakers() {
        assert_eq!(rest_escape("plain"), "plain");
        assert_eq!(rest_escape("a\"b"), "a\\\"b");
        assert_eq!(rest_escape("a\\b"), "a\\\\b");
    }
}
