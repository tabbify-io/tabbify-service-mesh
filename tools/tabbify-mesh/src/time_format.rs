//! Small helpers for human-friendly relative time strings ("3s ago",
//! "1m ago", …) used in the `peers` table output.

use chrono::{DateTime, Utc};

/// Render a wall-clock instant as a coarse, human-friendly relative time
/// string, e.g. `"3s ago"`, `"7m ago"`, `"2h ago"`, `"4d ago"`.
///
/// Future timestamps (clock skew or stale `now`) collapse to `"just now"`.
#[must_use]
pub fn relative(then: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let delta = now.signed_duration_since(then);
    let secs = delta.num_seconds();
    if secs <= 0 {
        return "just now".to_string();
    }
    if secs < 60 {
        return format!("{secs}s ago");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m ago");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h ago");
    }
    let days = hours / 24;
    format!("{days}d ago")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).single().expect("valid ts")
    }

    #[test]
    fn seconds_window() {
        assert_eq!(relative(at(1_000), at(1_003)), "3s ago");
        assert_eq!(relative(at(1_000), at(1_059)), "59s ago");
    }

    #[test]
    fn minutes_window() {
        assert_eq!(relative(at(1_000), at(1_060)), "1m ago");
        assert_eq!(relative(at(1_000), at(1_000 + 59 * 60)), "59m ago");
    }

    #[test]
    fn hours_window() {
        assert_eq!(relative(at(1_000), at(1_000 + 3_600)), "1h ago");
        assert_eq!(relative(at(1_000), at(1_000 + 23 * 3_600)), "23h ago");
    }

    #[test]
    fn days_window() {
        assert_eq!(relative(at(1_000), at(1_000 + 24 * 3_600)), "1d ago");
        assert_eq!(relative(at(1_000), at(1_000 + 7 * 24 * 3_600)), "7d ago");
    }

    #[test]
    fn equal_instants_render_as_just_now() {
        assert_eq!(relative(at(1_000), at(1_000)), "just now");
    }

    #[test]
    fn future_timestamps_collapse_to_just_now() {
        assert_eq!(relative(at(1_100), at(1_000)), "just now");
    }
}
