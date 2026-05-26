//! `tabbify-mesh status` — read the on-disk snapshot left by a running
//! `join` daemon and pretty-print it.

use std::io::ErrorKind;

use anyhow::Result;
use chrono::Utc;

use crate::status_file;
use crate::time_format;

/// Run the `status` subcommand.
///
/// # Errors
/// Exits with code 1 if no status file is present. Other read / parse
/// errors are surfaced as anyhow errors.
#[allow(clippy::unused_async)]
pub async fn run() -> Result<()> {
    let path = status_file::status_path()?;
    match status_file::read_from(&path) {
        Ok(snap) => {
            let last_seen = time_format::relative(snap.last_heartbeat_at, Utc::now());
            println!("status:           running");
            println!("pid:              {}", snap.pid);
            println!("peer_id:          {}", snap.peer_id);
            println!("ula:              {}", snap.ula);
            println!("display_name:     {}", snap.display_name);
            println!("tags:             {}", format_tags(&snap.tags));
            println!("coordinator:      {}", snap.coordinator_url);
            println!("peer_count:       {}", snap.peer_count);
            println!(
                "last_heartbeat:   {} ({})",
                snap.last_heartbeat_at.to_rfc3339(),
                last_seen
            );
            println!("status_file:      {}", path.display());
            Ok(())
        }
        Err(e) => {
            // Distinguish "not running" (file missing) from real parse
            // errors so the CLI's exit code is meaningful for scripts.
            if let Some(io) = e.downcast_ref::<std::io::Error>() {
                if io.kind() == ErrorKind::NotFound {
                    eprintln!("not running (no status file at {})", path.display());
                    std::process::exit(1);
                }
            }
            // anyhow wraps the io::Error one layer deep — check the
            // chain too.
            if e.chain().any(|c| {
                c.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == ErrorKind::NotFound)
            }) {
                eprintln!("not running (no status file at {})", path.display());
                std::process::exit(1);
            }
            Err(e)
        }
    }
}

fn format_tags(tags: &[String]) -> String {
    if tags.is_empty() {
        "-".to_string()
    } else {
        tags.join(",")
    }
}
