//! Per-app ULA addresses. See spec §2.5.
//!
//! Layout (128 bits):
//!   `fd5a:1f<XX>:<tenant16>:<app64_a>:<app64_b>:<app64_c>:<app64_d>:<instance16>`
//!
//! - `fd5a:1f` (24 bits): constant ULA prefix
//! - `<XX>` (8 bits): per-cluster magic byte
//! - `<tenant16>` (16 bits): tenant / workspace id
//! - `<app64>` (64 bits, split across four u16 segments): truncated UUID (top 8 bytes)
//! - `<instance16>` (16 bits): instance id within an app
//!
//! The 64-bit `app` slot covers the leading 8 bytes of the UUID. For
//! `UUIDv7` those are: 48-bit timestamp + 4-bit version + 12 bits of
//! `rand_a`, which is enough monotonic entropy that birthday collisions
//! across "millions of apps per tenant" stay vanishingly small (2^32
//! attempts before a >50% chance of collision).

use std::net::Ipv6Addr;

use uuid::Uuid;

/// Cluster-wide ULA prefix configuration: magic byte + tenant id.
///
/// The magic byte should be picked once per deployment (or generated
/// randomly) to avoid address collisions across separate tabbify clusters
/// that might one day connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UlaPrefix {
    magic: u8,
    tenant: u16,
}

impl UlaPrefix {
    /// Build a prefix from its components. Returns `Err` only if the
    /// inputs are out of range — currently all `u8`/`u16` values are valid,
    /// but the return type is left as `Result` for forward compatibility.
    #[allow(clippy::unnecessary_wraps)]
    pub const fn new(magic: u8, tenant: u16) -> Result<Self, &'static str> {
        Ok(Self { magic, tenant })
    }

    /// The tenant id encoded in this prefix.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub const fn tenant(&self) -> u16 {
        self.tenant
    }

    /// The cluster magic byte.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub const fn magic(&self) -> u8 {
        self.magic
    }
}

/// Fully-qualified per-app-instance ULA address.
///
/// Construct with [`Ula::from_components`] — the result is deterministic
/// from the inputs, so the same `(prefix, app_uuid, instance)` triple
/// always yields the same address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ula {
    address: Ipv6Addr,
}

impl Ula {
    /// Build a ULA from a cluster prefix, app UUID, and instance id.
    ///
    /// The app UUID is truncated to its leading 64 bits (top 8 bytes of
    /// the UUID) and split into four u16 segments of the IPv6 address.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn from_components(prefix: &UlaPrefix, app_uuid: Uuid, instance: u16) -> Self {
        let uuid_bytes = app_uuid.as_bytes();
        let app64_a: u16 = (u16::from(uuid_bytes[0]) << 8) | u16::from(uuid_bytes[1]);
        let app64_b: u16 = (u16::from(uuid_bytes[2]) << 8) | u16::from(uuid_bytes[3]);
        let app64_c: u16 = (u16::from(uuid_bytes[4]) << 8) | u16::from(uuid_bytes[5]);
        let app64_d: u16 = (u16::from(uuid_bytes[6]) << 8) | u16::from(uuid_bytes[7]);

        let address = Ipv6Addr::new(
            0xfd5a,
            0x1f00 | u16::from(prefix.magic),
            prefix.tenant,
            app64_a,
            app64_b,
            app64_c,
            app64_d,
            instance,
        );
        Self { address }
    }

    /// The underlying IPv6 address.
    pub const fn address(&self) -> Ipv6Addr {
        self.address
    }
}
