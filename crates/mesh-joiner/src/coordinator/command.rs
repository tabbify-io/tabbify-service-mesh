//! Signed `NodeCommand` — the end-to-end control-plane verb the coordinator
//! relays and the joiner verifies (Track C remote-restart).
//!
//! The coordinator is a DUMB RELAY: it queues an already-signed command and
//! never inspects the signature. The node verifies the super-admin Ed25519
//! pubkey itself, so a compromised coordinator/relay cannot forge a reboot.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The verbs a super-admin may remotely issue. Mirrored on the coordinator's
/// relay DTO. Each verb's joiner-side effect is in [`crate::coordinator::command_exec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandVerb {
    /// Drop + rebuild the in-process joiner (fresh register, fresh boringtun
    /// Tunns, fresh relay-WS). `relay_only` is preserved by construction.
    RestartJoiner,
    /// Force a re-handshake on every live WG session (no process restart).
    ResetWg,
    /// `systemctl reboot` — clears a wedged kernel-TUN / stuck NAT mapping a
    /// process restart can't. Behind the B2 reboot loop-guard (supervisor).
    RebootHost,
}

/// End-to-end-signed remote command.
///
/// The signed payload is a canonical `serde_json` of every field EXCEPT
/// `signature`, so sign + verify agree byte-for-byte regardless of map ordering
/// (struct field order is stable).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCommand {
    /// UUID v7 — idempotency key for the ack path.
    pub command_id: Uuid,
    /// The verb to execute.
    pub verb: CommandVerb,
    /// Target peer id (string UUID) — the coordinator routes the queue by it.
    pub peer_id: String,
    /// Anti-replay nonce — the joiner persists every executed nonce and
    /// refuses to re-run one (replay-guard).
    pub nonce: String,
    /// Issued-at, unix micros (informational + ordering).
    pub issued_at: i64,
    /// Expiry, unix micros — the joiner refuses to execute past this.
    pub expiry: i64,
    /// Ed25519 signature over the canonical bytes (hex). Empty until signed.
    #[serde(default)]
    pub signature: String,
}

/// Why a [`NodeCommand`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommandVerifyError {
    /// Signature did not verify against the configured super-admin pubkey.
    #[error("command signature verification failed")]
    BadSignature,
    /// `now > expiry`.
    #[error("command expired")]
    Expired,
    /// Signature hex / pubkey bytes were malformed.
    #[error("malformed signature or key material")]
    Malformed,
}

impl NodeCommand {
    /// Build an UNSIGNED command (`signature` empty). Use [`Self::signed_by`].
    #[must_use]
    pub const fn new(
        command_id: Uuid,
        verb: CommandVerb,
        peer_id: String,
        nonce: String,
        issued_at: i64,
        expiry: i64,
    ) -> Self {
        Self {
            command_id,
            verb,
            peer_id,
            nonce,
            issued_at,
            expiry,
            signature: String::new(),
        }
    }

    /// The canonical bytes that get signed/verified — everything but the
    /// signature. Serialize a clone with `signature` cleared so adding the
    /// signature never changes the signed payload.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bare = self.clone();
        bare.signature = String::new();
        // `serde_json` serializes struct fields in declaration order — stable.
        serde_json::to_vec(&bare).unwrap_or_default()
    }

    /// Sign with `sk` and return self with the hex signature filled in
    /// (test/issuer side; production issuance lives in the admin tooling).
    #[must_use]
    pub fn signed_by(mut self, sk: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let sig = sk.sign(&self.signing_bytes());
        self.signature = hex::encode(sig.to_bytes());
        self
    }

    /// Verify the signature against the super-admin `pubkey` (32 raw bytes).
    ///
    /// # Errors
    /// [`CommandVerifyError::Malformed`] on bad hex/key, [`CommandVerifyError::BadSignature`]
    /// when the signature does not match.
    pub fn verify(&self, pubkey: &[u8]) -> Result<(), CommandVerifyError> {
        let key_bytes: [u8; 32] = pubkey
            .try_into()
            .map_err(|_| CommandVerifyError::Malformed)?;
        let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|_| CommandVerifyError::Malformed)?;
        let sig_bytes = hex::decode(&self.signature).map_err(|_| CommandVerifyError::Malformed)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CommandVerifyError::Malformed)?;
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(&self.signing_bytes(), &sig)
            .map_err(|_| CommandVerifyError::BadSignature)
    }

    /// Reject a command whose `expiry` is in the past relative to `now_micros`.
    ///
    /// # Errors
    /// [`CommandVerifyError::Expired`] when `now_micros > expiry`.
    pub const fn check_fresh(&self, now_micros: i64) -> Result<(), CommandVerifyError> {
        if now_micros > self.expiry {
            return Err(CommandVerifyError::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// A command signed by the super-admin key verifies against that key's
    /// public half, and a DIFFERENT key (a compromised coordinator) fails.
    #[test]
    fn sign_then_verify_roundtrips_and_rejects_wrong_key() {
        let sk = signing_key();
        let cmd = NodeCommand::new(
            Uuid::now_v7(),
            CommandVerb::RestartJoiner,
            "01910f10-0000-7000-8000-0000000000aa".to_owned(),
            "nonce-abc".to_owned(),
            1_000,
            2_000,
        )
        .signed_by(&sk);

        // Correct key → Ok.
        assert!(cmd.verify(&sk.verifying_key().to_bytes()).is_ok());

        // A different (attacker) key → rejected.
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        assert!(matches!(
            cmd.verify(&attacker.verifying_key().to_bytes()),
            Err(CommandVerifyError::BadSignature)
        ));
    }

    /// Tampering with ANY signed field after signing invalidates the signature.
    #[test]
    fn tampered_verb_fails_verification() {
        let sk = signing_key();
        let mut cmd = NodeCommand::new(
            Uuid::now_v7(),
            CommandVerb::RestartJoiner,
            "01910f10-0000-7000-8000-0000000000aa".to_owned(),
            "nonce-xyz".to_owned(),
            1_000,
            2_000,
        )
        .signed_by(&sk);
        cmd.verb = CommandVerb::RebootHost; // escalate after signing
        assert!(matches!(
            cmd.verify(&sk.verifying_key().to_bytes()),
            Err(CommandVerifyError::BadSignature)
        ));
    }

    /// An expired command is rejected even with a valid signature.
    #[test]
    fn expired_command_is_rejected() {
        let sk = signing_key();
        let cmd = NodeCommand::new(
            Uuid::now_v7(),
            CommandVerb::ResetWg,
            "01910f10-0000-7000-8000-0000000000aa".to_owned(),
            "nonce-exp".to_owned(),
            1_000,
            2_000, // expiry = 2000
        )
        .signed_by(&sk);
        // now (3000) > expiry (2000) → Expired, signature is irrelevant.
        assert!(matches!(
            cmd.check_fresh(3_000),
            Err(CommandVerifyError::Expired)
        ));
        assert!(cmd.check_fresh(1_500).is_ok());
    }
}
