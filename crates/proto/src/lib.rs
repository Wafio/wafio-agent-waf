//! Generated AgentControl client and server (`shared/proto/agent/v1/agent_control.proto`,
//! package `wafio.agent.v1`).

#![forbid(unsafe_code)]

#[allow(clippy::all, clippy::pedantic)]
pub mod v1 {
    tonic::include_proto!("wafio.agent.v1");
}

/// Names the message and its ids, and sizes the two byte fields: the key is never printed, and
/// neither is the chain, so a log line or a panic message that formats the install cannot leak.
impl std::fmt::Debug for v1::CertificateInstall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateInstall")
            .field("command_id", &self.command_id)
            .field("app_id", &self.app_id)
            .field("certificate_id", &self.certificate_id)
            .field("leaf_sha256", &self.leaf_sha256)
            .field("chain_pem_len", &self.chain_pem.len())
            .field("key_pem_len", &self.key_pem.len())
            .finish()
    }
}

impl v1::CertificateInstall {
    /// Overwrites the key with zeros, spare capacity included, and keeps its length. Best effort:
    /// tonic keeps its own decode buffer, and a sink that took the key out has copied it.
    pub fn wipe_key(&mut self) {
        let key = &mut self.key_pem;
        key.fill(0);
        key.spare_capacity_mut().fill(std::mem::MaybeUninit::new(0));
        // Without this the compiler may drop the writes, as the buffer is freed right after.
        std::hint::black_box(key.as_ptr());
    }
}

/// The wipe sits on the type, not on one code path: a message that is read and dropped, one that is
/// drained from a closing stream, a clone and one dropped by a panic all zero the key the same way.
impl Drop for v1::CertificateInstall {
    fn drop(&mut self) {
        self.wipe_key();
    }
}

#[cfg(test)]
mod tests {
    use super::v1::{CertificateInstall, ServerMessage, server_message::Kind};

    fn install() -> CertificateInstall {
        CertificateInstall {
            command_id: "cmd-1".into(),
            app_id: "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11".into(),
            certificate_id: "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77".into(),
            chain_pem: b"-----BEGIN CERTIFICATE-----\nCHAINBYTES\n-----END CERTIFICATE-----\n"
                .to_vec(),
            key_pem: b"-----BEGIN PRIVATE KEY-----\nKEYBYTES\n-----END PRIVATE KEY-----\n".to_vec(),
            leaf_sha256: "ab".repeat(32),
        }
    }

    // No part of the key as text, and no byte list at all: a derived Debug prints a Vec<u8> as one.
    fn assert_no_key(shown: &str) {
        for needle in ["KEYBYTES", "PRIVATE KEY", "BEGIN", "["] {
            assert!(!shown.contains(needle), "{needle:?} in {shown}");
        }
    }

    #[test]
    fn wipe_key_zeroes_the_key_and_keeps_its_length_and_the_rest() {
        let mut m = install();
        let (key_len, chain) = (m.key_pem.len(), m.chain_pem.clone());
        m.wipe_key();
        assert_eq!(m.key_pem, vec![0; key_len]);
        assert_eq!(m.chain_pem, chain);
        assert_eq!(m.command_id, "cmd-1");
    }

    #[test]
    fn debug_of_an_install_shows_ids_and_lengths_but_no_key_byte() {
        let m = install();
        for shown in [format!("{m:?}"), format!("{m:#?}")] {
            assert_no_key(&shown);
            assert!(!shown.contains("CHAINBYTES"), "{shown}");
            for want in [
                "CertificateInstall",
                "cmd-1",
                "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11",
                "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77",
                &"ab".repeat(32),
                "key_pem_len",
                &m.key_pem.len().to_string(),
                "chain_pem_len",
                &m.chain_pem.len().to_string(),
            ] {
                assert!(shown.contains(want), "{want:?} missing from {shown}");
            }
        }
    }

    #[test]
    fn debug_of_a_server_message_holding_an_install_shows_no_key_byte() {
        let m = install();
        let msg = ServerMessage {
            kind: Some(Kind::CertificateInstall(m.clone())),
        };
        for shown in [
            format!("{msg:?}"),
            format!("{msg:#?}"),
            format!("{:?}", msg.kind),
        ] {
            assert_no_key(&shown);
            assert!(
                shown.contains("cmd-1") && shown.contains("key_pem_len"),
                "{shown}"
            );
        }
    }
}
