//! A credentials node inside an AWS Nitro Enclave.
//!
//! The `enclave` program generates a fresh node key at every boot (an enclave has no sealed
//! storage: a restarted enclave is a new node, and owners grant to it again), then serves the
//! HTTP API of `credentials serve` on vsock port [`server::relay::HTTP_PORT`], plus
//! `GET /attestation?nonce=<base64url>`: an attestation document of the Nitro Secure Module
//! whose `user_data` is [`engine::grant::NodeIdentity::report_data`] and whose `nonce` is the
//! caller's. An owner verifies the document (its certificate chain to the AWS Nitro root, and
//! PCR0, PCR1 and PCR2 against the published measurements of a release), then that its
//! `user_data` is the report data of the identity it is about to grant to.
//!
//! The enclave has no network and no disk. Its bytes reach destinations through the egress
//! relay of the host (TLS ends inside the enclave), and its log entries are stored by the log
//! writer of the host, which confirms each only after it is synced (see
//! [`server::relay`]). `credentials host` is that host program.
//!
//! The parts that need Nitro hardware ([`nitro`]) are compiled on Linux only; the attestation
//! endpoint ([`attestation`]) is portable and tested with a stand-in for the NSM.

pub mod attestation;

#[cfg(target_os = "linux")]
pub mod nitro;
