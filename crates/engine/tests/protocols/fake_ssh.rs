//! An SSH server for the tests, written apart from the node's client: AES-GCM from the
//! RustCrypto crate (the client uses ring), host keys from ed25519-dalek, p256 and an RSA key
//! the test generates, key exchange over X25519 and the NIST curves of the RustCrypto crates.
//! It speaks enough of RFC 4253, 4252 and 4254 to sign in, run commands and a shell, forward
//! a port, and serve SFTP from memory, and can be told to misbehave.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::Peer;

pub const KEXINIT: u8 = 20;

/// The host key of the server.
#[derive(Clone)]
pub enum HostKind {
    Ed25519([u8; 32]),
    P256([u8; 32]),
    /// A PKCS#1 DER private key: signs `rsa-sha2-256` or `rsa-sha2-512`, as agreed.
    Rsa(Vec<u8>),
}

/// A 2048-bit RSA key in PKCS#1 DER, generated now.
pub fn rsa_key() -> Vec<u8> {
    use rsa::Generate as _;
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    let key = rsa::PrivateKey::generate();
    key.to_pkcs1_der().unwrap().as_bytes().to_vec()
}

/// `ssh-rsa` blob of a PKCS#1 DER private key.
pub fn rsa_blob(der: &[u8]) -> Vec<u8> {
    let pair = ring::rsa::KeyPair::from_der(der).unwrap();
    let parts: ring::rsa::PublicKeyComponents<Vec<u8>> = pair.public().into();
    let mut out = string(b"ssh-rsa");
    out.extend(mpint(&parts.e));
    out.extend(mpint(&parts.n));
    out
}

impl HostKind {
    fn name(&self) -> &'static str {
        match self {
            HostKind::Ed25519(_) => "ssh-ed25519",
            HostKind::P256(_) => "ecdsa-sha2-nistp256",
            HostKind::Rsa(_) => "ssh-rsa",
        }
    }

    pub fn blob(&self) -> Vec<u8> {
        match self {
            HostKind::Rsa(der) => rsa_blob(der),
            HostKind::Ed25519(seed) => {
                let key = ed25519_dalek::SigningKey::from_bytes(seed);
                let mut out = string(b"ssh-ed25519");
                out.extend(string(key.verifying_key().as_bytes()));
                out
            }
            HostKind::P256(scalar) => {
                let key = p256::ecdsa::SigningKey::from_slice(scalar).unwrap();
                let point = key.verifying_key().to_sec1_point(false);
                let mut out = string(b"ecdsa-sha2-nistp256");
                out.extend(string(b"nistp256"));
                out.extend(string(point.as_bytes()));
                out
            }
        }
    }

    /// `type base64`, as a policy pins it.
    pub fn line(&self) -> String {
        use base64::Engine as _;
        format!(
            "{} {}",
            self.name(),
            base64::engine::general_purpose::STANDARD.encode(self.blob())
        )
    }

    fn sign(&self, data: &[u8], alg: &str) -> Vec<u8> {
        match self {
            HostKind::Rsa(der) => {
                let pair = ring::rsa::KeyPair::from_der(der).unwrap();
                let padding: &dyn ring::signature::RsaEncoding = match alg {
                    "rsa-sha2-512" => &ring::signature::RSA_PKCS1_SHA512,
                    _ => &ring::signature::RSA_PKCS1_SHA256,
                };
                let mut sig = vec![0u8; pair.public().modulus_len()];
                pair.sign(padding, &ring::rand::SystemRandom::new(), data, &mut sig)
                    .unwrap();
                let mut out = string(alg.as_bytes());
                out.extend(string(&sig));
                out
            }
            HostKind::Ed25519(seed) => {
                use ed25519_dalek::Signer as _;
                let key = ed25519_dalek::SigningKey::from_bytes(seed);
                let mut out = string(b"ssh-ed25519");
                out.extend(string(&key.sign(data).to_bytes()));
                out
            }
            HostKind::P256(scalar) => {
                use p256::ecdsa::signature::Signer as _;
                let key = p256::ecdsa::SigningKey::from_slice(scalar).unwrap();
                let sig: p256::ecdsa::Signature = key.sign(data);
                let bytes = sig.to_bytes();
                let mut inner = mpint(&bytes[..32]);
                inner.extend(mpint(&bytes[32..]));
                let mut out = string(b"ecdsa-sha2-nistp256");
                out.extend(string(&inner));
                out
            }
        }
    }
}

pub fn string(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn mpint(magnitude: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = magnitude.iter().copied().skip_while(|b| *b == 0).collect();
    let mut body = Vec::new();
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        body.push(0);
    }
    body.extend(trimmed);
    string(&body)
}

fn names(list: &[&str]) -> Vec<u8> {
    string(list.join(",").as_bytes())
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u8(&mut self) -> u8 {
        let b = self.0[0];
        self.0 = &self.0[1..];
        b
    }
    fn u32(&mut self) -> u32 {
        let v = u32::from_be_bytes(self.0[..4].try_into().unwrap());
        self.0 = &self.0[4..];
        v
    }
    fn string(&mut self) -> &'a [u8] {
        let n = self.u32() as usize;
        let s = &self.0[..n];
        self.0 = &self.0[n..];
        s
    }
    fn bool(&mut self) -> bool {
        self.u8() != 0
    }
}

enum Cipher {
    Clear,
    Gcm { key: Vec<u8>, nonce: [u8; 12] },
    Chacha(Box<[u8; 64]>),
}

struct Dir {
    cipher: Cipher,
    seq: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Misbehave {
    None,
    /// A packet before KEXINIT, which strict key exchange forbids.
    IgnoreBeforeKexinit,
    /// A key re-exchange after sign-in.
    Rekey,
    /// The host key blob sent is not the one it signs with.
    WrongSignature,
    /// Commands get no answer at all.
    Silent,
}

pub struct SshServer {
    pub kex: Vec<&'static str>,
    pub host_algs: Vec<&'static str>,
    pub ciphers: Vec<&'static str>,
    pub strict: bool,
    pub host: HostKind,
    pub user: Vec<u8>,
    pub password: Vec<u8>,
    /// Client public key blobs it accepts.
    pub keys: Vec<Vec<u8>>,
    /// Keyboard-interactive prompts and the answers it expects.
    pub prompts: Vec<(&'static str, Vec<u8>)>,
    /// What a command prints: (stdout, stderr, exit status).
    pub exec: fn(&[u8]) -> (Vec<u8>, Vec<u8>, u32),
    pub misbehave: Misbehave,
    /// What it saw.
    pub execs: Vec<Vec<u8>>,
    pub methods: Vec<String>,
    pub signed_in: bool,
    pub shell_input: Vec<u8>,
    pub agreed_cipher: String,
    pub agreed_kex: String,
    pub agreed_host: String,
    /// The SFTP files, by path, and its symbolic links, by path to target.
    pub files: BTreeMap<String, Vec<u8>>,
    pub links: BTreeMap<String, String>,
    /// SFTP directories made explicitly (a directory also exists under any file).
    pub dirs: std::collections::BTreeSet<String>,
    /// Directories whose listing was handed out (the next READDIR is the end).
    listed: std::collections::BTreeSet<String>,
    /// SFTP requests it got, by type and path.
    pub sftp_seen: Vec<(u8, String)>,
    /// `host:port` it forwards to; what it saw asked, and what came through.
    pub reachable: Vec<String>,
    pub forwards: Vec<String>,
    pub forwarded: Vec<u8>,
    /// Remote forwarding: whether it agrees to listen; the channels it opens once it does
    /// (kind, connected address, port); whether it opens them unasked, after the client's
    /// own channel; what it saw asked and cancelled, and the client's answer to each channel
    /// it opened (its channel number, and the failure reason, if any).
    pub remote_ok: bool,
    pub remote_opens: Vec<(&'static str, &'static str, u32)>,
    pub open_unasked: bool,
    pub binds: Vec<String>,
    pub cancels: Vec<String>,
    pub open_answers: Vec<(u32, Option<u32>)>,
    sftp: bool,
    sftp_in: Vec<u8>,
    forwarding: bool,
    sent_close: bool,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    client_version: Option<Vec<u8>>,
    client_kexinit: Vec<u8>,
    server_kexinit: Vec<u8>,
    session_id: Vec<u8>,
    k: Vec<u8>,
    h: Vec<u8>,
    pending_in: Option<Cipher>,
    inn: Dir,
    out: Dir,
    strict_on: bool,
    closed: bool,
    channel: Option<u32>,
    shell: bool,
    kbd_round: usize,
}

impl SshServer {
    pub fn new(host: HostKind) -> Self {
        let mut server = Self {
            kex: vec!["curve25519-sha256", "ecdh-sha2-nistp256"],
            host_algs: vec!["ssh-ed25519", "ecdsa-sha2-nistp256"],
            ciphers: vec!["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"],
            strict: true,
            host,
            user: b"deploy".to_vec(),
            password: Vec::new(),
            keys: Vec::new(),
            prompts: Vec::new(),
            exec: |_| (Vec::new(), Vec::new(), 0),
            misbehave: Misbehave::None,
            execs: Vec::new(),
            methods: Vec::new(),
            signed_in: false,
            shell_input: Vec::new(),
            agreed_cipher: String::new(),
            agreed_kex: String::new(),
            agreed_host: String::new(),
            files: BTreeMap::new(),
            links: BTreeMap::new(),
            dirs: std::collections::BTreeSet::new(),
            listed: std::collections::BTreeSet::new(),
            sftp_seen: Vec::new(),
            reachable: Vec::new(),
            forwards: Vec::new(),
            forwarded: Vec::new(),
            remote_ok: true,
            remote_opens: Vec::new(),
            open_unasked: false,
            binds: Vec::new(),
            cancels: Vec::new(),
            open_answers: Vec::new(),
            sftp: false,
            sftp_in: Vec::new(),
            forwarding: false,
            sent_close: false,
            inbuf: Vec::new(),
            outbuf: b"SSH-2.0-TestServer_1.0\r\n".to_vec(),
            client_version: None,
            client_kexinit: Vec::new(),
            server_kexinit: Vec::new(),
            session_id: Vec::new(),
            k: Vec::new(),
            h: Vec::new(),
            pending_in: None,
            inn: Dir {
                cipher: Cipher::Clear,
                seq: 0,
            },
            out: Dir {
                cipher: Cipher::Clear,
                seq: 0,
            },
            strict_on: false,
            closed: false,
            channel: None,
            shell: false,
            kbd_round: 0,
        };
        server.password = b"hunter2-pass".to_vec();
        server
    }

    fn kexinit(&self) -> Vec<u8> {
        let mut kex = self.kex.clone();
        if self.strict {
            kex.push("kex-strict-s-v00@openssh.com");
        }
        let mut p = vec![KEXINIT];
        p.extend([9u8; 16]);
        p.extend(names(&kex));
        p.extend(names(&self.host_algs));
        p.extend(names(&self.ciphers));
        p.extend(names(&self.ciphers));
        p.extend(names(&["hmac-sha2-256-etm@openssh.com", "hmac-sha1"]));
        p.extend(names(&["hmac-sha2-256-etm@openssh.com", "hmac-sha1"]));
        p.extend(names(&["none"]));
        p.extend(names(&["none"]));
        p.extend(names(&[]));
        p.extend(names(&[]));
        p.push(0);
        p.extend([0u8; 4]);
        p
    }

    fn send(&mut self, payload: &[u8]) {
        let dir = &mut self.out;
        let (block, counted) = match dir.cipher {
            Cipher::Gcm { .. } => (16, 1 + payload.len()),
            Cipher::Clear | Cipher::Chacha(_) => (8, 5 + payload.len()),
        };
        let mut padding = block - counted % block;
        if padding < 4 {
            padding += block;
        }
        let length = (1 + payload.len() + padding) as u32;
        let mut body = vec![padding as u8];
        body.extend_from_slice(payload);
        body.extend(vec![0u8; padding]);
        match &mut dir.cipher {
            Cipher::Clear => {
                self.outbuf.extend(length.to_be_bytes());
                self.outbuf.extend(body);
            }
            Cipher::Gcm { key, nonce } => {
                let aad = length.to_be_bytes();
                let sealed = gcm_seal(key, nonce, &aad, &body);
                self.outbuf.extend(aad);
                self.outbuf.extend(sealed);
                bump(nonce);
            }
            Cipher::Chacha(key) => {
                let sealing = ring::aead::chacha20_poly1305_openssh::SealingKey::new(key);
                let mut packet = length.to_be_bytes().to_vec();
                packet.extend(body);
                let mut tag = [0u8; 16];
                sealing.seal_in_place(dir.seq, &mut packet, &mut tag);
                self.outbuf.extend(packet);
                self.outbuf.extend(tag);
            }
        }
        dir.seq = dir.seq.wrapping_add(1);
    }

    /// One packet from the input, if a whole one is there.
    fn packet(&mut self) -> Option<Vec<u8>> {
        if self.inbuf.len() < 4 {
            return None;
        }
        let head: [u8; 4] = self.inbuf[..4].try_into().unwrap();
        let length = match &self.inn.cipher {
            Cipher::Chacha(key) => {
                let opening = ring::aead::chacha20_poly1305_openssh::OpeningKey::new(key);
                u32::from_be_bytes(opening.decrypt_packet_length(self.inn.seq, head))
            }
            _ => u32::from_be_bytes(head),
        } as usize;
        let tag = match self.inn.cipher {
            Cipher::Clear => 0,
            _ => 16,
        };
        if self.inbuf.len() < 4 + length + tag {
            return None;
        }
        let raw: Vec<u8> = self.inbuf.drain(..4 + length + tag).collect();
        let body = match &mut self.inn.cipher {
            Cipher::Clear => raw[4..].to_vec(),
            Cipher::Gcm { key, nonce } => {
                let plain = gcm_open(key, nonce, &raw[..4], &raw[4..]);
                bump(nonce);
                plain
            }
            Cipher::Chacha(key) => {
                let opening = ring::aead::chacha20_poly1305_openssh::OpeningKey::new(key);
                let mut data = raw[..4 + length].to_vec();
                let tag: [u8; 16] = raw[4 + length..].try_into().unwrap();
                opening
                    .open_in_place(self.inn.seq, &mut data, &tag)
                    .unwrap()
                    .to_vec()
            }
        };
        self.inn.seq = self.inn.seq.wrapping_add(1);
        let padding = body[0] as usize;
        Some(body[1..body.len() - padding].to_vec())
    }

    fn handle(&mut self, payload: Vec<u8>) {
        let mut r = Reader(&payload);
        match r.u8() {
            KEXINIT => {
                self.client_kexinit = payload.clone();
                let mut r = Reader(&payload[17..]);
                let client_kex: Vec<String> = text_list(r.string());
                let client_hosts = text_list(r.string());
                let client_ciphers = text_list(r.string());
                self.agreed_host = client_hosts
                    .iter()
                    .find(|h| self.host_algs.contains(&h.as_str()))
                    .cloned()
                    .unwrap_or_default();
                let kex = client_kex
                    .iter()
                    .find(|k| self.kex.contains(&k.as_str()))
                    .cloned();
                let cipher = client_ciphers
                    .iter()
                    .find(|c| self.ciphers.contains(&c.as_str()))
                    .cloned();
                self.agreed_kex = kex.unwrap_or_default();
                self.agreed_cipher = cipher.unwrap_or_default();
                self.strict_on = self.strict
                    && client_kex
                        .iter()
                        .any(|k| k == "kex-strict-c-v00@openssh.com");
            }
            30 => {
                // KEX_ECDH_INIT.
                let q_c = r.string().to_vec();
                let (q_s, k) = match self.agreed_kex.as_str() {
                    k if k.starts_with("curve25519") => {
                        let secret = [0x41u8; 32];
                        let public =
                            x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);
                        let shared = x25519_dalek::x25519(secret, q_c.clone().try_into().unwrap());
                        (public.to_vec(), shared.to_vec())
                    }
                    "ecdh-sha2-nistp384" => {
                        use p384::elliptic_curve::sec1::ToSec1Point as _;
                        let secret = p384::SecretKey::from_slice(&[0x43u8; 48]).unwrap();
                        let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
                        let peer = p384::PublicKey::from_sec1_bytes(&q_c).unwrap();
                        let shared = p384::ecdh::diffie_hellman(
                            secret.to_nonzero_scalar(),
                            peer.as_affine(),
                        );
                        (public, shared.raw_secret_bytes().to_vec())
                    }
                    "ecdh-sha2-nistp521" => {
                        use p521::elliptic_curve::sec1::ToSec1Point as _;
                        let mut scalar = [0x44u8; 66];
                        scalar[0] = 0x01;
                        let secret = p521::SecretKey::from_slice(&scalar).unwrap();
                        let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
                        let peer = p521::PublicKey::from_sec1_bytes(&q_c).unwrap();
                        let shared = p521::ecdh::diffie_hellman(
                            secret.to_nonzero_scalar(),
                            peer.as_affine(),
                        );
                        (public, shared.raw_secret_bytes().to_vec())
                    }
                    _ => {
                        let secret = p256::SecretKey::from_slice(&[0x42u8; 32]).unwrap();
                        let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
                        let peer = p256::PublicKey::from_sec1_bytes(&q_c).unwrap();
                        let shared = p256::ecdh::diffie_hellman(
                            secret.to_nonzero_scalar(),
                            peer.as_affine(),
                        );
                        (public, shared.raw_secret_bytes().to_vec())
                    }
                };
                let blob = self.host.blob();
                let k_mpint = mpint(&k);
                let mut exchange = string(self.client_version.as_deref().unwrap_or_default());
                exchange.extend(string(b"SSH-2.0-TestServer_1.0"));
                exchange.extend(string(&self.client_kexinit));
                exchange.extend(string(&self.server_kexinit));
                exchange.extend(string(&blob));
                exchange.extend(string(&q_c));
                exchange.extend(string(&q_s));
                exchange.extend(&k_mpint);
                let h = self.hash(&[&exchange]);
                let signature = if self.misbehave == Misbehave::WrongSignature {
                    HostKind::Ed25519([3; 32]).sign(&h, "ssh-ed25519")
                } else {
                    self.host.sign(&h, &self.agreed_host)
                };
                let mut reply = vec![31];
                reply.extend(string(&blob));
                reply.extend(string(&q_s));
                reply.extend(string(&signature));
                self.send(&reply);
                self.send(&[21]);
                self.k = k_mpint;
                self.h = h.clone();
                self.session_id = h;
                let (key_len, iv_len) = sizes(&self.agreed_cipher);
                let key_c = self.derive(b'C', key_len);
                let iv_c = self.derive(b'A', iv_len);
                let key_s = self.derive(b'D', key_len);
                let iv_s = self.derive(b'B', iv_len);
                self.out.cipher = cipher(&self.agreed_cipher, key_s, &iv_s);
                if self.strict_on {
                    self.out.seq = 0;
                }
                self.pending_in = Some(cipher(&self.agreed_cipher, key_c, &iv_c));
            }
            21 => {
                self.inn.cipher = self.pending_in.take().unwrap();
                if self.strict_on {
                    self.inn.seq = 0;
                }
            }
            5 => {
                let service = r.string().to_vec();
                let mut reply = vec![6];
                reply.extend(string(&service));
                self.send(&reply);
            }
            50 => self.userauth(&payload),
            61 => {
                // INFO_RESPONSE.
                let n = r.u32() as usize;
                let answers: Vec<Vec<u8>> = (0..n).map(|_| r.string().to_vec()).collect();
                let expected: Vec<Vec<u8>> = self.prompts.iter().map(|p| p.1.clone()).collect();
                if answers == expected {
                    self.success();
                } else {
                    self.send(&[51, 0, 0, 0, 0, 0]);
                }
            }
            90 => {
                let kind = r.string().to_vec();
                let theirs = r.u32();
                self.sftp = false;
                self.sftp_in.clear();
                self.forwarding = false;
                self.sent_close = false;
                if kind == b"direct-tcpip" {
                    let (_window, _packet) = (r.u32(), r.u32());
                    let host = String::from_utf8(r.string().to_vec()).unwrap();
                    let port = r.u32();
                    let target = format!("{host}:{port}");
                    self.forwards.push(target.clone());
                    if !self.reachable.contains(&target) {
                        // 1: SSH_OPEN_ADMINISTRATIVELY_PROHIBITED.
                        let mut refuse = vec![92];
                        refuse.extend(theirs.to_be_bytes());
                        refuse.extend(1u32.to_be_bytes());
                        refuse.extend(string(b"prohibited"));
                        refuse.extend(string(b""));
                        self.send(&refuse);
                        return;
                    }
                    self.forwarding = true;
                }
                self.channel = Some(theirs);
                let mut reply = vec![91];
                reply.extend(theirs.to_be_bytes());
                reply.extend(7u32.to_be_bytes());
                reply.extend((1u32 << 20).to_be_bytes());
                reply.extend(16384u32.to_be_bytes());
                self.send(&reply);
                if self.open_unasked {
                    self.open_remote();
                }
            }
            80 => {
                let kind = r.string().to_vec();
                let want = r.bool();
                let address = String::from_utf8(r.string().to_vec()).unwrap();
                let port = r.u32();
                match kind.as_slice() {
                    b"tcpip-forward" => {
                        self.binds.push(format!("{address}:{port}"));
                        if want {
                            self.send(&[if self.remote_ok { 81 } else { 82 }]);
                        }
                        if self.remote_ok {
                            self.open_remote();
                        }
                    }
                    b"cancel-tcpip-forward" => self.cancels.push(format!("{address}:{port}")),
                    _ if want => self.send(&[82]),
                    _ => {}
                }
            }
            91 => {
                // The client took a channel this server opened: data goes both ways on it.
                let ours = r.u32();
                let theirs = r.u32();
                self.open_answers.push((ours, None));
                self.channel = Some(theirs);
                self.forwarding = true;
                self.sent_close = false;
            }
            92 => {
                let ours = r.u32();
                let reason = r.u32();
                self.open_answers.push((ours, Some(reason)));
            }
            98 => {
                let _recipient = r.u32();
                let kind = r.string().to_vec();
                let want = r.bool();
                let channel = self.channel.unwrap();
                if want {
                    let mut ok = vec![99];
                    ok.extend(channel.to_be_bytes());
                    self.send(&ok);
                }
                match kind.as_slice() {
                    b"exec" if self.misbehave == Misbehave::Silent => {}
                    b"exec" => {
                        let command = r.string().to_vec();
                        self.execs.push(command.clone());
                        let (stdout, stderr, status) = (self.exec)(&command);
                        self.data(&stdout, false);
                        if !stderr.is_empty() {
                            self.data(&stderr, true);
                        }
                        let mut exit = vec![98];
                        exit.extend(channel.to_be_bytes());
                        exit.extend(string(b"exit-status"));
                        exit.push(0);
                        exit.extend(status.to_be_bytes());
                        self.send(&exit);
                        let mut eof = vec![96];
                        eof.extend(channel.to_be_bytes());
                        self.send(&eof);
                        let mut close = vec![97];
                        close.extend(channel.to_be_bytes());
                        self.send(&close);
                        self.sent_close = true;
                    }
                    b"shell" => {
                        self.shell = true;
                        self.data(b"$ ", false);
                    }
                    b"subsystem" => {
                        assert_eq!(r.string(), b"sftp");
                        self.sftp = true;
                    }
                    _ => {}
                }
            }
            94 if self.sftp => {
                let _recipient = r.u32();
                let data = r.string().to_vec();
                self.sftp_in.extend_from_slice(&data);
                while self.sftp_in.len() >= 4 {
                    let len = u32::from_be_bytes(self.sftp_in[..4].try_into().unwrap()) as usize;
                    if self.sftp_in.len() < 4 + len {
                        break;
                    }
                    let packet: Vec<u8> = self.sftp_in.drain(..4 + len).skip(4).collect();
                    let answer = self.sftp_answer(&packet);
                    self.data(&string(&answer), false);
                }
            }
            94 if self.forwarding => {
                let _recipient = r.u32();
                let data = r.string().to_vec();
                self.forwarded.extend_from_slice(&data);
                let mut echo = b"echo:".to_vec();
                echo.extend_from_slice(&data);
                self.data(&echo, false);
            }
            94 => {
                let _recipient = r.u32();
                let data = r.string().to_vec();
                self.shell_input.extend_from_slice(&data);
                if self.shell {
                    if data == b"exit\n" {
                        let channel = self.channel.unwrap();
                        let mut close = vec![97];
                        close.extend(channel.to_be_bytes());
                        self.send(&close);
                        self.sent_close = true;
                    } else {
                        let (stdout, _, _) = (self.exec)(&data);
                        self.data(&stdout, false);
                    }
                }
            }
            97 => {
                // A close it did not start gets its own close back (RFC 4254, 5.3).
                if let Some(channel) = self.channel
                    && !self.sent_close
                {
                    let mut close = vec![97];
                    close.extend(channel.to_be_bytes());
                    self.send(&close);
                }
                self.channel = None;
            }
            1 => self.closed = true,
            _ => {}
        }
    }

    /// The hash of the agreed key exchange (RFC 5656, 6.2.1: by curve size).
    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            d.finalize().to_vec()
        }
        match self.agreed_kex.as_str() {
            "ecdh-sha2-nistp384" => run::<Sha384>(parts),
            "ecdh-sha2-nistp521" => run::<Sha512>(parts),
            _ => run::<Sha256>(parts),
        }
    }

    fn derive(&self, letter: u8, len: usize) -> Vec<u8> {
        let mut out = self.hash(&[&self.k, &self.h, &[letter], &self.session_id]);
        while out.len() < len {
            let more = self.hash(&[&self.k, &self.h, &out]);
            out.extend(more);
        }
        out.truncate(len);
        out
    }

    /// Answers one SFTP request from the files in memory: links resolve in REALPATH and show
    /// as links in LSTAT.
    fn sftp_answer(&mut self, packet: &[u8]) -> Vec<u8> {
        const STATUS: u8 = 101;
        let mut r = Reader(packet);
        let kind = r.u8();
        if kind == 1 {
            let mut version = vec![2];
            version.extend(3u32.to_be_bytes());
            return version;
        }
        let id = r.u32();
        let status = |code: u32| {
            let mut out = vec![STATUS];
            out.extend(id.to_be_bytes());
            out.extend(code.to_be_bytes());
            out.extend(string(b""));
            out.extend(string(b""));
            out
        };
        let path_of = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).unwrap();
        match kind {
            // REALPATH.
            16 => {
                let path = path_of(r.string());
                self.sftp_seen.push((16, path.clone()));
                let mut real = path.clone();
                for (link, target) in &self.links {
                    if real == *link {
                        real = target.clone();
                    } else if let Some(rest) = real.strip_prefix(&format!("{link}/")) {
                        real = format!("{target}/{rest}");
                    }
                }
                let known = self.files.contains_key(&real) || self.is_dir(&real);
                if !known {
                    return status(2);
                }
                let mut out = vec![104];
                out.extend(id.to_be_bytes());
                out.extend(1u32.to_be_bytes());
                out.extend(string(real.as_bytes()));
                out.extend(string(real.as_bytes()));
                out.extend(0u32.to_be_bytes());
                out
            }
            // LSTAT.
            7 => {
                let path = path_of(r.string());
                self.sftp_seen.push((7, path.clone()));
                let mode: u32 = if self.links.contains_key(&path) {
                    0o120_777
                } else if self.files.contains_key(&path) {
                    0o100_644
                } else if self.is_dir(&path) {
                    0o040_755
                } else {
                    return status(2);
                };
                let size = self.files.get(&path).map_or(0, |f| f.len() as u64);
                let mut out = vec![105];
                out.extend(id.to_be_bytes());
                out.extend(0x0du32.to_be_bytes());
                out.extend(size.to_be_bytes());
                out.extend(mode.to_be_bytes());
                out.extend(1_700_000_000u32.to_be_bytes());
                out.extend(1_700_000_000u32.to_be_bytes());
                out
            }
            // OPENDIR: the handle is the path.
            11 => {
                let path = path_of(r.string());
                self.sftp_seen.push((11, path.clone()));
                if !self.is_dir(&path) {
                    return status(2);
                }
                self.listed.remove(&path);
                let mut out = vec![102];
                out.extend(id.to_be_bytes());
                out.extend(string(path.as_bytes()));
                out
            }
            // READDIR: every name once, with . and .., then the end.
            12 => {
                let path = path_of(r.string());
                if !self.listed.insert(path.clone()) {
                    return status(1);
                }
                let prefix = if path == "/" {
                    "/".to_string()
                } else {
                    format!("{path}/")
                };
                let mut names: Vec<(String, u32, u64)> =
                    vec![(".".into(), 0o040_755, 0), ("..".into(), 0o040_755, 0)];
                let mut seen = std::collections::BTreeSet::new();
                for (file, content) in &self.files {
                    if let Some(rest) = file.strip_prefix(&prefix) {
                        match rest.split_once('/') {
                            None => names.push((rest.into(), 0o100_644, content.len() as u64)),
                            Some((dir, _)) if seen.insert(dir.to_string()) => {
                                names.push((dir.into(), 0o040_755, 0));
                            }
                            Some(_) => {}
                        }
                    }
                }
                for dir in &self.dirs {
                    if let Some(rest) = dir.strip_prefix(&prefix)
                        && !rest.contains('/')
                        && seen.insert(rest.to_string())
                    {
                        names.push((rest.into(), 0o040_755, 0));
                    }
                }
                for link in self.links.keys() {
                    if let Some(rest) = link.strip_prefix(&prefix)
                        && !rest.contains('/')
                    {
                        names.push((rest.into(), 0o120_777, 0));
                    }
                }
                let mut out = vec![104];
                out.extend(id.to_be_bytes());
                out.extend((names.len() as u32).to_be_bytes());
                for (name, mode, size) in names {
                    out.extend(string(name.as_bytes()));
                    out.extend(string(format!("-rw-r--r-- 1 u g {size} {name}").as_bytes()));
                    out.extend(0x05u32.to_be_bytes());
                    out.extend(size.to_be_bytes());
                    out.extend(mode.to_be_bytes());
                }
                out
            }
            // REMOVE.
            13 => {
                let path = path_of(r.string());
                self.sftp_seen.push((13, path.clone()));
                if self.files.remove(&path).is_some() || self.links.remove(&path).is_some() {
                    status(0)
                } else {
                    status(2)
                }
            }
            // MKDIR.
            14 => {
                let path = path_of(r.string());
                self.sftp_seen.push((14, path.clone()));
                self.dirs.insert(path);
                status(0)
            }
            // RMDIR.
            15 => {
                let path = path_of(r.string());
                self.sftp_seen.push((15, path.clone()));
                let busy = self
                    .files
                    .keys()
                    .any(|f| f.starts_with(&format!("{path}/")));
                if busy || !self.dirs.remove(&path) {
                    status(4)
                } else {
                    status(0)
                }
            }
            // RENAME.
            18 => {
                let from = path_of(r.string());
                let to = path_of(r.string());
                self.sftp_seen.push((18, format!("{from} -> {to}")));
                match self.files.remove(&from) {
                    Some(content) => {
                        self.files.insert(to, content);
                        status(0)
                    }
                    None => status(2),
                }
            }
            // OPEN: the handle is the path.
            3 => {
                let path = path_of(r.string());
                let flags = r.u32();
                self.sftp_seen.push((3, path.clone()));
                if flags & 0x08 != 0 {
                    self.files.insert(path.clone(), Vec::new());
                } else if !self.files.contains_key(&path) {
                    return status(2);
                }
                let mut out = vec![102];
                out.extend(id.to_be_bytes());
                out.extend(string(path.as_bytes()));
                out
            }
            // READ.
            5 => {
                let path = path_of(r.string());
                let offset = u64::from_be_bytes(r.0[..8].try_into().unwrap()) as usize;
                r.0 = &r.0[8..];
                let len = r.u32() as usize;
                let file = self.files.get(&path).cloned().unwrap_or_default();
                if offset >= file.len() {
                    return status(1);
                }
                let end = (offset + len).min(file.len());
                let mut out = vec![103];
                out.extend(id.to_be_bytes());
                out.extend(string(&file[offset..end]));
                out
            }
            // WRITE.
            6 => {
                let path = path_of(r.string());
                let offset = u64::from_be_bytes(r.0[..8].try_into().unwrap()) as usize;
                r.0 = &r.0[8..];
                let data = r.string().to_vec();
                let file = self.files.entry(path).or_default();
                file.truncate(offset);
                file.extend(data);
                status(0)
            }
            // CLOSE.
            4 => status(0),
            _ => status(8),
        }
    }

    fn is_dir(&self, path: &str) -> bool {
        path == "/"
            || self.dirs.contains(path)
            || self
                .files
                .keys()
                .any(|f| f.starts_with(&format!("{path}/")))
    }

    /// Opens the channels of `remote_opens`, numbered from 100, from one originator.
    fn open_remote(&mut self) {
        for (i, (kind, address, port)) in self.remote_opens.clone().into_iter().enumerate() {
            let mut open = vec![90];
            open.extend(string(kind.as_bytes()));
            open.extend((100 + i as u32).to_be_bytes());
            open.extend((1u32 << 20).to_be_bytes());
            open.extend(16384u32.to_be_bytes());
            open.extend(string(address.as_bytes()));
            open.extend(port.to_be_bytes());
            open.extend(string(b"203.0.113.9"));
            open.extend((40_000 + i as u32).to_be_bytes());
            self.send(&open);
        }
    }

    fn data(&mut self, bytes: &[u8], stderr: bool) {
        let channel = self.channel.unwrap();
        let mut packet = vec![if stderr { 95 } else { 94 }];
        packet.extend(channel.to_be_bytes());
        if stderr {
            packet.extend(1u32.to_be_bytes());
        }
        packet.extend(string(bytes));
        self.send(&packet);
    }

    fn success(&mut self) {
        self.signed_in = true;
        self.send(&[52]);
        if self.misbehave == Misbehave::Rekey {
            let init = self.kexinit();
            self.send(&init);
        }
    }

    fn userauth(&mut self, payload: &[u8]) {
        let mut r = Reader(&payload[1..]);
        let user = r.string().to_vec();
        let _service = r.string();
        let method = String::from_utf8(r.string().to_vec()).unwrap();
        self.methods.push(method.clone());
        let ok = user == self.user
            && match method.as_str() {
                "password" => {
                    let _ = r.bool();
                    r.string() == self.password.as_slice()
                }
                "publickey" => {
                    let signed = r.bool();
                    let alg = r.string().to_vec();
                    let blob = r.string().to_vec();
                    let sig = r.string().to_vec();
                    let mut data = string(&self.session_id);
                    data.push(50);
                    data.extend(string(&user));
                    data.extend(string(b"ssh-connection"));
                    data.extend(string(b"publickey"));
                    data.push(1);
                    data.extend(string(&alg));
                    data.extend(string(&blob));
                    signed && self.keys.contains(&blob) && verify_client(&alg, &blob, &data, &sig)
                }
                "keyboard-interactive" => {
                    let mut request = vec![60];
                    request.extend(string(b""));
                    request.extend(string(b""));
                    request.extend(string(b""));
                    request.extend((self.prompts.len() as u32).to_be_bytes());
                    for (prompt, _) in self.prompts.clone() {
                        request.extend(string(prompt.as_bytes()));
                        request.push(0);
                    }
                    self.kbd_round += 1;
                    self.send(&request);
                    return;
                }
                _ => false,
            };
        if ok {
            self.success();
        } else {
            let mut failure = vec![51];
            failure.extend(names(&["publickey", "password"]));
            failure.push(0);
            self.send(&failure);
        }
    }
}

fn verify_client(alg: &[u8], blob: &[u8], data: &[u8], sig: &[u8]) -> bool {
    let mut s = Reader(sig);
    if s.string() != alg {
        return false;
    }
    let raw = s.string();
    let mut b = Reader(blob);
    let _ = b.string();
    match alg {
        b"ssh-ed25519" => {
            use ed25519_dalek::Verifier as _;
            let key =
                ed25519_dalek::VerifyingKey::from_bytes(b.string().try_into().unwrap()).unwrap();
            let sig = ed25519_dalek::Signature::from_bytes(raw.try_into().unwrap());
            key.verify(data, &sig).is_ok()
        }
        b"ecdsa-sha2-nistp384" => {
            use p384::ecdsa::signature::Verifier as _;
            let _curve = b.string();
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(b.string()).unwrap();
            let mut rs = Reader(raw);
            let (r, s) = (rs.string(), rs.string());
            let mut fixed = [0u8; 96];
            let r = r.strip_prefix(&[0]).unwrap_or(r);
            let s = s.strip_prefix(&[0]).unwrap_or(s);
            fixed[48 - r.len()..48].copy_from_slice(r);
            fixed[96 - s.len()..].copy_from_slice(s);
            let sig = p384::ecdsa::Signature::from_slice(&fixed).unwrap();
            key.verify(data, &sig).is_ok()
        }
        b"rsa-sha2-256" | b"rsa-sha2-512" => {
            let e = b.string();
            let n = b.string();
            let params = if alg == b"rsa-sha2-256" {
                &ring::signature::RSA_PKCS1_2048_8192_SHA256
            } else {
                &ring::signature::RSA_PKCS1_2048_8192_SHA512
            };
            let strip = |v: &[u8]| v.strip_prefix(&[0]).unwrap_or(v).to_vec();
            ring::signature::RsaPublicKeyComponents {
                n: strip(n),
                e: strip(e),
            }
            .verify(params, data, raw)
            .is_ok()
        }
        b"ecdsa-sha2-nistp256" => {
            use p256::ecdsa::signature::Verifier as _;
            let _curve = b.string();
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(b.string()).unwrap();
            let mut rs = Reader(raw);
            let (r, s) = (rs.string(), rs.string());
            let mut fixed = [0u8; 64];
            let r = r.strip_prefix(&[0]).unwrap_or(r);
            let s = s.strip_prefix(&[0]).unwrap_or(s);
            fixed[32 - r.len()..32].copy_from_slice(r);
            fixed[64 - s.len()..].copy_from_slice(s);
            let sig = p256::ecdsa::Signature::from_slice(&fixed).unwrap();
            key.verify(data, &sig).is_ok()
        }
        _ => false,
    }
}

fn text_list(bytes: &[u8]) -> Vec<String> {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .split(',')
        .map(str::to_string)
        .collect()
}

fn sizes(cipher: &str) -> (usize, usize) {
    match cipher {
        "aes256-gcm@openssh.com" => (32, 12),
        "aes128-gcm@openssh.com" => (16, 12),
        _ => (64, 0),
    }
}

fn cipher(name: &str, key: Vec<u8>, iv: &[u8]) -> Cipher {
    if name.starts_with("chacha20") {
        Cipher::Chacha(Box::new(key.try_into().unwrap()))
    } else {
        Cipher::Gcm {
            key,
            nonce: iv.try_into().unwrap(),
        }
    }
}

fn bump(nonce: &mut [u8; 12]) {
    let counter = u64::from_be_bytes(nonce[4..].try_into().unwrap()).wrapping_add(1);
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
}

fn gcm_seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let n = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::try_from(&nonce[..]).unwrap();
    let payload = Payload { msg: plain, aad };
    if key.len() == 32 {
        aes_gcm::Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(&n, payload)
            .unwrap()
    } else {
        aes_gcm::Aes128Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(&n, payload)
            .unwrap()
    }
}

fn gcm_open(key: &[u8], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Vec<u8> {
    let n = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::try_from(&nonce[..]).unwrap();
    let payload = Payload { msg: sealed, aad };
    if key.len() == 32 {
        aes_gcm::Aes256Gcm::new_from_slice(key)
            .unwrap()
            .decrypt(&n, payload)
            .unwrap()
    } else {
        aes_gcm::Aes128Gcm::new_from_slice(key)
            .unwrap()
            .decrypt(&n, payload)
            .unwrap()
    }
}

impl Peer for SshServer {
    fn feed(&mut self, bytes: &[u8]) {
        self.inbuf.extend_from_slice(bytes);
        if self.client_version.is_none() {
            let Some(at) = self.inbuf.windows(2).position(|w| w == b"\r\n") else {
                return;
            };
            let line: Vec<u8> = self.inbuf.drain(..at + 2).collect();
            self.client_version = Some(line[..line.len() - 2].to_vec());
            if self.misbehave == Misbehave::IgnoreBeforeKexinit {
                let mut ignore = vec![2];
                ignore.extend(string(b"x"));
                self.send(&ignore);
            }
            self.server_kexinit = self.kexinit();
            let init = self.server_kexinit.clone();
            self.send(&init);
        }
        while let Some(packet) = self.packet() {
            self.handle(packet);
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbuf)
    }

    fn closed(&self) -> bool {
        self.closed
    }
}
