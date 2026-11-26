//! An SSH server for the tests, written apart from the node's client: AES-GCM from the
//! RustCrypto crate (the client uses ring), host keys from ed25519-dalek and p256. It speaks
//! enough of RFC 4253, 4252 and 4254 to sign in, run commands and a shell, and can be told to
//! misbehave.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use sha2::{Digest, Sha256};

use super::Peer;

pub const KEXINIT: u8 = 20;

/// The host key of the server.
#[derive(Clone)]
pub enum HostKind {
    Ed25519([u8; 32]),
    P256([u8; 32]),
}

impl HostKind {
    fn name(&self) -> &'static str {
        match self {
            HostKind::Ed25519(_) => "ssh-ed25519",
            HostKind::P256(_) => "ecdsa-sha2-nistp256",
        }
    }

    pub fn blob(&self) -> Vec<u8> {
        match self {
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

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
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
                let _host = r.string();
                let client_ciphers = text_list(r.string());
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
                let (q_s, k) = if self.agreed_kex.starts_with("curve25519") {
                    let secret = [0x41u8; 32];
                    let public = x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);
                    let shared = x25519_dalek::x25519(secret, q_c.clone().try_into().unwrap());
                    (public.to_vec(), shared.to_vec())
                } else {
                    let secret = p256::SecretKey::from_slice(&[0x42u8; 32]).unwrap();
                    let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
                    let peer = p256::PublicKey::from_sec1_bytes(&q_c).unwrap();
                    let shared =
                        p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
                    (public, shared.raw_secret_bytes().to_vec())
                };
                let blob = self.host.blob();
                let k_mpint = mpint(&k);
                let mut hash = Sha256::new();
                hash.update(string(self.client_version.as_deref().unwrap_or_default()));
                hash.update(string(b"SSH-2.0-TestServer_1.0"));
                hash.update(string(&self.client_kexinit));
                hash.update(string(&self.server_kexinit));
                hash.update(string(&blob));
                hash.update(string(&q_c));
                hash.update(string(&q_s));
                hash.update(&k_mpint);
                let h = hash.finalize().to_vec();
                let signature = if self.misbehave == Misbehave::WrongSignature {
                    HostKind::Ed25519([3; 32]).sign(&h)
                } else {
                    self.host.sign(&h)
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
                let _kind = r.string();
                let theirs = r.u32();
                self.channel = Some(theirs);
                let mut reply = vec![91];
                reply.extend(theirs.to_be_bytes());
                reply.extend(7u32.to_be_bytes());
                reply.extend((1u32 << 20).to_be_bytes());
                reply.extend(16384u32.to_be_bytes());
                self.send(&reply);
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
                    }
                    b"shell" => {
                        self.shell = true;
                        self.data(b"$ ", false);
                    }
                    _ => {}
                }
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
                    } else {
                        let (stdout, _, _) = (self.exec)(&data);
                        self.data(&stdout, false);
                    }
                }
            }
            97 => {
                self.channel = None;
            }
            1 => self.closed = true,
            _ => {}
        }
    }

    fn derive(&self, letter: u8, len: usize) -> Vec<u8> {
        let mut hash = Sha256::new();
        hash.update(&self.k);
        hash.update(&self.h);
        hash.update([letter]);
        hash.update(&self.session_id);
        let mut out = hash.finalize().to_vec();
        while out.len() < len {
            let mut more = Sha256::new();
            more.update(&self.k);
            more.update(&self.h);
            more.update(&out);
            out.extend(more.finalize());
        }
        out.truncate(len);
        out
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
