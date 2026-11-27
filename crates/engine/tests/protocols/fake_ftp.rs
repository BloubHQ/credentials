//! An FTP server for the tests: the control connection line by line, and data connections
//! as pipes the node opens through its transport.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

use engine::egress::{Arrived, Stream};
use engine::error::TransportKind;

use super::Peer;

/// One data connection: what the server sends, what the node wrote, how it ended.
#[derive(Default)]
pub struct Pipe {
    pub to_node: Vec<u8>,
    pub from_node: Vec<u8>,
    /// The server has sent everything.
    pub done: bool,
    /// The server's end is a cut (no TLS close_notify): the transport reports it as closed.
    pub cut: bool,
    /// The node closed its end.
    pub node_closed: bool,
}

pub struct DataStream(Rc<RefCell<Pipe>>);

impl Stream for DataStream {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.0.borrow_mut().from_node.extend_from_slice(bytes);
        Ok(())
    }

    fn read_until(&mut self, _: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        Err(engine::Error::transport(TransportKind::Unsupported, true))
    }

    fn read_some(&mut self, max: usize, _: Duration) -> engine::Result<Arrived> {
        let mut pipe = self.0.borrow_mut();
        if !pipe.to_node.is_empty() {
            let n = pipe.to_node.len().min(max);
            return Ok(Arrived::Bytes(pipe.to_node.drain(..n).collect()));
        }
        match (pipe.done, pipe.cut) {
            (true, true) => Err(engine::Error::transport(TransportKind::Closed, true)),
            (true, false) => Ok(Arrived::End),
            _ => Ok(Arrived::Nothing),
        }
    }

    fn close(&mut self) -> engine::Result<()> {
        self.0.borrow_mut().node_closed = true;
        Ok(())
    }
}

pub struct FtpServer {
    pub user: Vec<u8>,
    pub secret: Vec<u8>,
    /// Files and directories by path.
    pub files: BTreeMap<Vec<u8>, Vec<u8>>,
    pub dirs: BTreeSet<Vec<u8>>,
    /// Whether it takes EPSV, lists MLST, takes PROT P.
    pub epsv: bool,
    pub mlst: bool,
    pub prot_p: bool,
    /// The address its PASV replies name, and the address the transport reached.
    pub pasv_ip: [u8; 4],
    pub peer: Option<IpAddr>,
    /// The port its passive replies name, and the port of its EPSV replies when that differs
    /// (`None`: the same).
    pub data_port: u16,
    pub epsv_port: Option<u16>,
    /// Ports a data connection cannot reach (a firewall in front of the server).
    pub unreachable: Vec<u16>,
    /// Appended to the text of every reply after the sign-in (an echo).
    pub echo: String,
    /// The data connections end in a cut.
    pub cut: bool,
    /// Extra lines for the reply to FEAT (an oversized reply).
    pub feat_lines: usize,
    /// What it saw.
    pub received: Vec<u8>,
    pub commands: Vec<String>,
    pub opened_data: Vec<u16>,
    pub signed_in: bool,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    user_ok: bool,
    rename_from: Option<Vec<u8>>,
    data: Option<Rc<RefCell<Pipe>>>,
    storing: Option<Vec<u8>>,
    closed: bool,
}

fn lines(inbuf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(at) = inbuf.windows(2).position(|w| w == b"\r\n") {
        out.push(inbuf.drain(..at + 2).collect());
    }
    out
}

impl FtpServer {
    /// `greet`: the server greets first (implicit TLS); after AUTH TLS it does not.
    pub fn new(greet: bool, user: &[u8], secret: &[u8]) -> Self {
        let mut files = BTreeMap::new();
        files.insert(b"/srv/reports/a.csv".to_vec(), b"id,total\n1,9\n".to_vec());
        let mut dirs = BTreeSet::new();
        dirs.insert(b"/srv/reports".to_vec());
        Self {
            user: user.to_vec(),
            secret: secret.to_vec(),
            files,
            dirs,
            epsv: true,
            mlst: true,
            prot_p: true,
            pasv_ip: [192, 0, 2, 10],
            peer: Some("192.0.2.10".parse().unwrap()),
            data_port: 50_000,
            epsv_port: None,
            unreachable: Vec::new(),
            echo: String::new(),
            cut: false,
            feat_lines: 0,
            received: Vec::new(),
            commands: Vec::new(),
            opened_data: Vec::new(),
            signed_in: false,
            inbuf: Vec::new(),
            outbuf: if greet {
                b"220 files.example.com FTP ready\r\n".to_vec()
            } else {
                Vec::new()
            },
            user_ok: false,
            rename_from: None,
            data: None,
            storing: None,
            closed: false,
        }
    }

    fn reply(&mut self, text: &str) {
        self.outbuf.extend_from_slice(text.as_bytes());
        if self.signed_in && !self.echo.is_empty() {
            self.outbuf.push(b' ');
            self.outbuf.extend_from_slice(self.echo.as_bytes());
        }
        self.outbuf.extend_from_slice(b"\r\n");
    }

    fn pipe(&mut self) -> Option<Rc<RefCell<Pipe>>> {
        self.data.take()
    }

    fn line(&mut self, line: Vec<u8>) {
        let body = line[..line.len() - 2].to_vec();
        let (verb, arg) = match body.iter().position(|b| *b == b' ') {
            Some(at) => (body[..at].to_vec(), body[at + 1..].to_vec()),
            None => (body.clone(), Vec::new()),
        };
        let verb = String::from_utf8_lossy(&verb).to_ascii_uppercase();
        self.commands
            .push(String::from_utf8_lossy(&body).into_owned());
        if !self.signed_in && !matches!(verb.as_str(), "USER" | "PASS" | "QUIT") {
            self.reply("530 Please login");
            return;
        }
        match verb.as_str() {
            "USER" => {
                self.user_ok = arg == self.user;
                self.reply("331 Password required");
            }
            "PASS" => {
                if self.user_ok && arg == self.secret {
                    self.signed_in = true;
                    self.reply("230 Logged in");
                } else {
                    self.reply("530 Login incorrect");
                }
            }
            "PBSZ" => self.reply("200 PBSZ=0"),
            "PROT" if self.prot_p && arg == b"P" => self.reply("200 Protection set to Private"),
            "PROT" => self.reply("536 Protection level not supported"),
            "TYPE" => self.reply("200 Binary"),
            "FEAT" => {
                let mut text = String::from("211-Features:\r\n EPSV\r\n PASV\r\n");
                if self.mlst {
                    text.push_str(" MLST type*;size*;modify*;\r\n");
                }
                for i in 0..self.feat_lines {
                    text.push_str(&format!(" X{i}\r\n"));
                }
                text.push_str("211 End");
                self.reply(&text);
            }
            "EPSV" if self.epsv => {
                let text = format!(
                    "229 Entering Extended Passive Mode (|||{}|)",
                    self.epsv_port.unwrap_or(self.data_port)
                );
                self.reply(&text);
            }
            "EPSV" => self.reply("500 EPSV not understood"),
            "PASV" => {
                let [a, b, c, d] = self.pasv_ip;
                let (p1, p2) = (self.data_port >> 8, self.data_port & 0xff);
                let text = format!("227 Entering Passive Mode ({a},{b},{c},{d},{p1},{p2})");
                self.reply(&text);
            }
            "RETR" => match (self.files.get(&arg).cloned(), self.pipe()) {
                (Some(content), Some(pipe)) => {
                    self.reply("150 Opening BINARY mode data connection");
                    let mut p = pipe.borrow_mut();
                    p.to_node = content;
                    p.done = true;
                    p.cut = self.cut;
                    drop(p);
                    self.reply("226 Transfer complete");
                }
                (None, _) => self.reply("550 No such file"),
                (_, None) => self.reply("425 Use PASV first"),
            },
            "STOR" => match self.pipe() {
                Some(pipe) => {
                    self.reply("150 Ok to send data");
                    self.storing = Some(arg);
                    self.data = Some(pipe);
                }
                None => self.reply("425 Use PASV first"),
            },
            "MLSD" | "NLST" => match self.pipe() {
                Some(pipe) if self.dirs.contains(&arg) || arg == b"/" => {
                    self.reply("150 Here comes the listing");
                    let mut prefix = arg.clone();
                    if prefix != b"/" {
                        prefix.push(b'/');
                    }
                    let mut listing = Vec::new();
                    if verb == "MLSD" {
                        listing.extend_from_slice(b"type=cdir; .\r\ntype=pdir; ..\r\n");
                    }
                    for (path, content) in &self.files {
                        if let Some(name) = path.strip_prefix(prefix.as_slice()) {
                            if verb == "MLSD" {
                                listing.extend_from_slice(
                                    format!(
                                        "type=file;size={};modify=20250101120000; ",
                                        content.len()
                                    )
                                    .as_bytes(),
                                );
                            }
                            listing.extend_from_slice(name);
                            listing.extend_from_slice(b"\r\n");
                        }
                    }
                    let mut p = pipe.borrow_mut();
                    p.to_node = listing;
                    p.done = true;
                    drop(p);
                    self.reply("226 Directory send OK");
                }
                Some(_) => self.reply("550 No such directory"),
                None => self.reply("425 Use PASV first"),
            },
            "DELE" => {
                if self.files.remove(&arg).is_some() {
                    self.reply("250 Delete operation successful");
                } else {
                    self.reply("550 Delete operation failed");
                }
            }
            "MKD" => {
                self.dirs.insert(arg.clone());
                let text = format!("257 \"{}\" created", String::from_utf8_lossy(&arg));
                self.reply(&text);
            }
            "RNFR" => {
                if self.files.contains_key(&arg) {
                    self.rename_from = Some(arg);
                    self.reply("350 Ready for RNTO");
                } else {
                    self.reply("550 RNFR command failed");
                }
            }
            "RNTO" => match self.rename_from.take() {
                Some(from) => {
                    let content = self.files.remove(&from).unwrap_or_default();
                    self.files.insert(arg, content);
                    self.reply("250 Rename successful");
                }
                None => self.reply("503 RNFR required first"),
            },
            "QUIT" => {
                self.reply("221 Goodbye");
                self.closed = true;
            }
            _ => self.reply("500 Unknown command"),
        }
    }
}

impl Peer for FtpServer {
    fn feed(&mut self, bytes: &[u8]) {
        self.received.extend_from_slice(bytes);
        self.inbuf.extend_from_slice(bytes);
        for line in lines(&mut self.inbuf) {
            self.line(line);
        }
    }

    fn take(&mut self) -> Vec<u8> {
        // A store ends when the node closes its data connection.
        if let Some(pipe) = &self.data
            && self.storing.is_some()
            && pipe.borrow().node_closed
        {
            let content = std::mem::take(&mut pipe.borrow_mut().from_node);
            let path = self.storing.take().unwrap();
            self.files.insert(path, content);
            self.data = None;
            self.reply("226 Transfer complete");
        }
        std::mem::take(&mut self.outbuf)
    }

    fn closed(&self) -> bool {
        self.closed
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer
    }

    fn data(&mut self, port: u16) -> engine::Result<Box<dyn Stream>> {
        self.opened_data.push(port);
        if self.unreachable.contains(&port) {
            return Err(engine::Error::transport(TransportKind::Connect, false));
        }
        let pipe = Rc::new(RefCell::new(Pipe::default()));
        self.data = Some(pipe.clone());
        Ok(Box::new(DataStream(pipe)))
    }
}
