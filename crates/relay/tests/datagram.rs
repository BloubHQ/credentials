//! Datagrams over the egress relay: the node's connector, the request line, the frames and the
//! host's relay to a UDP destination, over a local TCP link in place of vsock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::io::{self, Cursor};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use engine::egress::Stream;
use engine::readbuf::ReadBuf;
use relay::datagram::{
    self, Egress, RelayDatagramConnector, read_datagram, read_egress_request, take_datagram,
    write_datagram,
};
use relay::{RelayError, answer_tunnel};
use transport::Socket;
use transport::udp::{DatagramConnector, DatagramStream};

#[test]
fn frames_round_trip_and_bad_lengths_are_refused() {
    let mut wire = Vec::new();
    write_datagram(&mut wire, b"one").unwrap();
    write_datagram(&mut wire, &[9u8; 300]).unwrap();
    let mut reader = Cursor::new(wire.clone());
    assert_eq!(read_datagram(&mut reader).unwrap().unwrap(), b"one");
    assert_eq!(read_datagram(&mut reader).unwrap().unwrap(), vec![9u8; 300]);
    assert!(read_datagram(&mut reader).unwrap().is_none());
    // The same frames taken off a buffer, also when they arrive in pieces.
    let mut pending = ReadBuf::new();
    pending.push(&wire[..4]);
    assert!(take_datagram(&mut pending).unwrap().is_none());
    pending.push(&wire[4..]);
    assert_eq!(take_datagram(&mut pending).unwrap().unwrap(), b"one");
    assert_eq!(take_datagram(&mut pending).unwrap().unwrap().len(), 300);
    assert!(pending.pending().is_empty());
    // An empty datagram, and one too long, are not frames.
    assert!(write_datagram(&mut Vec::new(), b"").is_err());
    assert!(write_datagram(&mut Vec::new(), &vec![0u8; datagram::MAX_DATAGRAM + 1]).is_err());
    let mut empty = ReadBuf::new();
    empty.push(&[0, 0]);
    assert!(take_datagram(&mut empty).is_err());
    assert!(read_datagram(&mut Cursor::new(vec![0xff, 0xff])).is_err());
    // A frame cut short.
    assert!(read_datagram(&mut Cursor::new(vec![0, 5, 1])).is_err());
}

#[test]
fn the_request_line_names_the_kind_and_the_destination() {
    let read = |line: &str| read_egress_request(&mut Cursor::new(line.as_bytes().to_vec()));
    assert_eq!(
        read("DATAGRAM radius.example.com:1812\n").unwrap(),
        (Egress::Datagram, "radius.example.com".into(), 1812)
    );
    assert_eq!(
        read("CONNECT api.example.com:443\n").unwrap(),
        (Egress::Connect, "api.example.com".into(), 443)
    );
    for bad in [
        "DATAGRAM radius.example.com:0\n",
        "DATAGRAM radius.example.com\n",
        "DATAGRAM bad host:53\n",
        "BIND radius.example.com:53\n",
        "",
    ] {
        assert!(
            matches!(read(bad), Err(RelayError::Malformed(_))),
            "{bad:?}"
        );
    }
}

/// A host relay on a local TCP port that serves one link as `credentials host` does.
fn host_relay(allow: bool) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut link, _) = listener.accept().unwrap();
        let (kind, host, port) = read_egress_request(&mut link).unwrap();
        assert_eq!(kind, Egress::Datagram);
        if !allow {
            answer_tunnel(&mut link, Err("destination not allowed by the host")).unwrap();
            return;
        }
        let udp = datagram::connect_udp(&host, port).unwrap();
        answer_tunnel(&mut link, Ok(())).unwrap();
        let link2 = link.try_clone().unwrap();
        datagram::serve_datagrams(Box::new(link), Box::new(link2), udp, Duration::from_secs(5))
            .unwrap();
    });
    address
}

fn dial(address: std::net::SocketAddr) -> impl Fn() -> io::Result<Box<dyn Socket>> {
    move || Ok(Box::new(TcpStream::connect(address)?) as Box<dyn Socket>)
}

#[test]
fn datagrams_cross_the_relay_both_ways() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let port = server.local_addr().unwrap().port();
    let answer = thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        let (n, from) = server.recv_from(&mut buffer).unwrap();
        server.send_to(b"accept", from).unwrap();
        server.send_to(b"second", from).unwrap();
        buffer[..n].to_vec()
    });
    let relay = host_relay(true);
    let connector = RelayDatagramConnector::new(dial(relay));
    let deadline = Instant::now() + Duration::from_secs(30);
    let socket = connector.open("127.0.0.1", port, deadline).unwrap();
    let mut stream = DatagramStream::new(socket, Duration::from_secs(10), deadline);
    stream.write(b"access-request").unwrap();
    assert_eq!(stream.read_until(&[], 1024).unwrap(), b"accept");
    assert_eq!(stream.read_until(&[], 1024).unwrap(), b"second");
    assert_eq!(answer.join().unwrap(), b"access-request");
}

#[test]
fn the_host_refuses_a_destination_it_does_not_allow() {
    let relay = host_relay(false);
    let connector = RelayDatagramConnector::new(dial(relay));
    let deadline = Instant::now() + Duration::from_secs(30);
    let error = connector
        .open("radius.example.com", 1812, deadline)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
}
