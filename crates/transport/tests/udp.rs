//! Datagrams of `udp` operations against local UDP servers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use engine::Error;
use engine::egress::{Arrived, Stream, Transport};
use engine::error::TransportKind;
use engine::policy::Destination;
use transport::TlsTransport;
use transport::udp::{DatagramConnector, DatagramStream, UdpConnector};

fn server() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    (socket, address)
}

fn connector(address: SocketAddr) -> UdpConnector {
    UdpConnector::with_resolver(move |_, _| Ok(vec![address]))
}

fn stream(address: SocketAddr, wait: Duration) -> DatagramStream {
    let deadline = Instant::now() + Duration::from_secs(30);
    let socket = connector(address)
        .open("radius.test", 1812, deadline)
        .unwrap();
    DatagramStream::new(socket, wait, deadline)
}

#[test]
fn a_datagram_is_answered_by_one_datagram() {
    let (server, address) = server();
    let answer = thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        let (n, from) = server.recv_from(&mut buffer).unwrap();
        server.send_to(b"accept", from).unwrap();
        buffer[..n].to_vec()
    });
    let mut transport = TlsTransport::new().datagrams(connector(address));
    let mut stream = transport
        .open_datagrams(&Destination::new("radius.test", 1812))
        .unwrap();
    stream.write(b"access-request").unwrap();
    assert_eq!(stream.read_until(&[], 1024).unwrap(), b"accept");
    assert_eq!(answer.join().unwrap(), b"access-request");
    // Delimiters do not apply to datagrams.
    assert_eq!(
        stream.read_until(&[b"\n"], 1024),
        Err(Error::transport(TransportKind::Unsupported, true))
    );
}

#[test]
fn a_lost_datagram_is_sent_again() {
    let (server, address) = server();
    let answer = thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        // The first copy is lost.
        let (_, _) = server.recv_from(&mut buffer).unwrap();
        let (n, from) = server.recv_from(&mut buffer).unwrap();
        server.send_to(b"accept", from).unwrap();
        buffer[..n].to_vec()
    });
    let mut stream = stream(address, Duration::from_secs(10));
    let start = Instant::now();
    stream.write(b"request").unwrap();
    assert_eq!(stream.read_until(&[], 1024).unwrap(), b"accept");
    assert_eq!(answer.join().unwrap(), b"request");
    // Sent again after the first wait of one second.
    assert!(start.elapsed() >= Duration::from_millis(900));
}

#[test]
fn datagrams_from_another_address_are_dropped() {
    let (server, address) = server();
    let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
    let answer = thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        let (_, from) = server.recv_from(&mut buffer).unwrap();
        // Someone else answers first, to the client's address and port.
        stranger.send_to(b"forged", from).unwrap();
        thread::sleep(Duration::from_millis(100));
        server.send_to(b"accept", from).unwrap();
    });
    let mut stream = stream(address, Duration::from_secs(10));
    stream.write(b"request").unwrap();
    assert_eq!(stream.read_until(&[], 1024).unwrap(), b"accept");
    answer.join().unwrap();
}

#[test]
fn a_silent_destination_times_out() {
    let (_server, address) = server();
    let mut stream = stream(address, Duration::from_millis(300));
    stream.write(b"request").unwrap();
    assert_eq!(
        stream.read_until(&[], 1024),
        Err(Error::transport(TransportKind::Timeout, true))
    );
    assert!(matches!(
        stream.read_some(1024, Duration::from_millis(50)),
        Ok(Arrived::Nothing)
    ));
}

#[test]
fn a_datagram_has_a_size() {
    let (server, address) = server();
    let mut stream = stream(address, Duration::from_secs(10));
    assert_eq!(
        stream.write(&[]),
        Err(Error::transport(TransportKind::TooLarge, true))
    );
    assert_eq!(
        stream.write(&vec![0u8; transport::udp::MAX_DATAGRAM + 1]),
        Err(Error::transport(TransportKind::TooLarge, true))
    );
    // An answer longer than the reader takes is refused.
    let answer = thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        let (_, from) = server.recv_from(&mut buffer).unwrap();
        server.send_to(&[7u8; 100], from).unwrap();
    });
    stream.write(b"request").unwrap();
    assert_eq!(
        stream.read_until(&[], 50),
        Err(Error::transport(TransportKind::TooLarge, true))
    );
    answer.join().unwrap();
}
