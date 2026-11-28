use std::ffi::OsStr;
use std::io::Read;
use std::thread::sleep;
use std::time::Duration;

use thiserror::Error;

use clap::{builder::TypedValueParser, error::ErrorKind, Arg, Command};
use nfq::{Queue, Verdict};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("ip socket error")]
    IpError(#[source] SocketError),
    #[error("vsock socket error")]
    VsockError(#[source] SocketError),
    #[error("nfqueue error")]
    NfqError(#[source] SocketError),
}

#[derive(Error, Debug)]
pub enum SocketError {
    #[error(
        "failed to create socket with domain {domain:?}, type {r#type:?}, protocol {protocol:?}"
    )]
    CreateError {
        domain: Domain,
        r#type: Type,
        protocol: Option<Protocol>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to bind socket to {addr}")]
    BindError {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to listen with socket on {addr}")]
    ListenError {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to accept with socket on {addr}")]
    AcceptError {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to connect socket to {addr}")]
    ConnectError {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read from socket")]
    ReadError(#[source] std::io::Error),
    #[error("failed to write to socket")]
    WriteError(#[source] std::io::Error),
    #[error("failed to shutdown {side:?}")]
    ShutdownError {
        side: std::net::Shutdown,
        #[source]
        source: std::io::Error,
    },
    #[error("unexpected eof")]
    EofError,
    #[error("failed to open socket {0}")]
    OpenError(#[source] std::io::Error),
    #[error("failed to set verdict {0:?}")]
    VerdictError(Verdict, #[source] std::io::Error),
    #[error("failed to set option {0}")]
    OptionError(String, #[source] std::io::Error),
}

pub fn run_with_backoff<P: Clone, R, F: Fn(P) -> Result<R, ProxyError>>(
    f: F,
    p: P,
    max_backoff: u64,
) -> R {
    let mut backoff = 1;
    loop {
        match f(p.clone()) {
            Ok(r) => {
                return r;
            }
            Err(err) => {
                println!("{:?}", anyhow::Error::from(err));

                sleep(Duration::from_secs(backoff));
                backoff = (backoff * 2).clamp(1, max_backoff);
            }
        };
    }
}

fn new_nfq(addr: u16) -> Result<Queue, ProxyError> {
    let mut queue = Queue::open()
        .map_err(SocketError::OpenError)
        .map_err(ProxyError::NfqError)?;
    queue
        .bind(addr)
        .map_err(|e| SocketError::BindError {
            addr: addr.to_string(),
            source: e,
        })
        .map_err(ProxyError::NfqError)?;

    Ok(queue)
}

pub fn new_nfq_with_backoff(addr: u16) -> Queue {
    run_with_backoff(new_nfq, addr, 64)
}

fn new_vsock_socket(addr: &SockAddr) -> Result<Socket, ProxyError> {
    let vsock_socket = Socket::new(Domain::VSOCK, Type::STREAM, None)
        .map_err(|e| SocketError::CreateError {
            domain: Domain::VSOCK,
            r#type: Type::STREAM,
            protocol: None,
            source: e,
        })
        .map_err(ProxyError::VsockError)?;
    vsock_socket
        .connect(addr)
        .map_err(|e| SocketError::ConnectError {
            addr: format!("{:?}, {:?}", addr.domain(), addr.as_vsock_address()),
            source: e,
        })
        .map_err(ProxyError::VsockError)?;
    vsock_socket
        .shutdown(std::net::Shutdown::Read)
        .map_err(|e| SocketError::ShutdownError {
            side: std::net::Shutdown::Read,
            source: e,
        })
        .map_err(ProxyError::VsockError)?;

    Ok(vsock_socket)
}

pub fn new_vsock_socket_with_backoff(addr: &SockAddr) -> Socket {
    run_with_backoff(new_vsock_socket, addr, 4)
}

fn new_vsock_server(addr: &SockAddr) -> Result<Socket, ProxyError> {
    let vsock_socket = Socket::new(Domain::VSOCK, Type::STREAM, None)
        .map_err(|e| SocketError::CreateError {
            domain: Domain::VSOCK,
            r#type: Type::STREAM,
            protocol: None,
            source: e,
        })
        .map_err(ProxyError::VsockError)?;
    vsock_socket
        .bind(addr)
        .map_err(|e| SocketError::BindError {
            addr: format!("{:?}, {:?}", addr.domain(), addr.as_vsock_address()),
            source: e,
        })
        .map_err(ProxyError::VsockError)?;
    vsock_socket
        .listen(0)
        .map_err(|e| SocketError::ListenError {
            addr: format!("{:?}, {:?}", addr.domain(), addr.as_vsock_address()),
            source: e,
        })
        .map_err(ProxyError::VsockError)?;

    Ok(vsock_socket)
}

pub fn new_vsock_server_with_backoff(addr: &SockAddr) -> Socket {
    run_with_backoff(new_vsock_server, addr, 64)
}

fn accept_vsock_conn(params: (&SockAddr, &Socket)) -> Result<Socket, ProxyError> {
    let (addr, vsock_socket) = params;
    let (conn_socket, _) = vsock_socket
        .accept()
        .map_err(|e| SocketError::AcceptError {
            addr: format!("{:?}, {:?}", addr.domain(), addr.as_vsock_address()),
            source: e,
        })
        .map_err(ProxyError::VsockError)?;
    conn_socket
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| SocketError::ShutdownError {
            side: std::net::Shutdown::Write,
            source: e,
        })
        .map_err(ProxyError::VsockError)?;

    Ok(conn_socket)
}

pub fn accept_vsock_conn_with_backoff(params: (&SockAddr, &Socket)) -> Socket {
    run_with_backoff(accept_vsock_conn, params, 64)
}

fn new_ip_socket(device: &str) -> Result<Socket, ProxyError> {
    let ip_socket = Socket::new(Domain::IPV4, Type::RAW, Protocol::TCP.into())
        .map_err(|e| SocketError::CreateError {
            domain: Domain::IPV4,
            r#type: Type::RAW,
            protocol: Protocol::TCP.into(),
            source: e,
        })
        .map_err(ProxyError::IpError)?;
    ip_socket
        .bind_device(device.as_bytes().into())
        .map_err(|e| SocketError::BindError {
            addr: device.to_owned(),
            source: e,
        })
        .map_err(ProxyError::IpError)?;
    ip_socket
        .set_header_included(true)
        .map_err(|e| SocketError::OptionError("IP_HDRINCL".to_owned(), e))
        .map_err(ProxyError::IpError)?;
    // shutdown does not work since socket is not connected, set buffer size to 0 instead
    ip_socket
        .set_recv_buffer_size(0)
        .map_err(|e| SocketError::ShutdownError {
            side: std::net::Shutdown::Read,
            source: e,
        })
        .map_err(ProxyError::IpError)?;

    Ok(ip_socket)
}

pub fn new_ip_socket_with_backoff(device: &str) -> Socket {
    run_with_backoff(new_ip_socket, device, 64)
}

#[derive(Clone)]
pub struct VsockAddrParser {}

impl TypedValueParser for VsockAddrParser {
    type Value = SockAddr;

    fn parse_ref(
        &self,
        cmd: &Command,
        _: Option<&Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value
            .to_str()
            .ok_or(clap::Error::new(ErrorKind::InvalidUtf8).with_cmd(cmd))?;

        let (cid, port) = value
            .split_once(':')
            .ok_or(clap::Error::new(ErrorKind::ValueValidation).with_cmd(cmd))?;

        let cid = cid
            .parse::<u32>()
            .map_err(|_| clap::Error::new(ErrorKind::ValueValidation).with_cmd(cmd))?;
        let port = port
            .parse::<u32>()
            .map_err(|_| clap::Error::new(ErrorKind::ValueValidation).with_cmd(cmd))?;

        Ok(SockAddr::vsock(cid, port))
    }
}

// smallest ip header, without options
const MIN_IP_PACKET_SIZE: usize = 20;

/// Reads one ip packet from the stream into the start of buf and returns its size.
///
/// The other side of the stream is not trusted. A total length smaller than an ip header
/// is not a packet and it means the stream cannot be followed anymore,
/// it is returned as a read error so the caller resets the connection.
pub fn read_ip_packet(conn: &mut impl Read, buf: &mut [u8]) -> Result<usize, SocketError> {
    // read till total size
    conn.read_exact(&mut buf[0..4])
        .map_err(SocketError::ReadError)?;

    let size: usize = u16::from_be_bytes(buf[2..4].try_into().unwrap()).into();

    if size < MIN_IP_PACKET_SIZE || size > buf.len() {
        return Err(SocketError::ReadError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid ip packet size {size}"),
        )));
    }

    // read till full frame
    conn.read_exact(&mut buf[4..size])
        .map_err(SocketError::ReadError)?;

    Ok(size)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn packet(size: u16, len: usize) -> Vec<u8> {
        let mut packet = vec![0xabu8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&size.to_be_bytes());
        packet
    }

    #[test]
    fn reads_packets_one_after_the_other() {
        let mut stream = packet(20, 20);
        stream.extend(packet(60, 60));
        let mut conn = Cursor::new(stream);
        let mut buf = vec![0u8; 65535];

        assert_eq!(read_ip_packet(&mut conn, &mut buf).unwrap(), 20);
        assert_eq!(buf[..20], packet(20, 20));
        assert_eq!(read_ip_packet(&mut conn, &mut buf).unwrap(), 60);
        assert_eq!(buf[..60], packet(60, 60));
        assert!(read_ip_packet(&mut conn, &mut buf).is_err());
    }

    #[test]
    fn reads_the_largest_packet() {
        let mut conn = Cursor::new(packet(65535, 65535));
        let mut buf = vec![0u8; 65535];

        assert_eq!(read_ip_packet(&mut conn, &mut buf).unwrap(), 65535);
    }

    #[test]
    fn short_sizes_are_errors() {
        for size in [0, 1, 3, 4, 19] {
            let mut conn = Cursor::new(packet(size, 64));
            let mut buf = vec![0u8; 65535];

            let err = read_ip_packet(&mut conn, &mut buf).unwrap_err();

            assert!(
                matches!(err, SocketError::ReadError(ref e) if e.kind() == std::io::ErrorKind::InvalidData),
                "{size}: {err:?}"
            );
        }
    }

    #[test]
    fn truncated_packets_are_errors() {
        let mut conn = Cursor::new(packet(40, 30));
        let mut buf = vec![0u8; 65535];

        assert!(read_ip_packet(&mut conn, &mut buf).is_err());
    }

    #[test]
    fn packets_bigger_than_the_buffer_are_errors() {
        let mut conn = Cursor::new(packet(100, 100));
        let mut buf = vec![0u8; 64];

        assert!(read_ip_packet(&mut conn, &mut buf).is_err());
    }
}
