// Summarizing NAT insights
//
// v1: track (src_port, dst_addr, dst_port)
// or any form of stateful NAT for that matter
//
// 1. tracking and assigning ports is a headache
// 2. does not easily scale to many threads and I want to avoid tokio/async if possible
// 3. there should be a fast path
//
// Host does not have any real services running on it
// Therefore, we have a lot of latitude in port assignment
//
// Let us direct map some port ranges directly to skip lookups
// 80, 443, 1024-61439 of enclave -> 80, 443, 1024-61439 of host
//
// Connections to and from the enclave now work directly
// More importantly, we do not need a stateful NAT!
// This means no lookups affecting performance
// This also means the NAT can easily be multi threaded without needing locks
//
// On the enclave, we set ephemeral ports to stay within the same range
// It seems to already be the case in my local system, the max is 60999
//
// Only downside - some ports need to be reserved for the host to use
// 61440-65535 is available for that
// This means the enclave cannot use these ports to reach the internet
// While this should not be an issue in most cases since ephemeral ports do not extend there
// and most applications use ports lower than ephemeral, it _is_ a breaking change

// for incoming packets, we need to _intercept_ them and not just get a copy
// raw sockets do the latter, therefore we go with iptables and nfqueue
// iptables can be used to redirect packets to a nfqueue
// we read it here, do NAT and forward onwards

use std::ffi::CStr;
use std::io::Read;
use std::net::SocketAddrV4;
use std::net::Ipv4Addr; 
use anyhow::{anyhow, Context};
use clap::Parser;
use libc::{freeifaddrs, getifaddrs, ifaddrs, strncmp};
use socket2::{SockAddr, Socket};

use oyster_raw_proxy::{
    accept_vsock_conn_with_backoff, new_ip_socket_with_backoff, new_vsock_server_with_backoff,
    ProxyError, SocketError, VsockAddrParser,
};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// vsock address to listen on <cid:port>
    #[clap(short, long, value_parser = VsockAddrParser{})]
    vsock_addr: SockAddr,
}

fn get_eth_interface() -> anyhow::Result<(String, u32)> {
    let mut ifap: *mut ifaddrs = std::ptr::null_mut();
    let res = unsafe { getifaddrs(&mut ifap) };

    if res < 0 {
        return Err(anyhow!("failed to query interfaces"));
    }

    let mut ifap_iter = ifap;
    let mut ifname = "".to_owned();
    let mut ifaddr = 0;
    while !ifap_iter.is_null() {
        let name = unsafe { CStr::from_ptr((*ifap_iter).ifa_name) };
        if (unsafe { strncmp(name.as_ptr(), "eth".as_ptr().cast(), 3) } == 0
            || unsafe { strncmp(name.as_ptr(), "ens".as_ptr().cast(), 3) } == 0)
            && unsafe { (*(*ifap_iter).ifa_addr).sa_family == libc::AF_INET as u16 }
        {
            ifname = name.to_str().context("non utf8 interface")?.to_owned();
            ifaddr = unsafe {
                (*(*ifap_iter).ifa_addr.cast::<libc::sockaddr_in>())
                    .sin_addr
                    .s_addr
            };
            break;
        }
        ifap_iter = unsafe { (*ifap_iter).ifa_next };
    }

    unsafe { freeifaddrs(ifap) };

    if ifname == "" {
        Err(anyhow!("no matching interface found"))
    } else {
        Ok((ifname, ifaddr))
    }
}

fn handle_conn(
    conn_socket: &mut Socket,
    ip_socket: &mut Socket,
    ifaddr: u32,
) -> Result<(), ProxyError> {
    let mut buf = vec![0u8; 65535].into_boxed_slice();
    println!("New connection");
    // does not matter what the address is, just has to be a publicly routed address
    let external_addr: SockAddr = "1.1.1.1:80".parse::<SocketAddrV4>().unwrap().into();

    loop {
        // read till total size
        conn_socket
            .read_exact(&mut buf[0..4])
            .map_err(SocketError::ReadError)
            .map_err(ProxyError::VsockError)?;

        let size: usize = u16::from_be_bytes(buf[2..4].try_into().unwrap()).into();

        // read till full frame
        conn_socket
            .read_exact(&mut buf[4..size])
            .map_err(SocketError::ReadError)
            .map_err(ProxyError::VsockError)?;

        // IMPORTANT: checks are needed here, assume packets from the enclave to be untrusted

        // get src and dst addr
        let src_addr = u32::from_ne_bytes(buf[12..16].try_into().unwrap());
        let src_addr_read = Ipv4Addr::from(src_addr);
        println!("\n--------------------------------------------------------------");
        println!("src_addr {:#?}",src_addr_read);
        let dst_addr = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        let dst_addr_read = Ipv4Addr::from(dst_addr);
        println!("dst_addr {:#?}",dst_addr_read);
        // ignore packets not originating from the interface address
        if src_addr != ifaddr {
            continue;
        }

        // https://en.wikipedia.org/wiki/Reserved_IP_addresses
        // ignore packets sent to
        // 0.0.0.0/8
        if (dst_addr & 0xff000000) == 0x00000000 ||
            // 10.0.0.0/8
            (dst_addr & 0xff000000) == 0x0a000000 ||
            // 100.64.0.0/10
            (dst_addr & 0xffc00000) == 0x64400000 ||
            // 127.0.0.0/8
            (dst_addr & 0xff000000) == 0x7f000000 ||
            // 169.254.0.0/16
            (dst_addr & 0xffff0000) == 0xa9fe0000 ||
            // 172.16.0.0/12
            (dst_addr & 0xfff00000) == 0xac100000 ||
            // 192.0.0.0/24
            (dst_addr & 0xffffff00) == 0xc0000000 ||
            // 192.0.2.0/24
            (dst_addr & 0xffffff00) == 0xc0000200 ||
            // 192.88.99.0/24
            (dst_addr & 0xffffff00) == 0xc0586300 ||
            // 192.168.0.0/16
            (dst_addr & 0xffff0000) == 0xc0a80000 ||
            // 198.18.0.0/15
            (dst_addr & 0xfffe0000) == 0xc6120000 ||
            // 198.51.100.0/24
            (dst_addr & 0xffffff00) == 0xc6336400 ||
            // 203.0.113.0/24
            (dst_addr & 0xffffff00) == 0xcb007100 ||
            // 224.0.0.0/4
            (dst_addr & 0xf0000000) == 0xe0000000 ||
            // 233.252.0.0/24
            (dst_addr & 0xffffff00) == 0xe9fc0000 ||
            // 240.0.0.0/4
            (dst_addr & 0xf0000000) == 0xf0000000 ||
            // 255.255.255.255/32
            (dst_addr & 0xffffffff) == 0xffffffff
        {
            continue;
        }

        let ip_header_size = usize::from((buf[0] & 0x0f) * 4);
        let src_port =
            u16::from_be_bytes(buf[ip_header_size..ip_header_size + 2].try_into().unwrap());
        println!("src_port {:#}",src_port);

        if src_port != 80 && src_port != 443 && (src_port < 1024 || src_port > 61439) {
            // silently drop
            continue;
        }

        // send
        let mut total_sent = 0;
        while total_sent < size {
            let size = ip_socket
                .send_to(&buf[total_sent..size], &external_addr)
                .map_err(SocketError::WriteError)
                .map_err(ProxyError::NfqError)?;
            total_sent += size;
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // get ethernet interface
    let (ifname, ifaddr) = get_eth_interface().context("could not get ethernet interface")?;
    println!("detected ethernet interface: {}, {:#10x}", ifname, ifaddr);

    // set up ip socket for outgoing packets
    let mut ip_socket = new_ip_socket_with_backoff(&ifname);

    // set up outgoing vsock socket for outgoing packets
    let vsock_addr = &cli.vsock_addr;
    let vsock_socket = new_vsock_server_with_backoff(vsock_addr);

    // get conn socket
    let mut conn_socket = accept_vsock_conn_with_backoff((vsock_addr, &vsock_socket));

    loop {
        // do proxying
        // on errors, simply reset the erroring socket
        match handle_conn(&mut conn_socket, &mut ip_socket, ifaddr) {
            Ok(_) => {
                // should never happen!
                unreachable!("connection handler exited without error");
            }
            Err(err @ ProxyError::IpError(_)) => {
                println!("{:?}", anyhow::Error::from(err));

                // get ip socket
                ip_socket = new_ip_socket_with_backoff(&ifname);
            }
            Err(err @ ProxyError::VsockError(_)) => {
                println!("{:?}", anyhow::Error::from(err));

                // get conn socket
                conn_socket = accept_vsock_conn_with_backoff((vsock_addr, &vsock_socket));
            }
            Err(err) => {
                // should never happen!
                unreachable!("connection handler exited with unknown error {err:?}");
            }
        }
    }
}
