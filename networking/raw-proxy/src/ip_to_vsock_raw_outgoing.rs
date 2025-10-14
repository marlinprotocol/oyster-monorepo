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

use clap::Parser;
use nfq::{Queue, Verdict};
use socket2::{SockAddr, Socket};

use oyster_raw_proxy::{
    new_nfq_with_backoff, new_vsock_socket_with_backoff, ProxyError, SocketError, VsockAddrParser,
};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// vsock address to forward packets to <cid:port>
    #[clap(short, long, value_parser = VsockAddrParser{})]
    vsock_addr: SockAddr,
    /// nfqueue number of the listener <num>
    #[clap(short, long, value_parser)]
    queue_num: u16,
}

fn handle_conn(conn_socket: &mut Socket, queue: &mut Queue) -> Result<(), ProxyError> {
    loop {
        let mut msg = queue
            .recv()
            .map_err(SocketError::ReadError)
            .map_err(ProxyError::NfqError)?;

        let buf = msg.get_payload_mut();
        let size = buf.len();

        // send through vsock
        let mut total_sent = 0;
        while total_sent < size {
            let size = conn_socket
                .send(&buf[total_sent..size])
                .map_err(SocketError::WriteError)
                .map_err(ProxyError::VsockError)?;
            total_sent += size;
        }

        // verdicts
        msg.set_verdict(Verdict::Drop);
        queue
            .verdict(msg)
            .map_err(|e| SocketError::VerdictError(Verdict::Drop, e))
            .map_err(ProxyError::NfqError)?;
    }
}


fn main() -> anyhow::Result<()> {
    println!("Starting the ip-to-vsock-raw-proxy.....");
    let cli = Cli::parse();

    // nfqueue for incoming packets
    let queue_addr = cli.queue_num;
    let mut queue = new_nfq_with_backoff(queue_addr);

    // get vsock socket
    let vsock_addr = &cli.vsock_addr;
    let mut vsock_socket = new_vsock_socket_with_backoff(vsock_addr);

    loop {
        // do proxying
        // on errors, simply reset the erroring socket
        match handle_conn(&mut vsock_socket, &mut queue) {
            Ok(_) => {
                // should never happen!
                unreachable!("connection handler exited without error");
            }
            Err(err @ ProxyError::NfqError(_)) => {
                println!("{:?}", anyhow::Error::from(err));

                // get nfqueue
                queue = new_nfq_with_backoff(queue_addr);
            }
            Err(err @ ProxyError::VsockError(_)) => {
                println!("{:?}", anyhow::Error::from(err));

                // get vsock socket
                vsock_socket = new_vsock_socket_with_backoff(vsock_addr);
            }
            Err(err) => {
                // should never happen!
                unreachable!("connection handler exited with unknown error {err:?}");
            }
        }
    }
}
