use std::ffi::CStr;
use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{ready, Poll};

use hyper::StatusCode;
use libc::{freeifaddrs, getifaddrs, ifaddrs, strncmp};

use anyhow::Context;

use axum::{routing::get, Router};
use clap::{builder::TypedValueParser, error::ErrorKind, Arg, Command, Parser};
use hyper::server::accept::Accept;
use tokio::fs;
use tokio_vsock::{VsockListener, VsockStream};

struct VsockServer {
    listener: VsockListener,
}

impl Accept for VsockServer {
    type Conn = VsockStream;
    type Error = std::io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let (conn, _addr) = ready!(self.listener.poll_accept(cx))?;
        Poll::Ready(Some(Ok(conn)))
    }
}

#[derive(Clone)]
pub struct VsockAddrParser {}

impl TypedValueParser for VsockAddrParser {
    type Value = (u32, u32);

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

        Ok((cid, port))
    }
}

fn get_eth_interface() -> anyhow::Result<(String, u32)> {
    let mut ifap: *mut ifaddrs = std::ptr::null_mut();
    let res = unsafe { getifaddrs(&mut ifap) };

    if res < 0 {
        return Err(anyhow::anyhow!("failed to query interfaces"));
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

    if ifname.is_empty() {
        Err(anyhow::anyhow!("no matching interface found"))
    } else {
        Ok((ifname, ifaddr.to_be()))
    }
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// vsock address to listen on <cid:port>
    #[clap(short, long, value_parser = VsockAddrParser{})]
    vsock_addr: (u32, u32),
    /// job id served by the enclave
    #[clap(short, long, value_parser)]
    job_id: String,
    /// path to init params file
    #[clap(short, long, value_parser)]
    init_params_path: String,
    /// path to extra init params file
    #[clap(short, long, value_parser)]
    extra_init_params_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    let (_, ip) = get_eth_interface().context("failed to get ethernet ip")?;
    println!("ip: {:#010x}", ip);
    let ip = Ipv4Addr::from(ip).to_string();
    println!("{ip}");

    let app = Router::new()
        .route("/oyster/job", get(|| async { cli.job_id }))
        .route(
            "/oyster/init-params",
            get(|| async {
                fs::read(cli.init_params_path)
                    .await
                    .map(|data| (StatusCode::OK, data))
                    .unwrap_or((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Vec::from(b"could not read init params"),
                    ))
            }),
        )
        .route(
            "/oyster/extra-init-params",
            get(|| async {
                fs::read(cli.extra_init_params_path)
                    .await
                    .map(|data| (StatusCode::OK, data))
                    .unwrap_or((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Vec::from(b"could not read extra init params"),
                    ))
            }),
        )
        .route("/instance/ip", get(|| async { ip }));

    axum::Server::builder(VsockServer {
        listener: VsockListener::bind(cli.vsock_addr.0, cli.vsock_addr.1)
            .context("failed to create vsock listener")?,
    })
    .serve(app.into_make_service())
    .await
    .context("server exited with error")?;

    Ok(())
}
