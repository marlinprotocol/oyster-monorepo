use std::ffi::OsStr;
use std::pin::Pin;
use std::task::{ready, Poll};

use clap::{builder::TypedValueParser, error::ErrorKind, Arg, Command};
use hyper::server::accept::Accept;
use tokio_vsock::{VsockListener, VsockStream};

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

pub struct VsockServer {
    pub listener: VsockListener, // TODO make the field private
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
