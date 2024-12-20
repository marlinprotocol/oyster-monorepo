use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::{client::connect::{Connected, Connection}, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct VsockStream(tokio_vsock::VsockStream);

impl Connection for VsockStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AsyncRead for VsockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for VsockStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub async fn vsock_connector(dst: Uri) -> Result<VsockStream, std::io::Error> {
    let scheme = dst.scheme().ok_or(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "uri should have a scheme",
    ))?;

    if scheme != "vsock" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "only vsock uris supported",
        ));
    }

    let authority = dst.authority().ok_or(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "uri should have an authority",
    ))?;

    let host = authority.host().parse::<u32>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "uri should have a u32 host",
        )
    })?;
    let port: u32 = authority
        .port_u16()
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "uri should have a u16 port",
        ))?
        .into();

    tokio_vsock::VsockStream::connect(host, port)
        .await
        .map(VsockStream)
}
