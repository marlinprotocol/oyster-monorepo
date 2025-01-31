use std::net::SocketAddr;

use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use tokio::net::{TcpListener, TcpStream};

use crate::scallop::{
    new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b, ScallopAuthStore, ScallopAuther,
    ScallopError, ScallopStream,
};

#[derive(Debug, thiserror::Error)]
pub enum AxumError {
    #[error("failed to accept conns")]
    AcceptError(#[from] tokio::io::Error),
    #[error("failed to scallop")]
    ScallopError(#[from] ScallopError),
}

pub struct ScallopListener<AuthStore, Auther> {
    pub listener: TcpListener,
    pub secret: [u8; 32],
    pub auth_store: AuthStore,
    pub auther: Auther,
}

impl<AuthStore, Auther> ScallopListener<AuthStore, Auther>
where
    AuthStore: ScallopAuthStore + Clone + Send + 'static,
    AuthStore::State: Send + Unpin,
    Auther: ScallopAuther + Clone + 'static,
{
    async fn accept_impl(
        &mut self,
    ) -> Result<(<Self as Listener>::Io, <Self as Listener>::Addr), AxumError> {
        let (stream, addr) = self.listener.accept().await?;
        let stream = new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b(
            stream,
            &self.secret,
            Some(self.auth_store.clone()),
            Some(self.auther.clone()),
        )
        .await?;

        Ok((stream, addr))
    }
}

impl<AuthStore, Auther> Listener for ScallopListener<AuthStore, Auther>
where
    AuthStore: ScallopAuthStore + Clone + Send + 'static,
    AuthStore::State: Send + Unpin,
    Auther: ScallopAuther + Clone + 'static,
{
    type Io = ScallopStream<TcpStream, <AuthStore as ScallopAuthStore>::State>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let res = self.accept_impl().await;
            match res {
                Ok(res) => return res,
                Err(_) => continue, // nothing, maybe log?
            }
        }
    }

    fn local_addr(&self) -> tokio::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

#[derive(Clone)]
pub struct ScallopState<State>(pub Option<State>);

impl<AuthStore, Auther> Connected<IncomingStream<'_, ScallopListener<AuthStore, Auther>>>
    for ScallopState<AuthStore::State>
where
    AuthStore: ScallopAuthStore + Clone + Send + 'static,
    AuthStore::State: Clone + Send + Sync + Unpin,
    Auther: ScallopAuther + Clone + 'static,
{
    fn connect_info(stream: IncomingStream<'_, ScallopListener<AuthStore, Auther>>) -> Self {
        // is it possible to avoid a clone here?
        ScallopState(stream.io().state.clone())
    }
}
