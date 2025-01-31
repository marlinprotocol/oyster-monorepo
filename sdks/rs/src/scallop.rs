// Scallop protocol
//
// Broad goals:
// - Transport layer security (the concept not the protocol)
// - Enclave native protocol (no Web PKI)
// - Modern cryptography
//
// Handshake shape and security levels in the user stories are modelled on the Noise protocol specification.
//
// User story 1 - HTTP query against known server:
//
// Server is running inside an enclave.
// Client has authenticated the attestation of the enclave and has the static key.
//
// Client wants to create a secure channel with the server to make a HTTP query.
//
// Client to server requires a security level of 0/5.
// Server to client requires a security level of 2/1.
// NK is the minimum viable handshake.
// With 1RTT client delay and 0.5RTT server delay.
//
// Bonuses:
// - Authentication refresh on expiry
//   - Client can request a new attestation in the first message
//   - Server can send the attestation in the second message
//
// User story 2 - HTTP query against unknown server:
//
// Server is running inside an enclave.
// Client knows the expected PCRs of the server.
//
// Client wants to create a secure channel with the server to make a HTTP query.
//
// Client to server requires a security level of 0/5.
// Server to client requires a security level of 2/1.
// NX is the minimum viable handshake.
// With 1RTT client delay and 0.5RTT server delay.
// With additional handshake payloads
//   - Client requests a new attestation in the first message
//   - Server sends the attestation in the second message
//
// User story 3 - webhook trigger from a known client to a known server:
//
// Client is running inside an enclave.
// Client has the static key of the server.
// Server has previously authenticated the attestation of the client and has the static key.
//
// Client wants to create a secure channel with the server and trigger a webhook.
//
// Client to server requires a security level of 2/5.
// Server to client requires a security level of 2/5.
// KK is the minimum viable handshake.
// With 1 RTT client delay and 0.5RTT server delay.
//
// User story 4 - webhook trigger from a known client to an unknown server:
//
// Client is running inside an enclave.
// Server is running inside an enclave.
// Client knows the expected PCRs of the server.
// Server has previously authenticated the attestation of the client and has the static key.
//
// Client wants to create a secure channel with the server and trigger a webhook.
//
// Client to server requires a security level of 2/5.
// Server to client requires a security level of 2/5.
// KX is the minimum viable handshake.
// With 1 RTT client delay and 0.5RTT server delay.
// With additional handshake payloads
//   - Client requests a new attestation in the first message
//   - Server sends the attestation in the second message
//
// User story 5 - webhook trigger from an unknown client to a known server:
//
// Client is running inside an enclave.
// Client has the static key of the server.
// Server knows the expected PCRs of the client.
//
// Client wants to create a secure channel with the server and trigger a webhook.
//
// Client to server requires a security level of 2/5.
// Server to client requires a security level of 2/5.
// XK is the minimum viable handshake.
// With 1 RTT client delay and 1.5RTT server delay.
// With additional handshake payloads
//   - Server requests a new attestation in the second message
//   - Client sends the attestation in the third message
//
// User story 6 - webhook trigger from an unknown client to an unknown server:
//
// Client is running inside an enclave.
// Server is running inside an enclave.
// Client knows the expected PCRs of the server.
// Server knows the expected PCRs of the client.
//
// Client wants to create a secure channel with the server and trigger a webhook.
//
// Client to server requires a security level of 2/5.
// Server to client requires a security level of 2/5.
// XX is the minimum viable handshake.
// With 1 RTT client delay and 1.5RTT server delay.
// With additional handshake payloads
//   - Client requests a new attestation in the first message
//   - Server sends the attestation in the second message
//   - Server requests a new attestation in the second message
//   - Client sends the attestation in the third message
//
// Attestation efficiency:
//
// How does the server know whether to request a new attestation or not?
// The client sends the static key only in the third message.
//
// Either switch to I* handshakes or incur additional messages and RTT delays.
//
// How does the client know whether to request a new attestation or not?
// The server sends the static key only in the second message.
//
// Nothing can really be done since it is the first message sent by the server.
// TLS always sends certificates to work around this, but this seems very inefficient.
//
// Worst case here is 2 RTT client delay and 1.5 RTT server delay.
//
// Once cached on both sides, 1 RTT client delay and 1.5 RTT server delay.
// (Server still has to wait for the client to request attestation or not)
//
// User story considerations:
// - various handshake shapes
// - various security levels
// - handshake latency
// - handshake efficiency
//   - not having to send attestations unless requested by the other party
//   - (questionable?) not having to send static keys unless requested by the other party
//
// General considerations:
// - Different cipher suites
// - Protocol evolution
//
// Conclusions:
// Pick IX as the Noise Protocol
// - Most flexible and covers wide variety of use cases
// - At the cost of a higher server delay
// - At the cost of a lower security level for handshake messages themselves
// - At the cost of handshake messages being larger
// - But allows the significantly larger attestations to be optional in both directions
//
// Pick NoiseSocket as the negotiation protocol
//
// TODOs:
// - (desirable?) 0RTT
//   - main concern is replay attacks

// TODO: vectored reads/writes

use snow::{Builder, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[derive(Debug, thiserror::Error)]
pub enum ScallopError {
    #[error("failed to init builder")]
    InitFailed(#[source] snow::Error),
    #[error("transport error")]
    TransportError(#[from] tokio::io::Error),
    #[error("noise error")]
    NoiseError(#[from] snow::Error),
    #[error("protocol error")]
    ProtocolError(String),
    #[error("auth error")]
    AuthError(String),
}

#[derive(Debug, PartialEq)]
enum ReadMode {
    Length,
    Body,
    Read,
}

pub type Key = [u8; 32];
#[derive(PartialEq)]
pub enum ContainsResponse<State: PartialEq> {
    // the key was found and is approved
    Approved(State),
    // the key was not found
    NotFound,
    // the key is rejected
    Rejected,
}

pub trait ScallopAuthStore {
    type State: PartialEq;

    // intended as a caching mechanism so attestations do not have to be
    // requested every time, always returning NotFound is valid
    fn contains(&mut self, _key: &Key) -> ContainsResponse<Self::State> {
        ContainsResponse::NotFound
    }
    fn verify(&mut self, attestation: &[u8], key: Key) -> Option<Self::State>;
}

impl<T: ScallopAuthStore> ScallopAuthStore for &mut T {
    type State = T::State;

    fn contains(&mut self, key: &Key) -> ContainsResponse<Self::State> {
        (**self).contains(key)
    }

    fn verify(&mut self, attestation: &[u8], key: Key) -> Option<Self::State> {
        (**self).verify(attestation, key)
    }
}

// to let callers pass in None with empty type
impl ScallopAuthStore for () {
    type State = ();

    fn contains(&mut self, _key: &Key) -> ContainsResponse<Self::State> {
        unimplemented!()
    }

    fn verify(&mut self, _attestation: &[u8], _key: Key) -> Option<Self::State> {
        unimplemented!()
    }
}

// Send bound not ideal
// Investigate both Send and non-Send versions
pub trait ScallopAuther: Send {
    type Error: std::fmt::Debug;
    fn new_auth(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Box<[u8]>, Self::Error>> + Send;
}

impl<T: ScallopAuther> ScallopAuther for &mut T {
    type Error = T::Error;
    async fn new_auth(&mut self) -> Result<Box<[u8]>, T::Error> {
        (**self).new_auth().await
    }
}

// to let callers pass in None with empty type
impl ScallopAuther for () {
    type Error = ();
    // was not able to implement in the impl Future form
    // requires higher MSRV
    async fn new_auth(&mut self) -> Result<Box<[u8]>, ()> {
        unimplemented!();
    }
}

#[derive(Debug)]
pub struct ScallopStream<Stream: AsyncWrite + AsyncRead + Unpin, State = ()> {
    noise: TransportState,
    stream: Stream,

    // read buffer
    rbuf: Box<[u8]>,
    pending: usize,
    mode: ReadMode,
    read_end: usize,
    read_start: usize,

    // write buffer
    wbuf: Box<[u8]>,
    write_start: usize,
    write_end: usize,

    // extra connection state from the AuthStore if any
    pub state: Option<State>,
}

trait Noiser {
    fn read_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, snow::Error>;
    fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, snow::Error>;
}

impl Noiser for snow::HandshakeState {
    fn read_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, snow::Error> {
        self.read_message(payload, message)
    }

    fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, snow::Error> {
        self.write_message(payload, message)
    }
}

impl Noiser for snow::TransportState {
    fn read_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, snow::Error> {
        snow::TransportState::read_message(self, payload, message)
    }

    fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, snow::Error> {
        snow::TransportState::write_message(self, payload, message)
    }
}

async fn noise_read(
    noise: &mut impl Noiser,
    stream: &mut (impl AsyncRead + Unpin),
    src: &mut [u8],
    dst: &mut [u8],
) -> Result<usize, ScallopError> {
    // read noise message length
    let len = stream.read_u16().await? as usize;

    // check if buffer is big enough
    if len > src.len() {
        return Err(ScallopError::ProtocolError("message too big".into()));
    }

    // read handshake message
    stream.read_exact(&mut src[0..len]).await?;

    // handle handshake message
    let len = noise.read_message(&src[0..len], dst)?;

    Ok(len)
}

async fn noise_write(
    noise: &mut impl Noiser,
    stream: &mut (impl AsyncWrite + Unpin),
    src: &[u8],
    dst: &mut [u8],
    // in case dst has data encoded already
    dst_offset: usize,
) -> Result<(), ScallopError> {
    // set noise message
    let len = noise
        .write_message(src, &mut dst[dst_offset + 2..])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // set length
    dst[dst_offset..dst_offset + 2].copy_from_slice(&(len as u16).to_be_bytes());

    // send
    stream.write_all(&dst[0..dst_offset + len + 2]).await?;
    stream.flush().await?;

    Ok(())
}

#[allow(non_snake_case)]
pub async fn new_client_async_Noise_IX_25519_ChaChaPoly_BLAKE2b<
    Base: AsyncWrite + AsyncRead + Unpin,
    AS: ScallopAuthStore,
>(
    mut stream: Base,
    secret: &[u8; 32],
    // will not auth remote if None
    mut auth_store: Option<AS>,
    // will not respond to auth requests if None
    auther: Option<impl ScallopAuther>,
) -> Result<ScallopStream<Base, AS::State>, ScallopError> {
    let mut buf = vec![0u8; 65000].into_boxed_slice();
    let mut noise_buf = vec![0u8; 65000].into_boxed_slice();

    let prologue = b"NoiseSocketInit1\x00\x00";

    let mut noise = Builder::new(
        "Noise_IX_25519_ChaChaPoly_BLAKE2b"
            .parse()
            .map_err(ScallopError::InitFailed)?,
    )
    .local_private_key(secret)
    .prologue(prologue)
    .build_initiator()
    .map_err(ScallopError::InitFailed)?;

    //---- -> e, s start ----//

    // first two bytes are already zero, skip writing negotiation payload

    // encode and send handshake message
    noise_write(&mut noise, &mut stream, &[], &mut buf, 2).await?;

    //---- -> e, s end ----//

    //---- <- e, ee, se, s, es start ----//

    // read negotiation length
    let len = stream.read_u16().await?;

    // length should be zero
    if len != 0 {
        return Err(ScallopError::ProtocolError(
            "non zero second negotiation length".into(),
        ));
    }

    // read and handle handshake message
    let len = noise_read(&mut noise, &mut stream, &mut buf, &mut noise_buf).await?;

    // handshake payload should contain auth request
    if len != 3 || noise_buf[0] != 0 || noise_buf[1] != 1 {
        return Err(ScallopError::ProtocolError(
            "invalid second payload length".into(),
        ));
    }

    // auth request should be 0 or 1
    if noise_buf[2] > 1 {
        return Err(ScallopError::ProtocolError(
            "invalid auth request in second payload".into(),
        ));
    }

    let should_send_auth = noise_buf[2] == 1;

    //---- <- e, ee, se, s, es end ----//

    // check if auth is possible
    if should_send_auth && auther.is_none() {
        // auth requested and no auther available
        // error out
        return Err(ScallopError::ProtocolError(
            "auth requested but no auther available".into(),
        ));
    }

    // safe to unwrap since IX should have key by now
    let remote_static: [u8; 32] = noise.get_remote_static().unwrap().try_into().unwrap();

    let contains = auth_store.as_mut().map(|x| x.contains(&remote_static));
    // error out if key is considered rejected
    if contains == Some(ContainsResponse::Rejected) {
        return Err(ScallopError::ProtocolError(
            "remote static key rejected".into(),
        ));
    }

    // start tracking what state should go in the stream
    // it is expected to be set if contains returns state
    // or verify returns state
    let mut state = None::<AS::State>;

    let should_ask_auth = contains == Some(ContainsResponse::NotFound);

    // set state immediately if key was approved previously
    if let Some(ContainsResponse::Approved(_state)) = contains {
        state = Some(_state);
    }

    // handshake is done, switch to transport mode
    let mut noise = noise.into_transport_mode()?;

    //---- -> CLIENTFIN start ----//
    //
    // not part of the noise protocol, needed for optional attestations
    //
    // first two bytes length
    // 0x00 for no auth request, 0x01 for auth request
    // two bytes payload size
    // payload

    async fn send_CLIENTFIN(
        noise: &mut impl Noiser,
        stream: &mut (impl AsyncWrite + Unpin),
        buf: &mut [u8],
        noise_buf: &mut [u8],
        payload: &[u8],
        should_ask_auth: bool,
    ) -> Result<(), ScallopError> {
        // assemble message for encryption
        noise_buf[0] = if !should_ask_auth { 0 } else { 1 };
        // safe to cast since range has been checked above
        noise_buf[1..3].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        noise_buf[3..3 + payload.len()].copy_from_slice(payload);

        // encode and send handshake message
        noise_write(noise, stream, &noise_buf[0..payload.len() + 3], buf, 0).await?;

        Ok(())
    }

    if should_send_auth {
        // safe to unwrap since it has been checked above
        let payload = auther
            .unwrap()
            .new_auth()
            .await
            .map_err(|e| ScallopError::AuthError(format!("{e:?}")))?;
        // check if payload is not too big
        if payload.len() > 60000 {
            return Err(ScallopError::ProtocolError("auth payload too big".into()));
        }

        send_CLIENTFIN(
            &mut noise,
            &mut stream,
            &mut buf,
            &mut noise_buf,
            &payload,
            should_ask_auth,
        )
        .await?;
    } else {
        send_CLIENTFIN(
            &mut noise,
            &mut stream,
            &mut buf,
            &mut noise_buf,
            &[],
            should_ask_auth,
        )
        .await?;
    }

    //---- -> CLIENTFIN end ----//

    //---- <- SERVERFIN start ----//
    //
    // not part of the noise protocol, needed for optional attestations
    //
    // first two bytes length
    // two bytes payload size
    // payload

    if should_ask_auth {
        // read and handle handshake message
        let len = noise_read(&mut noise, &mut stream, &mut buf, &mut noise_buf).await?;

        // should have at least 2 size
        if len < 2 {
            return Err(ScallopError::ProtocolError(
                "invalid SERVERFIN length".into(),
            ));
        }

        // payload size should match
        if u16::from_be_bytes([noise_buf[0], noise_buf[1]]) as usize != len - 2 {
            return Err(ScallopError::ProtocolError(
                "invalid SERVERFIN payload length".into(),
            ));
        }

        // verify
        let Some(_state) = auth_store
            .as_mut()
            .unwrap()
            .verify(&noise_buf[2..len], remote_static)
        else {
            return Err(ScallopError::ProtocolError("invalid attestation".into()));
        };

        // set state
        state = Some(_state)
    }

    //---- <- SERVERFIN end ----//

    Ok(ScallopStream {
        noise,
        stream,
        // initialize with 2 sized buffer to read length
        rbuf: vec![0u8; 2].into_boxed_slice(),
        pending: 2,
        mode: ReadMode::Length,
        read_start: 0,
        read_end: 0,
        wbuf: vec![].into_boxed_slice(),
        write_start: 0,
        write_end: 0,
        state,
    })
}

#[allow(non_snake_case)]
pub async fn new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b<
    Base: AsyncWrite + AsyncRead + Unpin,
    AS: ScallopAuthStore,
>(
    mut stream: Base,
    secret: &[u8; 32],
    // will not auth remote if None
    mut auth_store: Option<AS>,
    // will not respond to auth requests if None
    auther: Option<impl ScallopAuther>,
) -> Result<ScallopStream<Base, AS::State>, ScallopError> {
    let mut buf = vec![0u8; 65000].into_boxed_slice();
    let mut noise_buf = vec![0u8; 65000].into_boxed_slice();

    let prologue = b"NoiseSocketInit1\x00\x00";

    let mut noise = Builder::new(
        "Noise_IX_25519_ChaChaPoly_BLAKE2b"
            .parse()
            .map_err(ScallopError::InitFailed)?,
    )
    .local_private_key(secret)
    .prologue(prologue)
    .build_responder()
    .map_err(ScallopError::InitFailed)?;

    //---- -> e, s start ----//

    // read negotiation length
    let len = stream.read_u16().await?;

    // length should be zero
    if len != 0 {
        return Err(ScallopError::ProtocolError(
            "non zero first negotiation length".into(),
        ));
    }

    // read and handle handshake message
    let len = noise_read(&mut noise, &mut stream, &mut buf, &mut noise_buf).await?;

    // handshake payload should be empty
    if len != 0 {
        return Err(ScallopError::ProtocolError(
            "non zero first handshake payload".into(),
        ));
    }

    //---- -> e, s end ----//

    //---- <- e, ee, se, s, es start ----//

    // negotiation length
    buf[0..2].copy_from_slice(&0u16.to_be_bytes());

    // request auth if auth_store is available
    // and static key is not found in the auth store
    let remote_static: [u8; 32] = noise
        .get_remote_static()
        .expect("handshake should have static key by now")
        .try_into()
        .expect("expected 32 byte key");

    let contains = auth_store.as_mut().map(|x| x.contains(&remote_static));
    // error out if key is considered rejected
    if contains == Some(ContainsResponse::Rejected) {
        return Err(ScallopError::ProtocolError(
            "remote static key rejected".into(),
        ));
    }

    // start tracking what state should go in the stream
    // it is expected to be set if contains returns state
    // or verify returns state
    let mut state = None::<AS::State>;

    let should_ask_auth = contains == Some(ContainsResponse::NotFound);

    // set state immediately if key was approved previously
    if let Some(ContainsResponse::Approved(_state)) = contains {
        state = Some(_state);
    }

    let payload = &[0u8, 1u8, if !should_ask_auth { 0u8 } else { 1u8 }];

    // encode and send handshake message
    noise_write(&mut noise, &mut stream, payload, &mut buf, 2).await?;

    //---- <- e, ee, se, s, es end ----//

    // handshake is done, switch to transport mode
    let mut noise = noise.into_transport_mode()?;

    //---- -> CLIENTFIN start ----//
    //
    // not part of the noise protocol, needed for optional attestations
    //
    // first two bytes length
    // 0x00 for no auth request, 0x01 for auth request
    // two bytes payload size
    // payload

    // read and handle handshake message
    let len = noise_read(&mut noise, &mut stream, &mut buf, &mut noise_buf).await?;

    // should have at least 3 size
    if len < 3 {
        return Err(ScallopError::ProtocolError(
            "invalid CLIENTFIN length".into(),
        ));
    }

    // payload size should match
    if u16::from_be_bytes([noise_buf[1], noise_buf[2]]) as usize != len - 3 {
        return Err(ScallopError::ProtocolError(
            "invalid CLIENTFIN payload length".into(),
        ));
    }

    // verify auth if we asked for it
    if should_ask_auth {
        // verify
        let Some(_state) = auth_store
            .as_mut()
            .unwrap()
            .verify(&noise_buf[3..len], remote_static)
        else {
            return Err(ScallopError::ProtocolError("invalid attestation".into()));
        };

        // set state
        state = Some(_state)
    }

    // auth request should be 0 or 1
    if noise_buf[0] > 1 {
        return Err(ScallopError::ProtocolError(
            "invalid auth request in third payload".into(),
        ));
    }

    let should_send_auth = noise_buf[0] == 1;

    //---- -> CLIENTFIN end ----//

    // check if auth is possible
    if should_send_auth && auther.is_none() {
        // auth requested and no auther available
        // error out
        return Err(ScallopError::ProtocolError(
            "auth requested but no auther available".into(),
        ));
    }

    //---- <- SERVERFIN start ----//
    //
    // not part of the noise protocol, needed for optional attestations
    //
    // first two bytes length
    // two bytes payload size
    // payload

    if should_send_auth {
        // safe to unwrap since it has been checked above
        let payload = auther
            .unwrap()
            .new_auth()
            .await
            .map_err(|e| ScallopError::AuthError(format!("{e:?}")))?;
        // check if payload is not too big
        if payload.len() > 60000 {
            return Err(ScallopError::ProtocolError("auth payload too big".into()));
        }

        // safe to cast since range has been checked above
        noise_buf[0..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        noise_buf[2..2 + payload.len()].copy_from_slice(&payload);

        // encode and send handshake message
        noise_write(
            &mut noise,
            &mut stream,
            &noise_buf[0..payload.len() + 2],
            &mut buf,
            0,
        )
        .await?;
    }

    //---- <- SERVERFIN end ----//

    Ok(ScallopStream {
        noise,
        stream,
        // initialize with 2 sized buffer to read length
        rbuf: vec![0u8; 2].into_boxed_slice(),
        pending: 2,
        mode: ReadMode::Length,
        read_start: 0,
        read_end: 0,
        wbuf: vec![].into_boxed_slice(),
        write_start: 0,
        write_end: 0,
        state,
    })
}

impl<Base: AsyncWrite + AsyncRead + Unpin, State> ScallopStream<Base, State> {
    pub fn get_remote_static(&self) -> Option<[u8; 32]> {
        self.noise
            .get_remote_static()
            .map(|x| x.try_into().expect("expected 32 byte key"))
    }
}

impl<Base: AsyncWrite + AsyncRead + Unpin, State: Unpin> AsyncRead for ScallopStream<Base, State> {
    // IMPORTANT: Return Pending only as a direct result of base returning Pending
    // Ensures wakers are set up correctly
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let stream = self.get_mut();
        loop {
            while stream.pending != 0 {
                let base = std::pin::pin!(&mut stream.stream);

                // do not have enough data, try to read more
                let len = stream.rbuf.len();
                let mut buf = ReadBuf::new(&mut stream.rbuf[(len - stream.pending)..]);
                std::task::ready!(base.poll_read(cx, &mut buf))?;

                // check eof
                if buf.filled().is_empty() {
                    return std::task::Poll::Ready(Ok(()));
                }
                stream.pending -= buf.filled().len();
            }

            // pending should always be 0 after this point

            if stream.mode == ReadMode::Length {
                // we have read the length

                // parse length
                let record_length = u16::from_be_bytes(stream.rbuf[0..2].try_into().unwrap());

                // set up to read record
                stream.pending = record_length.into();
                stream.mode = ReadMode::Body;
                stream.rbuf = vec![0u8; stream.pending].into_boxed_slice();
            } else if stream.mode == ReadMode::Body {
                // we have the data

                // process as noise message
                let len = stream
                    .noise
                    .read_message(&stream.rbuf.clone(), &mut stream.rbuf)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                // set up to send body upstream
                stream.read_start = 0;
                stream.read_end = len;
                stream.mode = ReadMode::Read;
            } else {
                if buf.remaining() < stream.read_end - stream.read_start {
                    // can transmit only partial
                    let read_start = stream.read_start;
                    stream.read_start += buf.remaining();
                    let read_end = read_start + buf.remaining();
                    buf.put_slice(&stream.rbuf[read_start..read_end]);
                } else {
                    // can transmit full
                    buf.put_slice(&stream.rbuf[stream.read_start..stream.read_end]);

                    stream.rbuf = vec![0u8; 2].into_boxed_slice();
                    stream.pending = 2;
                    stream.mode = ReadMode::Length;
                }
                return std::task::Poll::Ready(Ok(()));
            }
        }
    }
}

impl<Base: AsyncWrite + AsyncRead + Unpin, State: Unpin> AsyncWrite for ScallopStream<Base, State> {
    // IMPORTANT: Return Pending only as a direct result of base returning Pending
    // Ensures wakers are set up correctly
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        // flush existing data first
        std::task::ready!(self.as_mut().poll_flush(cx))?;

        let mut stream = self.as_mut();

        // construct new buf
        // up to 64000 bytes at once
        let len = std::cmp::min(buf.len(), 64000) as u16;
        let mut new_buf = vec![0u8; len as usize + 1000].into_boxed_slice();

        // set noise message
        let noise_len = stream
            .noise
            .write_message(&buf[0..len as usize], &mut new_buf[2..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // set length
        new_buf[0..2].copy_from_slice(&(noise_len as u16).to_be_bytes());

        // queue up new buf
        stream.wbuf = new_buf;
        stream.write_start = 0;
        stream.write_end = noise_len + 2;

        // TODO: Should we flush here so it does not need to be called in the common case?
        // How do we implement this?
        //
        // Not sure how the semantics will play out though.
        //
        // Happy path looks great.
        // We make a call to poll_flush, it returns Ready and we return Ready with length.
        //
        // But what if it returns Pending?
        // If we return Pending, the caller will assume nothing was sent.
        // If we return Ready, polL_flush has potentially set up wakers.
        // What happens on repeated calls? Unsure if it is supposed to be idempotent.

        std::task::Poll::Ready(Ok(len as usize))
    }

    // IMPORTANT: Return Pending only as a direct result of base returning Pending
    // Ensures wakers are set up correctly
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let stream = self.get_mut();

        while stream.write_start != stream.write_end {
            let base = std::pin::pin!(&mut stream.stream);

            // try to send existing messages first
            let size = std::task::ready!(
                base.poll_write(cx, &stream.wbuf[stream.write_start..stream.write_end])
            )?;
            stream.write_start += size;
        }

        // flush data after write since base could be buffered
        let base = std::pin::pin!(&mut stream.stream);
        base.poll_flush(cx)
    }

    // IMPORTANT: Return Pending only as a direct result of base returning Pending
    // Ensures wakers are set up correctly
    //
    // Shutdown is supposed to be graceful
    //
    // From the tokio docs:
    // Invocation of a shutdown implies an invocation of flush.
    // Once this method returns Ready it implies that a flush successfully happened
    // before the shutdown happened. That is, callers don’t need to call flush before
    // calling shutdown. They can rely that by calling shutdown any pending buffered
    // data will be written out.
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        // flush data for graceful shutdowns
        std::task::ready!(self.as_mut().poll_flush(cx))?;

        let stream = self.get_mut();
        let base = std::pin::pin!(&mut stream.stream);

        base.poll_shutdown(cx)
    }
}
