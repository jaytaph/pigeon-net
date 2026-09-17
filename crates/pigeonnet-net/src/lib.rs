//! Transports. The only crate in the workspace that depends on tokio.
//!
//! Its entire job is to move encoded frames. Every decision about what to ask
//! for, what to accept and when to stop lives in `pigeonnet-proto`, which has no
//! idea a socket exists (§3.6, §34.1) — so swapping TCP for QUIC, Tor or a
//! serial link changes nothing above this line.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use pigeonnet_proto::{Input, Limits, Message, Output, ProtocolError, Replica, Session};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// Transport errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum NetError {
    /// The socket failed.
    Io(std::io::Error),
    /// The peer broke the protocol.
    Protocol(ProtocolError),
    /// The peer hung up mid-session.
    Disconnected,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Protocol(e) => write!(f, "{e}"),
            Self::Disconnected => f.write_str("peer disconnected mid-session"),
        }
    }
}

impl core::error::Error for NetError {}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ProtocolError> for NetError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

/// Length-prefixed framing: four bytes big-endian, then a canonical CBOR frame.
#[derive(Debug)]
pub struct Framed<S> {
    stream: S,
    limits: Limits,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Framed<S> {
    /// Wrap a stream.
    pub const fn new(stream: S, limits: Limits) -> Self {
        Self { stream, limits }
    }

    /// Read one frame.
    ///
    /// The declared length is checked *before* allocating, so a peer cannot make
    /// us reserve a gigabyte by claiming it is about to send one (§30.1).
    pub async fn read_frame(&mut self) -> Result<Message, NetError> {
        let mut header = [0u8; 4];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(NetError::Disconnected);
            }
            Err(e) => return Err(e.into()),
        }

        let length = u32::from_be_bytes(header) as usize;
        if length > self.limits.max_frame_bytes {
            return Err(NetError::Protocol(ProtocolError::FrameTooLarge {
                size: length,
                limit: self.limits.max_frame_bytes,
            }));
        }

        let mut body = vec![0u8; length];
        self.stream.read_exact(&mut body).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                NetError::Disconnected
            } else {
                NetError::Io(e)
            }
        })?;
        Ok(Message::decode(&body, &self.limits)?)
    }

    /// Write one frame.
    pub async fn write_frame(&mut self, message: &Message) -> Result<(), NetError> {
        let body = message.encode()?;
        let length = u32::try_from(body.len()).map_err(|_| {
            NetError::Protocol(ProtocolError::FrameTooLarge {
                size: body.len(),
                limit: self.limits.max_frame_bytes,
            })
        })?;
        self.stream.write_all(&length.to_be_bytes()).await?;
        self.stream.write_all(&body).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

/// Drive a session to completion over a framed stream.
///
/// Returns how many objects were accepted.
pub async fn run_session<S, R>(
    framed: &mut Framed<S>,
    session: &mut Session,
    replica: &mut R,
    initial: Input,
) -> Result<usize, NetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Replica,
{
    Ok(drive(framed, session, replica, initial).await?.accepted)
}

/// What a completed session produced.
#[derive(Debug, Default)]
pub struct SessionOutcome {
    /// Objects validated and stored.
    pub accepted: usize,
    /// An identity snapshot, if this was a resolve. Unverified bytes.
    pub snapshot: Option<Vec<u8>>,
}

/// Drive a session to completion, returning everything it produced.
pub async fn drive<S, R>(
    framed: &mut Framed<S>,
    session: &mut Session,
    replica: &mut R,
    initial: Input,
) -> Result<SessionOutcome, NetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Replica,
{
    let mut outcome = SessionOutcome::default();
    let mut outputs = session.step(replica, initial)?;

    loop {
        let mut finished = false;
        for output in outputs {
            match output {
                Output::Send(message) => framed.write_frame(&message).await?,
                Output::Accepted(_) => outcome.accepted += 1,
                Output::Resolved(_, snapshot) => outcome.snapshot = snapshot,
                Output::Complete => finished = true,
            }
        }
        if finished {
            return Ok(outcome);
        }
        let message = framed.read_frame().await?;
        outputs = session.step(replica, Input::Received(message))?;
    }
}

/// Drive a session that answers rather than calls.
pub async fn serve_session<S, R>(
    framed: &mut Framed<S>,
    session: &mut Session,
    replica: &mut R,
) -> Result<usize, NetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: Replica,
{
    let mut accepted = 0;
    loop {
        let message = match framed.read_frame().await {
            Ok(message) => message,
            // A responder that has finished serving may see the peer close
            // first; that is an orderly end, not a failure.
            Err(NetError::Disconnected) if session.is_complete() => return Ok(accepted),
            Err(e) => return Err(e),
        };
        for output in session.step(replica, Input::Received(message))? {
            match output {
                Output::Send(message) => framed.write_frame(&message).await?,
                Output::Accepted(_) => accepted += 1,
                // A responder never asks, so it never receives an answer.
                Output::Resolved(_, _) => {}
                Output::Complete => return Ok(accepted),
            }
        }
    }
}
