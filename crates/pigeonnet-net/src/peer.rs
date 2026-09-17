//! Talking to configured peers: dialling out, and listening.
//!
//! Everything here is a thin driver. What to ask for, what to accept and when
//! to stop is decided in `pigeonnet-proto`, which has never heard of a socket.

use std::time::Duration;

use pigeonnet_core::NodeId;
use pigeonnet_node::Node;
use pigeonnet_proto::{Input, Limits, ProtocolError, Session};
use tokio::net::{TcpListener, TcpStream};

use crate::{Framed, NetError, serve_session};

/// The port §27 uses in its examples.
pub const DEFAULT_PORT: u16 = 4137;

/// How long a single peer may hold a connection open.
///
/// A node serves one connection at a time, so this is also how long one slow or
/// malicious peer can keep everyone else waiting. Bounded rather than generous.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);

/// What one sync achieved.
#[derive(Clone, Copy, Debug)]
pub struct SyncReport {
    /// Objects accepted from the peer.
    ///
    /// There is deliberately no count of what the peer took from us: a serving
    /// session learns what it was asked for, never what the asker chose to keep.
    /// Reporting a number we cannot know would be worse than reporting none.
    pub accepted: usize,
    /// Whether the reciprocal phase completed, so the peer had its chance to
    /// pull whatever this node holds.
    pub offered: bool,
    /// The identity the peer proved.
    pub peer: Option<NodeId>,
}

/// Sync with one peer, in **both directions**, over one outbound connection.
///
/// Two phases on the same socket: this node pulls, then serves while the peer
/// pulls. Roles swap; nothing new is added to the protocol.
///
/// The second phase is what makes a node behind a firewall a participant rather
/// than a reader. §3.5 treats an outbound-only node as normal and D13 arranges
/// for a carrier to spool its mail — but neither helps if the only way its own
/// posts can leave is for somebody to dial in. One outbound connection has to
/// carry traffic both ways, or a leaf can read the network and never contribute
/// to it.
///
/// `expect` is the identity previously pinned to this address, if any. When it
/// is supplied the handshake fails unless the peer proves it — a wrong address
/// then yields no conversation rather than a conversation with a stranger.
pub async fn sync_peer(
    node: &Node,
    local: NodeId,
    address: &str,
    expect: Option<NodeId>,
    limits: Limits,
    now: i64,
) -> Result<SyncReport, NetError> {
    let socket = tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| NetError::Disconnected)??;
    let mut framed = Framed::new(socket, limits);

    let mut session = Session::initiator(local, node.sync_plan()?, limits);
    if let Some(expect) = expect {
        session = session.expecting(expect);
    }

    let mut replica = node.replication(now);
    let accepted = tokio::time::timeout(
        CONNECTION_TIMEOUT,
        crate::run_session(&mut framed, &mut session, &mut replica, Input::Start),
    )
    .await
    .map_err(|_| NetError::Disconnected)??;
    let peer = session.peer();

    // Phase two: let them pull from us, on the same connection. Roles swap and
    // nothing new is added to the protocol.
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce)
        .map_err(|_| NetError::Io(std::io::Error::other("no entropy available")))?;
    let mut serving = Session::responder(local, limits, nonce);
    let mut replica = node.replication(now);
    tokio::time::timeout(
        CONNECTION_TIMEOUT,
        serve_session(&mut framed, &mut serving, &mut replica),
    )
    .await
    .map_err(|_| NetError::Disconnected)??;

    Ok(SyncReport {
        accepted,
        offered: true,
        peer,
    })
}

/// Serve peers until the process is stopped.
///
/// One connection at a time, deliberately. A node holds a SQLite connection,
/// which is not `Sync`, and a home node on a domestic line has no business
/// fanning out anyway — §15.4 is explicit that a node is never obliged to
/// answer. Concurrency here would be a change of posture, not an optimisation.
///
/// A failing connection is logged and dropped. One hostile peer must not be able
/// to stop the server.
pub async fn serve<F>(
    node: &Node,
    local: NodeId,
    listener: &TcpListener,
    limits: Limits,
    reciprocate: bool,
    mut clock: F,
) -> Result<(), NetError>
where
    F: FnMut() -> i64,
{
    loop {
        let (socket, from) = listener.accept().await?;

        // A fresh challenge per connection. Reusing one would make a captured
        // inbox proof replayable (§15.4).
        let mut nonce = [0u8; 32];
        if getrandom::fill(&mut nonce).is_err() {
            return Err(NetError::Io(std::io::Error::other("no entropy available")));
        }

        let now = clock();
        let mut framed = Framed::new(socket, limits);
        let mut session = Session::responder(local, limits, nonce);
        let mut replica = node.replication(now);

        let served = tokio::time::timeout(
            CONNECTION_TIMEOUT,
            serve_session(&mut framed, &mut session, &mut replica),
        )
        .await;

        match served {
            Ok(Ok(offered)) => {
                // Second phase: pull from whoever just called, on the same
                // connection. This is how a node that cannot accept inbound
                // connections gets its own objects out (§3.5).
                //
                // A node is never obliged (§15.4), so an operator who wants to
                // serve and not collect can turn this off. Objects arriving this
                // way are validated exactly as any others and bounded by the
                // same quotas — but they do arrive from whoever dialled, which
                // is the public-echo exposure §37.2 already describes.
                let accepted = if reciprocate {
                    let mut pulling =
                        Session::initiator(local, node.sync_plan().unwrap_or_default(), limits);
                    let mut replica = node.replication(now);
                    match tokio::time::timeout(
                        CONNECTION_TIMEOUT,
                        crate::run_session(&mut framed, &mut pulling, &mut replica, Input::Start),
                    )
                    .await
                    {
                        Ok(Ok(count)) => count,
                        Ok(Err(error)) => {
                            tracing::debug!(%from, %error, "reciprocal pull failed");
                            0
                        }
                        Err(_) => 0,
                    }
                } else {
                    0
                };
                tracing::info!(%from, offered, accepted, "served peer");
            }
            Ok(Err(NetError::Protocol(ProtocolError::AccessDenied))) => {
                tracing::debug!(%from, "refused a restricted stream");
            }
            Ok(Err(error)) => tracing::warn!(%from, %error, "peer session failed"),
            Err(_) => tracing::warn!(%from, "peer session timed out"),
        }
    }
}
