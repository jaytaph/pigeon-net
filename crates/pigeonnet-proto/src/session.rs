//! The replication session: a sans-io state machine.
//!
//! `step(replica, input) -> outputs`. No sockets, no clock, no runtime. The
//! transport's only job is to move encoded frames; every decision about what to
//! ask for, what to accept and when to stop happens here, where it can be driven
//! by a scripted hostile peer without opening a port.
//!
//! The sync itself is the journal-cursor exchange of D5:
//!
//! ```text
//! A -> B   Want  { stream, after: cursor }
//! B -> A   Have  { entries, more }
//! A -> B   Fetch { the entries A lacks }
//! B -> A   Deliver { bytes }
//! A        cursor := highest position in the batch
//! ```
//!
//! Cost is proportional to what is new, not to what is already known.

use std::collections::{BTreeSet, VecDeque};

use pigeonnet_core::{IdentityId, NodeId, Object, ObjectId};

use crate::{
    ProtocolError,
    limits::Limits,
    message::{
        Access, Features, JournalEntry, Message, PROTOCOL_VERSION, StreamId, inbox_auth_transcript,
    },
    replica::{AcceptError, InboxSigner, Replica},
};

/// Which side of a session this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Opens the connection and drives the sync.
    Initiator,
    /// Answers.
    Responder,
}

/// What the host feeds the session.
#[derive(Clone, Debug)]
pub enum Input {
    /// Begin. Initiator only.
    Start,
    /// A frame arrived.
    Received(Message),
}

/// What the session asks the host to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Put this frame on the wire.
    Send(Message),
    /// An object was validated and stored.
    Accepted(ObjectId),
    /// A resolve answered. `None` means the peer does not hold that identity.
    ///
    /// The bytes are unverified: a snapshot is self-signed throughout, so the
    /// caller verifies it and this layer does not pretend to.
    Resolved(IdentityId, Option<Vec<u8>>),
    /// The session finished cleanly.
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    New,
    AwaitingHello,
    AwaitingHelloAck,
    AwaitingHave,
    AwaitingDeliver,
    AwaitingResolved,
    Serving,
    Done,
    Failed,
}

impl State {
    const fn name(self) -> &'static str {
        match self {
            Self::New => "starting",
            Self::AwaitingHello => "awaiting Hello",
            Self::AwaitingHelloAck => "awaiting HelloAck",
            Self::AwaitingHave => "awaiting Have",
            Self::AwaitingDeliver => "awaiting Deliver",
            Self::AwaitingResolved => "awaiting Resolved",
            Self::Serving => "serving",
            Self::Done => "finished",
            Self::Failed => "failed",
        }
    }
}

/// Progress through one stream.
#[derive(Clone, Debug)]
struct StreamProgress {
    stream: StreamId,
    /// Where our cursor stands now.
    cursor: u64,
    /// Highest position in the batch currently being fetched.
    batch_high: u64,
    /// Whether the peer said more remains beyond that batch.
    more: bool,
}

/// One replication session with one peer.
pub struct Session {
    role: Role,
    local: NodeId,
    peer: Option<NodeId>,
    limits: Limits,
    features: Features,
    state: State,
    queue: VecDeque<StreamId>,
    progress: Option<StreamProgress>,
    pending: BTreeSet<ObjectId>,
    resolving: Option<IdentityId>,
    /// Responder: challenge for this session, injected so that this crate needs
    /// no randomness of its own.
    nonce: [u8; 32],
    /// Responder: identities that have proved themselves on this connection.
    authenticated: BTreeSet<IdentityId>,
    /// Responder: the request parked while a challenge is outstanding.
    challenged: Option<(StreamId, u64, u32)>,
    /// Initiator: how to answer a challenge, if it can.
    signer: Option<Box<dyn InboxSigner>>,
    /// Initiator: the identity this peer is expected to prove.
    expected_peer: Option<NodeId>,
    objects_accepted: usize,
    bytes_accepted: usize,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("role", &self.role)
            .field("state", &self.state)
            .field("peer", &self.peer)
            .field("authenticated", &self.authenticated.len())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// A session that opens the connection and syncs the given streams.
    pub fn initiator(local: NodeId, streams: Vec<StreamId>, limits: Limits) -> Self {
        Self {
            role: Role::Initiator,
            local,
            peer: None,
            limits,
            features: Features::NONE,
            state: State::New,
            queue: streams.into_iter().take(limits.max_streams).collect(),
            progress: None,
            pending: BTreeSet::new(),
            resolving: None,
            nonce: [0u8; 32],
            authenticated: BTreeSet::new(),
            challenged: None,
            signer: None,
            expected_peer: None,
            objects_accepted: 0,
            bytes_accepted: 0,
        }
    }

    /// Require the peer to prove a particular identity (§17.1, D14).
    ///
    /// Trust on first use: the first successful handshake pins an address to an
    /// identity, and every later one must match. A wrong address then yields a
    /// failed handshake rather than a conversation with whoever answered.
    #[must_use]
    pub const fn expecting(mut self, peer: NodeId) -> Self {
        self.expected_peer = Some(peer);
        self
    }

    /// Supply a credential for reading an inbox (§15.4).
    ///
    /// Without one, a session asking for a restricted stream fails the challenge
    /// rather than silently receiving nothing.
    #[must_use]
    pub fn with_inbox_signer(mut self, signer: Box<dyn InboxSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// A session whose only job is to resolve one identity (D12).
    ///
    /// Separate from a sync because a snapshot fetch has no cursor, no ordering
    /// and no session state to carry — forcing it into the journal model is what
    /// made it not fit anywhere for so long.
    pub fn resolver(local: NodeId, identity: IdentityId, limits: Limits) -> Self {
        Self {
            role: Role::Initiator,
            local,
            peer: None,
            limits,
            features: Features::NONE,
            state: State::New,
            queue: VecDeque::new(),
            progress: None,
            pending: BTreeSet::new(),
            resolving: Some(identity),
            nonce: [0u8; 32],
            authenticated: BTreeSet::new(),
            challenged: None,
            signer: None,
            expected_peer: None,
            objects_accepted: 0,
            bytes_accepted: 0,
        }
    }

    /// A session that answers.
    ///
    /// The `nonce` is the challenge this connection will issue for restricted
    /// streams. It is injected rather than generated so that this crate draws no
    /// randomness — which is what keeps it reproducible in a test and fuzzable.
    /// It must be unpredictable and must not be reused across connections, or a
    /// captured proof becomes a replayable one.
    pub fn responder(local: NodeId, limits: Limits, nonce: [u8; 32]) -> Self {
        Self {
            role: Role::Responder,
            local,
            peer: None,
            limits,
            features: Features::NONE,
            state: State::AwaitingHello,
            queue: VecDeque::new(),
            progress: None,
            pending: BTreeSet::new(),
            resolving: None,
            nonce,
            authenticated: BTreeSet::new(),
            challenged: None,
            signer: None,
            expected_peer: None,
            objects_accepted: 0,
            bytes_accepted: 0,
        }
    }

    /// Whether the session finished cleanly.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Whether the session ended badly.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self.state, State::Failed)
    }

    /// The peer's node identifier, once the handshake has happened.
    #[must_use]
    pub const fn peer(&self) -> Option<NodeId> {
        self.peer
    }

    /// Features both sides support.
    #[must_use]
    pub const fn features(&self) -> Features {
        self.features
    }

    /// How many objects this session has accepted.
    #[must_use]
    pub const fn objects_accepted(&self) -> usize {
        self.objects_accepted
    }

    /// Advance the session.
    ///
    /// Any error is terminal: the session moves to a failed state and will
    /// refuse further input. Continuing to talk to a peer that has already
    /// broken the protocol is how a resource attack gets its second try.
    pub fn step<R: Replica>(
        &mut self,
        replica: &mut R,
        input: Input,
    ) -> Result<Vec<Output>, ProtocolError> {
        if matches!(self.state, State::Failed | State::Done) {
            let message = match &input {
                Input::Start => "Start",
                Input::Received(m) => m.name(),
            };
            return Err(ProtocolError::Unexpected {
                message,
                state: self.state.name(),
            });
        }
        match self.dispatch(replica, input) {
            Ok(outputs) => Ok(outputs),
            Err(error) => {
                self.state = State::Failed;
                Err(error)
            }
        }
    }

    fn dispatch<R: Replica>(
        &mut self,
        replica: &mut R,
        input: Input,
    ) -> Result<Vec<Output>, ProtocolError> {
        match (self.state, input) {
            (State::New, Input::Start) if self.role == Role::Initiator => {
                self.state = State::AwaitingHelloAck;
                Ok(vec![Output::Send(Message::Hello {
                    version: PROTOCOL_VERSION,
                    node: self.local,
                    features: Features::SUPPORTED,
                })])
            }

            (
                State::AwaitingHello,
                Input::Received(Message::Hello {
                    version,
                    node,
                    features,
                }),
            ) => {
                Self::check_version(version)?;
                self.peer = Some(node);
                self.features = Features::SUPPORTED.intersect(features);
                self.state = State::Serving;
                Ok(vec![Output::Send(Message::HelloAck {
                    version: PROTOCOL_VERSION,
                    node: self.local,
                    features: Features::SUPPORTED,
                })])
            }

            (
                State::AwaitingHelloAck,
                Input::Received(Message::HelloAck {
                    version,
                    node,
                    features,
                }),
            ) => {
                Self::check_version(version)?;
                if let Some(expected) = self.expected_peer
                    && expected != node
                {
                    return Err(ProtocolError::WrongPeer {
                        expected,
                        found: node,
                    });
                }
                self.peer = Some(node);
                self.features = Features::SUPPORTED.intersect(features);
                if let Some(identity) = self.resolving {
                    self.state = State::AwaitingResolved;
                    return Ok(vec![Output::Send(Message::Resolve { identity })]);
                }
                self.begin_next_stream(replica)
            }

            (
                State::AwaitingResolved,
                Input::Received(Message::Resolved { identity, snapshot }),
            ) => {
                if Some(identity) != self.resolving {
                    return Err(ProtocolError::Unexpected {
                        message: "Resolved",
                        state: "a session that asked about a different identity",
                    });
                }
                self.state = State::Done;
                Ok(vec![
                    Output::Resolved(identity, snapshot.map(Into::into)),
                    Output::Send(Message::Bye),
                    Output::Complete,
                ])
            }

            (
                State::AwaitingHave,
                Input::Received(Message::Have {
                    stream,
                    entries,
                    more,
                }),
            ) => self.on_have(replica, &stream, &entries, more),

            (State::AwaitingHave, Input::Received(Message::AuthRequired { stream, nonce })) => {
                let Access::Owner(identity) = stream.access() else {
                    return Err(ProtocolError::Unexpected {
                        message: "AuthRequired",
                        state: "a session asking for an open stream",
                    });
                };
                let Some(signer) = self.signer.as_ref() else {
                    return Err(ProtocolError::AccessDenied);
                };
                if signer.identity() != identity {
                    return Err(ProtocolError::AccessDenied);
                }
                let peer = self.peer.ok_or(ProtocolError::Unexpected {
                    message: "AuthRequired",
                    state: "a session with no handshake",
                })?;
                let transcript = inbox_auth_transcript(&stream, &nonce, peer);
                Ok(vec![Output::Send(Message::AuthProof {
                    stream,
                    identity,
                    signing_key: signer.signing_key(),
                    signature: signer.sign(&transcript),
                })])
            }

            (State::AwaitingDeliver, Input::Received(Message::Deliver { objects })) => {
                self.on_deliver(replica, objects)
            }

            // -- responder duties ------------------------------------------
            (
                State::Serving,
                Input::Received(Message::Want {
                    stream,
                    after,
                    limit,
                }),
            ) => {
                // Access is a property of the stream, never of who is asking.
                if let Access::Owner(identity) = stream.access()
                    && !self.authenticated.contains(&identity)
                {
                    self.challenged = Some((stream.clone(), after, limit));
                    return Ok(vec![Output::Send(Message::AuthRequired {
                        stream,
                        nonce: self.nonce,
                    })]);
                }
                let limit = (limit as usize).min(self.limits.max_have_entries);
                let (entries, more) = replica
                    .journal_after(&stream, after, limit)
                    .map_err(|e| ProtocolError::Local(e.0))?;
                Ok(vec![Output::Send(Message::Have {
                    stream,
                    entries,
                    more,
                })])
            }

            (State::Serving, Input::Received(Message::Fetch { objects })) => {
                let mut bytes = Vec::with_capacity(objects.len());
                for id in objects {
                    if let Some(object) = replica
                        .object_bytes(id)
                        .map_err(|e| ProtocolError::Local(e.0))?
                    {
                        bytes.push(object.into());
                    }
                }
                Ok(vec![Output::Send(Message::Deliver { objects: bytes })])
            }

            (State::Serving, Input::Received(Message::InventoryRequest { stream, from, to })) => {
                if !self.features.contains(Features::INVENTORY_REPAIR) {
                    return Err(ProtocolError::Unexpected {
                        message: "InventoryRequest",
                        state: "a session that did not negotiate inventory repair",
                    });
                }
                let objects = replica
                    .inventory(&stream, from, to)
                    .map_err(|e| ProtocolError::Local(e.0))?;
                Ok(vec![Output::Send(Message::InventoryResponse {
                    stream,
                    objects,
                })])
            }

            (
                State::Serving,
                Input::Received(Message::AuthProof {
                    stream,
                    identity,
                    signing_key,
                    signature,
                }),
            ) => {
                let Some((wanted, after, limit)) = self.challenged.take() else {
                    return Err(ProtocolError::Unexpected {
                        message: "AuthProof",
                        state: "a session that issued no challenge",
                    });
                };
                if wanted != stream || stream.access() != Access::Owner(identity) {
                    return Err(ProtocolError::Unexpected {
                        message: "AuthProof",
                        state: "a session that challenged a different stream",
                    });
                }

                let transcript = inbox_auth_transcript(&stream, &self.nonce, self.local);
                let ok = replica
                    .verify_inbox_access(identity, signing_key, &transcript, signature)
                    .map_err(|e| ProtocolError::Local(e.0))?;
                if !ok {
                    return Err(ProtocolError::AccessDenied);
                }
                self.authenticated.insert(identity);

                // Answer the request that was parked, rather than making the
                // peer ask again.
                let limit = (limit as usize).min(self.limits.max_have_entries);
                let (entries, more) = replica
                    .journal_after(&stream, after, limit)
                    .map_err(|e| ProtocolError::Local(e.0))?;
                Ok(vec![Output::Send(Message::Have {
                    stream,
                    entries,
                    more,
                })])
            }

            (State::Serving, Input::Received(Message::Resolve { identity })) => {
                // Answered from what this node holds, and never by asking
                // anyone else. Forwarding would make every node a party to who
                // is asking about whom, and would make the query floodable.
                let snapshot = replica
                    .snapshot(identity)
                    .map_err(|e| ProtocolError::Local(e.0))?;
                Ok(vec![Output::Send(Message::Resolved {
                    identity,
                    snapshot: snapshot.map(Into::into),
                })])
            }

            (State::Serving, Input::Received(Message::Bye)) => {
                self.state = State::Done;
                Ok(vec![Output::Complete])
            }

            (state, Input::Received(message)) => Err(ProtocolError::Unexpected {
                message: message.name(),
                state: state.name(),
            }),
            (state, Input::Start) => Err(ProtocolError::Unexpected {
                message: "Start",
                state: state.name(),
            }),
        }
    }

    fn check_version(version: u16) -> Result<(), ProtocolError> {
        if version == PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(ProtocolError::VersionMismatch {
                ours: PROTOCOL_VERSION,
                theirs: version,
            })
        }
    }

    /// Ask for the next stream, or finish.
    fn begin_next_stream<R: Replica>(
        &mut self,
        replica: &mut R,
    ) -> Result<Vec<Output>, ProtocolError> {
        self.progress = None;
        let Some(stream) = self.queue.pop_front() else {
            self.state = State::Done;
            return Ok(vec![Output::Send(Message::Bye), Output::Complete]);
        };
        let peer = self.peer.ok_or(ProtocolError::Unexpected {
            message: "stream request",
            state: "a session with no handshake",
        })?;
        let cursor = replica
            .cursor(peer, &stream)
            .map_err(|e| ProtocolError::Local(e.0))?;

        self.progress = Some(StreamProgress {
            stream: stream.clone(),
            cursor,
            batch_high: cursor,
            more: false,
        });
        self.state = State::AwaitingHave;
        Ok(vec![Output::Send(Message::Want {
            stream,
            after: cursor,
            limit: u32::try_from(self.limits.max_have_entries).unwrap_or(u32::MAX),
        })])
    }

    fn on_have<R: Replica>(
        &mut self,
        replica: &mut R,
        stream: &StreamId,
        entries: &[JournalEntry],
        more: bool,
    ) -> Result<Vec<Output>, ProtocolError> {
        let progress = self.progress.as_mut().ok_or(ProtocolError::Unexpected {
            message: "Have",
            state: "a session tracking no stream",
        })?;
        if *stream != progress.stream {
            return Err(ProtocolError::Unexpected {
                message: "Have",
                state: "a session waiting on a different stream",
            });
        }

        // A journal is append-only. Positions that do not strictly increase are
        // either corruption or an attempt to rewind our cursor and make us
        // re-fetch history for as long as we are willing to listen.
        let mut previous = progress.cursor;
        for entry in entries {
            if entry.position <= previous {
                return Err(ProtocolError::NonMonotonicJournal {
                    previous,
                    offered: entry.position,
                });
            }
            previous = entry.position;
        }

        progress.batch_high = previous;
        progress.more = more;

        let mut missing = BTreeSet::new();
        for entry in entries {
            if !replica
                .contains(entry.object)
                .map_err(|e| ProtocolError::Local(e.0))?
            {
                missing.insert(entry.object);
            }
        }

        if missing.is_empty() {
            return self.finish_batch(replica);
        }
        if missing.len() > self.limits.max_fetch_ids {
            return Err(ProtocolError::TooMany {
                what: "objects to fetch",
                count: missing.len(),
                limit: self.limits.max_fetch_ids,
            });
        }

        self.pending = missing;
        self.state = State::AwaitingDeliver;
        Ok(vec![Output::Send(Message::Fetch {
            objects: self.pending.iter().copied().collect(),
        })])
    }

    fn on_deliver<R: Replica>(
        &mut self,
        replica: &mut R,
        objects: Vec<minicbor::bytes::ByteVec>,
    ) -> Result<Vec<Output>, ProtocolError> {
        let mut outputs = Vec::with_capacity(objects.len());

        for bytes in objects {
            if bytes.len() > self.limits.max_object_bytes {
                return Err(ProtocolError::ObjectTooLarge {
                    size: bytes.len(),
                    limit: self.limits.max_object_bytes,
                });
            }
            self.objects_accepted += 1;
            self.bytes_accepted += bytes.len();
            if self.objects_accepted > self.limits.max_objects_per_session
                || self.bytes_accepted > self.limits.max_bytes_per_session
            {
                return Err(ProtocolError::SessionBudgetExhausted);
            }

            // Establish what these bytes *are* before storing them. Accepting
            // first and checking afterwards would let any peer push arbitrary
            // content at any moment, and every limit here is expressed in terms
            // of what we asked for.
            let object =
                Object::from_canonical_bytes(&bytes).map_err(|_| ProtocolError::InvalidObject)?;
            let id = object.id();

            if !self.pending.remove(&id) {
                return Err(ProtocolError::UnsolicitedObject(id));
            }

            match replica.accept(&bytes) {
                Ok(stored) if stored == id => outputs.push(Output::Accepted(stored)),
                Ok(stored) => {
                    return Err(ProtocolError::WrongObject {
                        expected: id,
                        received: stored,
                    });
                }
                Err(AcceptError::Invalid) => return Err(ProtocolError::InvalidObject),
                Err(AcceptError::Local(e)) => return Err(ProtocolError::Local(e.0)),
            }
        }

        if self.pending.is_empty() {
            outputs.extend(self.finish_batch(replica)?);
        }
        Ok(outputs)
    }

    /// A batch is complete: advance the cursor, then continue or move on.
    ///
    /// The cursor only ever moves after everything in the batch is stored, so an
    /// interrupted session resumes from the last fully-applied position rather
    /// than skipping what it never received.
    fn finish_batch<R: Replica>(&mut self, replica: &mut R) -> Result<Vec<Output>, ProtocolError> {
        let Some(progress) = self.progress.clone() else {
            return self.begin_next_stream(replica);
        };
        let peer = self.peer.ok_or(ProtocolError::Unexpected {
            message: "batch completion",
            state: "a session with no handshake",
        })?;

        if progress.batch_high > progress.cursor {
            replica
                .set_cursor(peer, &progress.stream, progress.batch_high)
                .map_err(|e| ProtocolError::Local(e.0))?;
        }

        if progress.more {
            let cursor = progress.batch_high;
            if let Some(current) = self.progress.as_mut() {
                current.cursor = cursor;
                current.more = false;
            }
            self.state = State::AwaitingHave;
            return Ok(vec![Output::Send(Message::Want {
                stream: progress.stream,
                after: cursor,
                limit: u32::try_from(self.limits.max_have_entries).unwrap_or(u32::MAX),
            })]);
        }
        self.begin_next_stream(replica)
    }
}
