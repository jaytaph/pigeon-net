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

use pigeonnet_core::{NodeId, Object, ObjectId};

use crate::{
    ProtocolError,
    limits::Limits,
    message::{Features, JournalEntry, Message, PROTOCOL_VERSION, StreamId},
    replica::{AcceptError, Replica},
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
#[derive(Debug)]
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
    objects_accepted: usize,
    bytes_accepted: usize,
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
            objects_accepted: 0,
            bytes_accepted: 0,
        }
    }

    /// A session that answers.
    pub fn responder(local: NodeId, limits: Limits) -> Self {
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
                self.peer = Some(node);
                self.features = Features::SUPPORTED.intersect(features);
                self.begin_next_stream(replica)
            }

            (
                State::AwaitingHave,
                Input::Received(Message::Have {
                    stream,
                    entries,
                    more,
                }),
            ) => self.on_have(replica, &stream, &entries, more),

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
            stream,
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
