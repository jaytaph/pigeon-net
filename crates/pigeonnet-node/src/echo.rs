//! Echo areas: subscribing, posting, and reading threads (§6, §7).

use pigeonnet_core::{
    AreaName, EchoPost, IdentityId, ObjectId, ObjectType, Tbs, Timestamp, cbor,
    payload::{Capabilities, Payload},
};
use pigeonnet_proto::StreamId;

use crate::{Node, NodeError};

/// A post, placed in its thread.
#[derive(Clone, Debug)]
pub struct ThreadedPost {
    /// The object.
    pub id: ObjectId,
    /// Who wrote it.
    pub author: IdentityId,
    /// When they say they did.
    pub timestamp: Timestamp,
    /// How deep in the thread, with a root at zero.
    pub depth: usize,
    /// The post itself.
    pub post: EchoPost,
}

/// What this node can say about an area, from what it holds.
///
/// Every figure here is a fact about *this node's store*, not about the area.
/// Another node carrying the same area will report different numbers, and
/// neither is wrong — there is no authoritative view of an echo, by design.
#[derive(Clone, Debug)]
pub struct AreaStats {
    /// The area.
    pub area: AreaName,
    /// Whether this node carries it deliberately, or merely happens to hold it.
    pub subscribed: bool,
    /// Posts held.
    pub posts: usize,
    /// Distinct threads among them.
    pub threads: usize,
    /// The earliest post held.
    ///
    /// **Not the area's creation date.** No object creates an area; one exists
    /// because somebody posted to it. The earliest post this node happens to
    /// hold says nothing about when the area began, and calling it a creation
    /// date would be a small lie that gets repeated.
    pub first_held: Timestamp,
    /// The most recent post held.
    pub latest: Timestamp,
    /// Distinct authors.
    pub voices: usize,
}

impl Node {
    /// Statistics for every area this node holds posts in.
    ///
    /// Scans stored posts rather than consulting an index. Fine for the volumes
    /// a personal node sees; an area with a decade of traffic would want the
    /// counts maintained on write instead.
    pub fn area_stats(&self) -> Result<Vec<AreaStats>, NodeError> {
        use std::collections::{BTreeMap, BTreeSet};

        let subscribed: BTreeSet<AreaName> = self.subscriptions()?.into_iter().collect();

        struct Acc {
            posts: usize,
            threads: BTreeSet<ObjectId>,
            voices: BTreeSet<IdentityId>,
            first: i64,
            latest: i64,
        }
        let mut areas: BTreeMap<AreaName, Acc> = BTreeMap::new();

        for object in self.store().objects_of_type(ObjectType::EchoPost.code())? {
            let id = object.id();
            let tbs = object.tbs()?;
            let post = EchoPost::decode_payload(&tbs.payload)?;
            let at = tbs.timestamp.as_millis();

            let acc = areas.entry(post.area.clone()).or_insert_with(|| Acc {
                posts: 0,
                threads: BTreeSet::new(),
                voices: BTreeSet::new(),
                first: at,
                latest: at,
            });
            acc.posts += 1;
            acc.threads.insert(post.thread_root(id));
            acc.voices.insert(tbs.author);
            acc.first = acc.first.min(at);
            acc.latest = acc.latest.max(at);
        }

        // An area subscribed to but silent still deserves a row: "nothing here
        // yet" and "you are not carrying this" are different answers.
        for area in &subscribed {
            areas.entry(area.clone()).or_insert_with(|| Acc {
                posts: 0,
                threads: BTreeSet::new(),
                voices: BTreeSet::new(),
                first: 0,
                latest: 0,
            });
        }

        Ok(areas
            .into_iter()
            .map(|(area, acc)| AreaStats {
                subscribed: subscribed.contains(&area),
                area,
                posts: acc.posts,
                threads: acc.threads.len(),
                voices: acc.voices.len(),
                first_held: Timestamp::from_millis(acc.first),
                latest: Timestamp::from_millis(acc.latest),
            })
            .collect())
    }

    /// Subscribe to an echo area.
    pub fn subscribe(&self, area: &AreaName) -> Result<(), NodeError> {
        Ok(self.store().subscribe(area.as_str())?)
    }

    /// Stop carrying an area. Objects already held are kept.
    pub fn unsubscribe(&self, area: &AreaName) -> Result<(), NodeError> {
        Ok(self.store().unsubscribe(area.as_str())?)
    }

    /// Every subscribed area.
    pub fn subscriptions(&self) -> Result<Vec<AreaName>, NodeError> {
        let mut areas = Vec::new();
        for text in self.store().subscriptions()? {
            // Stored names were validated before insertion; a name that no
            // longer parses means the database was edited by something else.
            areas.push(AreaName::parse(&text)?);
        }
        Ok(areas)
    }

    /// What this node should ask a peer for.
    ///
    /// `All` plus one stream per subscribed area. `All` is what carries identity
    /// chains and anything this build does not understand; the per-area streams
    /// are what let a peer sync one area without taking everything.
    pub fn sync_plan(&self) -> Result<Vec<StreamId>, NodeError> {
        let mut plan = vec![StreamId::All];
        for area in self.subscriptions()? {
            plan.push(StreamId::Echo(area));
        }
        Ok(plan)
    }

    /// This node's own identity.
    ///
    /// Recorded when the identity is created, not inferred from the store. A node
    /// that has synced once holds other people's genesis objects, and they are
    /// indistinguishable from its own — so scanning for one returns whichever
    /// happens to sort first, which is a bug that only appears after the node
    /// starts talking to anybody.
    pub fn local_identity(&self) -> Result<IdentityId, NodeError> {
        let bytes = self
            .store()
            .state(crate::LOCAL_IDENTITY)?
            .ok_or(NodeError::NotInitialised)?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| NodeError::NotInitialised)?;
        Ok(IdentityId::from_bytes(bytes))
    }

    /// Start a thread.
    pub fn post(
        &self,
        area: &AreaName,
        content: &str,
        passphrase: &[u8],
        now: i64,
    ) -> Result<ObjectId, NodeError> {
        let payload = EchoPost::root(area.clone(), "text/markdown".to_owned(), content.to_owned());
        self.publish_post(payload, passphrase, now)
    }

    /// Reply to a post, inheriting its area and thread.
    ///
    /// The thread root comes from the parent rather than from the caller, so a
    /// reply cannot be attached to one thread while claiming another.
    pub fn reply(
        &self,
        parent_id: ObjectId,
        content: &str,
        passphrase: &[u8],
        now: i64,
    ) -> Result<ObjectId, NodeError> {
        let parent = self
            .object(parent_id)?
            .ok_or(NodeError::UnknownObject(parent_id))?;
        let parent_tbs = parent.tbs()?;
        if parent_tbs.object_type() != Ok(ObjectType::EchoPost) {
            return Err(NodeError::Object(pigeonnet_core::Error::BadThreading));
        }
        let parent_post = EchoPost::decode_payload(&parent_tbs.payload)?;

        let payload = EchoPost::reply(
            parent_post.area.clone(),
            parent_post.thread_root(parent_id),
            parent_id,
            "text/markdown".to_owned(),
            content.to_owned(),
        );
        self.publish_post(payload, passphrase, now)
    }

    fn publish_post(
        &self,
        payload: EchoPost,
        passphrase: &[u8],
        now: i64,
    ) -> Result<ObjectId, NodeError> {
        self.publish(
            ObjectType::EchoPost,
            payload.encode_payload()?,
            Capabilities::POST,
            passphrase,
            now,
        )
    }

    /// Every post in an area, arranged into threads.
    ///
    /// Ordering is total and derived only from the objects themselves — thread
    /// roots by timestamp then identifier, replies likewise within each parent —
    /// so two nodes holding the same objects render the same tree. Any ordering
    /// that depended on arrival time would not (§7).
    pub fn read_area(&self, area: &AreaName) -> Result<Vec<ThreadedPost>, NodeError> {
        let key = cbor::to_canonical_vec(&StreamId::Echo(area.clone()))?;
        let (entries, _) = self.store().journal_after(&key, 0, usize::MAX)?;

        let mut posts = Vec::new();
        for (_, id) in entries {
            let Some(object) = self.store().get(id)? else {
                continue;
            };
            let tbs = object.tbs()?;
            if tbs.object_type() != Ok(ObjectType::EchoPost) {
                continue;
            }
            let post = EchoPost::decode_payload(&tbs.payload)?;
            if post.area != *area {
                continue;
            }
            posts.push((id, tbs, post));
        }

        Ok(Self::arrange(posts))
    }

    /// Turn a flat set of posts into a depth-first forest.
    ///
    /// A reply whose parent is absent — pruned (D8), or simply not yet arrived —
    /// is attached at its thread root rather than dropped. Losing a reply because
    /// an intermediate post is missing would make threads depend on replication
    /// order, which is exactly what stubs exist to prevent (§30.3).
    fn arrange(posts: Vec<(ObjectId, Tbs, EchoPost)>) -> Vec<ThreadedPost> {
        use std::collections::BTreeMap;

        let present: std::collections::BTreeSet<ObjectId> =
            posts.iter().map(|(id, _, _)| *id).collect();

        let mut children: BTreeMap<ObjectId, Vec<(ObjectId, Tbs, EchoPost)>> = BTreeMap::new();
        let mut roots: Vec<(ObjectId, Tbs, EchoPost)> = Vec::new();

        for (id, tbs, post) in posts {
            match post.parent {
                None => roots.push((id, tbs, post)),
                Some(parent) if present.contains(&parent) => {
                    children.entry(parent).or_default().push((id, tbs, post));
                }
                Some(_) => {
                    // Orphaned: hang it off the thread root it names.
                    let root = post.thread_root(id);
                    children.entry(root).or_default().push((id, tbs, post));
                }
            }
        }

        let by_time = |a: &(ObjectId, Tbs, EchoPost), b: &(ObjectId, Tbs, EchoPost)| {
            a.1.timestamp
                .cmp(&b.1.timestamp)
                .then_with(|| a.0.cmp(&b.0))
        };
        roots.sort_by(by_time);
        for list in children.values_mut() {
            list.sort_by(by_time);
        }

        let mut out = Vec::new();
        for root in roots {
            Self::walk(root, 0, &mut children, &mut out);
        }
        out
    }

    fn walk(
        (id, tbs, post): (ObjectId, Tbs, EchoPost),
        depth: usize,
        children: &mut std::collections::BTreeMap<ObjectId, Vec<(ObjectId, Tbs, EchoPost)>>,
        out: &mut Vec<ThreadedPost>,
    ) {
        out.push(ThreadedPost {
            id,
            author: tbs.author,
            timestamp: tbs.timestamp,
            depth,
            post,
        });
        // `remove` rather than `get`: a cycle forged by a malicious author would
        // otherwise recurse forever, and object identifiers make a true cycle
        // impossible only if every hash is honest.
        if let Some(kids) = children.remove(&id) {
            for kid in kids {
                Self::walk(kid, depth + 1, children, out);
            }
        }
    }
}
