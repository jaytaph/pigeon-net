//! `nodectl` — the Pigeonnet command line interface (§27).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod render;

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use pigeonnet_core::{NodeId, ObjectId, payload::IdentityCreated, payload::Payload};
use pigeonnet_node::Node;

/// Pigeonnet node control.
#[derive(Parser, Debug)]
#[command(name = "nodectl", version, about)]
struct Cli {
    /// Node directory. Defaults to $PIGEONNET_HOME, then ~/.pigeonnet
    #[arg(long, global = true)]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Identity management.
    #[command(subcommand)]
    Identity(IdentityCommand),

    /// Object inspection.
    #[command(subcommand)]
    Object(ObjectCommand),

    /// Offline transport: bundles on removable media (§19).
    #[command(subcommand)]
    Bundle(BundleCommand),

    /// Public discussion areas (§6).
    #[command(subcommand)]
    Echo(EchoCommand),

    /// Peers this node talks to (§17.1).
    #[command(subcommand)]
    Peer(PeerCommand),

    /// Sync with configured peers.
    Sync {
        /// One address, or every configured peer if omitted.
        address: Option<String>,
    },

    /// Answer peers until stopped.
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "0.0.0.0:4137")]
        listen: String,
        /// Serve only; do not also pull from whoever connects.
        ///
        /// The reciprocal pull is how a peer behind a firewall gets its own
        /// objects out. Turning it off makes this node a read-only source.
        #[arg(long)]
        serve_only: bool,
    },

    /// Post to an echo area.
    Post {
        /// The area, e.g. GOSUB.DEV
        area: String,
        /// What to say.
        content: String,
    },

    /// Send a private message (§8).
    Message {
        /// The recipient's identity. It must already be resolvable here.
        identity: String,
        /// What to say.
        content: String,
    },

    /// Show private messages addressed to this node.
    Inbox,

    /// Destroy epoch secrets whose retention window has closed (§8.1).
    ///
    /// Irreversible. Meant for a schedule: a node that never runs this keeps
    /// every secret it has held, and its forward secrecy is a claim rather than
    /// a property.
    Expire,

    /// Show what this node knows of an identity's current state (§5.6).
    Resolve {
        /// The exact identity. There is no search.
        identity: String,
    },

    /// Publish epoch prekeys for this device (§8.1).
    Prekeys {
        /// How many epochs ahead to cover.
        #[arg(long, default_value_t = 14)]
        lookahead: u64,
    },

    /// Reply to a post, inheriting its area and thread.
    Reply {
        /// The post being replied to.
        parent: String,
        /// What to say.
        content: String,
    },
}

#[derive(Subcommand, Debug)]
enum PeerCommand {
    /// Remember a peer.
    Add {
        /// `host:port`. The port defaults to 4137.
        address: String,
        /// Require this exact node identity, instead of pinning on first use.
        #[arg(long)]
        expect: Option<String>,
    },
    /// Forget a peer. Objects learned from it are kept.
    Remove {
        /// The address, as given to `peer add`.
        address: String,
    },
    /// Show configured peers.
    List,
}

#[derive(Subcommand, Debug)]
enum EchoCommand {
    /// Carry an area.
    Subscribe {
        /// The area, e.g. GOSUB.DEV
        area: String,
    },
    /// Stop carrying an area. Objects already held are kept.
    Unsubscribe {
        /// The area.
        area: String,
    },
    /// Show subscribed areas.
    List,
    /// Read an area's threads.
    Read {
        /// The area.
        area: String,
    },
}

#[derive(Subcommand, Debug)]
enum IdentityCommand {
    /// Create this node's identity.
    Create {
        /// A local label. Not published, and not part of the identity.
        #[arg(long)]
        name: Option<String>,
    },
    /// Show this node's identity and key state.
    Show,
}

#[derive(Subcommand, Debug)]
enum BundleCommand {
    /// Pack this node's objects into a file.
    Export {
        /// Where to write it.
        path: PathBuf,
        /// The peer this bundle is for, so it can carry our cursor back.
        #[arg(long)]
        peer: Option<String>,
    },
    /// Read a bundle. Safe to run on a file from anywhere.
    Import {
        /// The file to read.
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum ObjectCommand {
    /// Show one object.
    Show {
        /// Object identifier, as `obj:b3:...`
        id: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let home = resolve_home(cli.home)?;
    let node = Node::open(&home).with_context(|| format!("opening node at {}", home.display()))?;

    match cli.command {
        Command::Identity(IdentityCommand::Create { name }) => {
            create_identity(&node, name.as_deref())
        }
        Command::Identity(IdentityCommand::Show) => show_identity(&node),
        Command::Object(ObjectCommand::Show { id }) => show_object(&node, &id),
        Command::Bundle(BundleCommand::Export { path, peer }) => {
            export_bundle(&node, &path, peer.as_deref())
        }
        Command::Bundle(BundleCommand::Import { path }) => import_bundle(&node, &path),
        Command::Echo(EchoCommand::Subscribe { area }) => {
            node.subscribe(&parse_area(&area)?)?;
            println!("subscribed to echo://{area}");
            Ok(())
        }
        Command::Echo(EchoCommand::Unsubscribe { area }) => {
            node.unsubscribe(&parse_area(&area)?)?;
            println!("unsubscribed from echo://{area}");
            Ok(())
        }
        Command::Echo(EchoCommand::List) => {
            for area in node.subscriptions()? {
                println!("echo://{area}");
            }
            Ok(())
        }
        Command::Echo(EchoCommand::Read { area }) => read_area(&node, &parse_area(&area)?),
        Command::Post { area, content } => {
            let id = node.post(&parse_area(&area)?, &content, &passphrase()?, now_millis()?)?;
            println!("created  {id}");
            println!("queued   for subscribed peers");
            Ok(())
        }
        Command::Peer(PeerCommand::Add { address, expect }) => {
            let address = with_default_port(&address);
            let expect = expect
                .map(|text| NodeId::parse(&text).map_err(|e| anyhow::anyhow!("{e}")))
                .transpose()?;
            node.store().peer_add(&address, expect, now_millis()?)?;
            match expect {
                Some(id) => println!("added {address}, requiring {id}"),
                None => println!("added {address}; its identity pins on first sync"),
            }
            Ok(())
        }
        Command::Peer(PeerCommand::Remove { address }) => {
            let address = with_default_port(&address);
            if node.store().peer_remove(&address)? {
                println!("removed {address}");
            } else {
                println!("no such peer: {address}");
            }
            Ok(())
        }
        Command::Peer(PeerCommand::List) => list_peers(&node),
        Command::Sync { address } => run_sync(&node, address.as_deref()),
        Command::Serve { listen, serve_only } => run_serve(&node, &listen, !serve_only),
        Command::Message { identity, content } => {
            let identity =
                pigeonnet_core::IdentityId::parse(&identity).map_err(|e| anyhow::anyhow!("{e}"))?;
            let id = node.send_message(identity, &content, &passphrase()?, now_millis()?)?;
            println!("created  {id}");
            println!("queued   for the next sync");
            Ok(())
        }
        Command::Inbox => show_inbox(&node),
        Command::Expire => {
            let destroyed = node.destroy_expired_prekeys(&passphrase()?, now_millis()?)?;
            match destroyed {
                0 => println!("nothing has expired yet"),
                n => println!("destroyed {n} epoch secrets; messages sealed to them are gone"),
            }
            Ok(())
        }
        Command::Resolve { identity } => show_resolved(&node, &identity),
        Command::Prekeys { lookahead } => {
            let published = node.publish_prekeys(&passphrase()?, now_millis()?, lookahead)?;
            match published.len() {
                0 => println!("already covered; nothing to publish"),
                n => println!(
                    "published {n} epoch prekeys, epochs {}..={}",
                    published.first().copied().unwrap_or(0),
                    published.last().copied().unwrap_or(0)
                ),
            }
            Ok(())
        }
        Command::Reply { parent, content } => {
            let parent = ObjectId::parse(&parent).map_err(|e| anyhow::anyhow!("{e}"))?;
            let id = node.reply(parent, &content, &passphrase()?, now_millis()?)?;
            println!("created  {id}");
            println!("queued   for subscribed peers");
            Ok(())
        }
    }
}

fn resolve_home(flag: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = flag {
        return Ok(path);
    }
    if let Ok(path) = std::env::var("PIGEONNET_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME").context("neither --home, $PIGEONNET_HOME nor $HOME is set")?;
    Ok(PathBuf::from(home).join(".pigeonnet"))
}

/// Read the keystore passphrase.
///
/// From the environment, deliberately not from a command-line argument: argv is
/// visible to every process on the machine. An interactive prompt is the right
/// answer and arrives with the rest of the CLI work; until then this is the
/// honest option rather than the convenient one.
fn passphrase() -> Result<Vec<u8>> {
    match std::env::var("PIGEONNET_PASSPHRASE") {
        Ok(value) if !value.is_empty() => Ok(value.into_bytes()),
        _ => bail!("set PIGEONNET_PASSPHRASE (an interactive prompt is not implemented yet)"),
    }
}

fn now_millis() -> Result<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis();
    i64::try_from(millis).context("system clock is implausibly far in the future")
}

fn create_identity(node: &Node, name: Option<&str>) -> Result<()> {
    let passphrase = passphrase()?;
    let created = node.create_identity(&passphrase, now_millis()?)?;

    println!("Generating root key      ed25519 ........ ok");
    println!("Generating recovery key  ed25519 ........ ok");
    println!("Generating identity key  x25519  ........ ok");
    println!("Writing genesis object   IdentityCreated  ok");
    println!();
    println!("  Your identity is");
    println!("      {}", created.identity);
    println!();
    println!("  Fingerprint (read this aloud to verify in person)");
    for line in render::fingerprint(created.identity.as_bytes()) {
        println!("      {line}");
    }
    println!();
    println!(
        "Granting device key      {:<16} ok",
        name.unwrap_or("this-device")
    );
    println!("Locking keystore         argon2id         ok");
    println!();
    println!("  \u{26a0}  RECOVERY KEY — write this down, on paper, now.");
    println!();
    println!(
        "      {}",
        render::recovery_phrase(&created.recovery_secret)
    );
    println!();
    println!("     Not stored on this machine. Will not be shown again.");
    println!("     Without it, a lost or stolen root key ends this identity.");
    println!();
    println!("  genesis      {}", created.genesis);
    println!("  device grant {}", created.device_grant);
    Ok(())
}

fn show_identity(node: &Node) -> Result<()> {
    let passphrase = passphrase()?;
    let keyring = node.keyring(&passphrase)?;

    // The identity is derived from stored objects, not from the keystore: the
    // keystore holds secrets, the chain holds the truth.
    let genesis_author = node
        .store()
        .objects_by_author(pigeonnet_core::IdentityId::ZERO)?
        .into_iter()
        .next()
        .context("no genesis object in the store")?;
    let identity = pigeonnet_core::IdentityId::from_genesis(genesis_author.id());
    let state = node.identity_state(identity)?;

    println!("identity      {}", state.id());
    println!("genesis       {}", state.id().genesis_object());
    println!("root key      {}", state.root_key());
    println!(
        "recovery key  {}   (private half is on paper only)",
        state.recovery_key()
    );
    println!("agreement key {}", state.agreement_key());
    println!();
    let device = keyring.device().public();
    match state.capabilities_of(device) {
        Some(capabilities) => println!("this device   {device}\n              {capabilities:?}"),
        None => println!("this device   {device}\n              not delegated"),
    }
    println!();
    println!("objects held  {}", node.store().len()?);
    Ok(())
}

fn show_object(node: &Node, id: &str) -> Result<()> {
    let id = ObjectId::parse(id).map_err(|e| anyhow::anyhow!("{e}"))?;
    let object = node
        .object(id)?
        .context("object not found in this node's store")?;
    let tbs = object.tbs()?;

    println!("id            {}", object.id());
    println!("version       {}", tbs.version);
    match tbs.object_type() {
        Ok(t) => println!("type          {t:?} ({})", tbs.type_code),
        Err(_) => println!(
            "type          unknown ({}) — storable and relayable",
            tbs.type_code
        ),
    }
    println!(
        "author        {}",
        if tbs.is_genesis() {
            "(genesis — this object creates the identity)".to_string()
        } else {
            tbs.author.to_string()
        }
    );
    println!("signing key   {}", tbs.signing_key);
    println!(
        "timestamp     {} ({})",
        render::iso8601(tbs.timestamp.as_millis()),
        tbs.timestamp.as_millis()
    );
    println!("sequence      {}", tbs.sequence);
    println!("payload       {} bytes", tbs.payload.len());
    println!("signature     {}", object.signature());

    if tbs.object_type() == Ok(pigeonnet_core::ObjectType::IdentityCreated)
        && let Ok(payload) = IdentityCreated::decode_payload(&tbs.payload)
    {
        println!();
        println!("  root key      {}", payload.root_key);
        println!("  recovery key  {}", payload.recovery_key);
        println!("  agreement key {}", payload.agreement_key);
    }
    Ok(())
}

fn export_bundle(node: &Node, path: &std::path::Path, peer: Option<&str>) -> Result<()> {
    let passphrase = passphrase()?;
    let origin = node.node_id(&passphrase)?;
    let peer = peer
        .map(|text| NodeId::parse(text).map_err(|e| anyhow::anyhow!("{e}")))
        .transpose()?;

    let bytes = node.export_bundle(origin, now_millis()?, &[], peer)?;
    std::fs::write(path, &bytes).with_context(|| format!("writing {}", path.display()))?;

    println!("  objects   {}", node.store().len()?);
    println!("  origin    {origin}");
    println!("  size      {} bytes", bytes.len());
    println!("  written to {}", path.display());
    Ok(())
}

fn import_bundle(node: &Node, path: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let (report, requests) = node.import_bundle(&bytes, now_millis()?)?;

    println!("  {} objects accepted", report.accepted);
    println!("  {} already held", report.already_held);
    println!("  {} cursors advanced", report.cursors_advanced);
    if !requests.is_empty() {
        println!();
        println!("  the sender is missing everything after:");
        for request in requests {
            println!("    {:?} after {}", request.stream, request.after);
        }
    }
    Ok(())
}

fn parse_area(text: &str) -> Result<pigeonnet_core::AreaName> {
    pigeonnet_core::AreaName::parse(text).map_err(|e| anyhow::anyhow!("{e}"))
}

fn read_area(node: &Node, area: &pigeonnet_core::AreaName) -> Result<()> {
    let posts = node.read_area(area)?;
    if posts.is_empty() {
        println!("echo://{area} is empty");
        return Ok(());
    }
    for post in posts {
        let indent = "  ".repeat(post.depth);
        println!(
            "{indent}{}  {}",
            render::iso8601(post.timestamp.as_millis()),
            post.id
        );
        println!("{indent}  from {}", post.author);
        for line in post.post.content.lines() {
            println!("{indent}  {line}");
        }
        println!();
    }
    Ok(())
}

fn show_resolved(node: &Node, identity: &str) -> Result<()> {
    let identity =
        pigeonnet_core::IdentityId::parse(identity).map_err(|e| anyhow::anyhow!("{e}"))?;
    let now = now_millis()?;
    let snapshot = node
        .snapshot(identity, now)?
        .context("this node holds nothing for that identity")?;
    let resolved = snapshot
        .verify(pigeonnet_core::Timestamp::from_millis(now))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("identity      {}", resolved.state.id());
    if let Some(profile) = &resolved.profile
        && let Some(name) = &profile.display_name
    {
        println!("calls itself  {name}   (self-asserted; not a bound name)");
    }
    println!("root key      {}", resolved.state.root_key());
    println!(
        "usable until  {}   (clamped to its contents, not the server's claim)",
        render::iso8601(resolved.valid_until.as_millis())
    );
    println!();

    println!("prekeys       {}", resolved.prekeys.len());
    let mut prekeys = resolved.prekeys.clone();
    prekeys.sort_by_key(|(_, prekey)| prekey.epoch);
    for (device, prekey) in &prekeys {
        println!(
            "  epoch {:<6} until {}  device {}",
            prekey.epoch,
            render::iso8601(prekey.valid_until.as_millis()),
            &device.to_string()[..24]
        );
    }
    println!();

    if resolved.carriers.is_empty() {
        println!("carriers      none confirmed");
    } else {
        println!("carriers      {} confirmed", resolved.carriers.len());
        for carrier in &resolved.carriers {
            println!("  cost {:<4} {}", carrier.cost, carrier.node);
        }
    }
    for carrier in &resolved.unconfirmed {
        println!(
            "  UNCONFIRMED  {}  (claimed, but it has not consented)",
            carrier.node
        );
    }
    Ok(())
}

/// `host` means `host:4137`.
fn with_default_port(address: &str) -> String {
    if address
        .rsplit(':')
        .next()
        .is_some_and(|tail| tail.parse::<u16>().is_ok())
    {
        address.to_owned()
    } else {
        format!("{address}:{}", pigeonnet_net::DEFAULT_PORT)
    }
}

fn list_peers(node: &Node) -> Result<()> {
    let peers = node.store().peers()?;
    if peers.is_empty() {
        println!("no peers configured — try: nodectl peer add hub.example.net");
        return Ok(());
    }
    for peer in peers {
        println!("{}", peer.address);
        match peer.node_id {
            Some(id) => println!("  identity   {id}"),
            None => println!("  identity   not yet pinned"),
        }
        match peer.last_sync_at {
            Some(at) => println!("  last sync  {}", render::iso8601(at)),
            None => println!("  last sync  never"),
        }
        if let Some(error) = peer.last_error {
            println!("  last error {error}");
        }
    }
    Ok(())
}

/// A tokio runtime, built only where one is needed.
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")
}

fn run_sync(node: &Node, only: Option<&str>) -> Result<()> {
    let passphrase = passphrase()?;
    let local = node.node_id(&passphrase)?;
    let limits = *node.limits();

    let peers: Vec<_> = match only {
        Some(address) => {
            let address = with_default_port(address);
            node.store()
                .peers()?
                .into_iter()
                .filter(|p| p.address == address)
                .collect()
        }
        None => node.store().peers()?,
    };
    if peers.is_empty() {
        println!("no peers to sync with");
        return Ok(());
    }

    let runtime = runtime()?;
    for peer in peers {
        let now = now_millis()?;
        print!("{} ... ", peer.address);
        use std::io::Write as _;
        std::io::stdout().flush().ok();

        let result = runtime.block_on(pigeonnet_net::sync_peer(
            node,
            local,
            &peer.address,
            peer.node_id,
            limits,
            now,
        ));

        match result {
            Ok(report) => {
                if let Some(proved) = report.peer {
                    node.store().peer_pin(&peer.address, proved)?;
                }
                node.store().peer_record_sync(&peer.address, now, None)?;
                let direction = if report.offered {
                    "both ways"
                } else {
                    "pull only"
                };
                println!("{} objects, {direction}", report.accepted);
            }
            Err(error) => {
                // Recorded rather than only printed: a peer that has been
                // failing for a week is worth seeing in `peer list`.
                node.store()
                    .peer_record_sync(&peer.address, now, Some(&error.to_string()))?;
                println!("failed: {error}");
            }
        }
    }
    Ok(())
}

fn run_serve(node: &Node, listen: &str, reciprocate: bool) -> Result<()> {
    let passphrase = passphrase()?;
    let local = node.node_id(&passphrase)?;
    let limits = *node.limits();

    let runtime = runtime()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding {listen}"))?;
        println!("listening on {listen}");
        println!("identity   {local}");
        println!("serving    public areas and identity snapshots to anyone;");
        println!("           inboxes only to their owner (\u{a7}15.4)");
        if reciprocate {
            println!("           and pulling from whoever connects, so peers behind");
            println!("           a firewall can publish (--serve-only to stop)");
        }
        pigeonnet_net::serve(node, local, &listener, limits, reciprocate, || {
            now_millis().unwrap_or(0)
        })
        .await
        .context("serving")
    })
}

fn show_inbox(node: &Node) -> Result<()> {
    let messages = node.inbox(&passphrase()?, now_millis()?)?;
    if messages.is_empty() {
        println!("inbox is empty");
        return Ok(());
    }
    for message in messages {
        let secrecy = match message.fs {
            pigeonnet_core::ForwardSecrecy::Epoch => "forward-secret",
            pigeonnet_core::ForwardSecrecy::None => "NOT forward-secret",
        };
        println!(
            "{}  {}",
            render::iso8601(message.timestamp.as_millis()),
            message.id
        );
        println!("  from     {}", message.sender);
        println!("  secrecy  {secrecy}");
        match message.body {
            pigeonnet_node::MessageBody::Opened(text) => {
                println!();
                for line in text.lines() {
                    println!("  {line}");
                }
            }
            pigeonnet_node::MessageBody::Expired => {
                println!(
                    "  (the epoch this was sealed to has been destroyed \u{2014} gone for good)"
                );
            }
            pigeonnet_node::MessageBody::NotForThisDevice => {
                println!("  (sealed to another of your devices)");
            }
            pigeonnet_node::MessageBody::Unreadable => {
                println!("  (could not be opened)");
            }
        }
        println!();
    }
    Ok(())
}
