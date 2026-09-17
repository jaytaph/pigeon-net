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

    /// Post to an echo area.
    Post {
        /// The area, e.g. GOSUB.DEV
        area: String,
        /// What to say.
        content: String,
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
