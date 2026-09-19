//! `nodectl` — the Pigeonnet command line interface (§27).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// Write a line to stdout, exiting quietly if the reader has gone away.
///
/// `println!` panics on a closed pipe, so `nodectl echo read AREA | head` would
/// end in a backtrace. A command-line tool piped into `head` or `less` must stop,
/// not complain. We cannot restore the default `SIGPIPE` handler because that
/// needs `unsafe`, and the workspace forbids it -- so the write is checked
/// instead.
macro_rules! out {
    () => { out!("") };
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if let Err(error) = writeln!(std::io::stdout(), $($arg)*)
            && error.kind() == std::io::ErrorKind::BrokenPipe
        {
            std::process::exit(0);
        }
    }};
}

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
        /// Claim a different creation time: `-3d`, `-90m`, `+2h`, or raw
        /// milliseconds. Useful for seeding; see the note in `--help`.
        // `allow_hyphen_values`, or clap reads `-3d` as an unknown flag.
        #[arg(long, value_name = "WHEN", allow_hyphen_values = true)]
        at: Option<String>,
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

    /// This identity's own profile (§5.6).
    #[command(subcommand)]
    Profile(ProfileCommand),

    /// Local labels for other identities. Never published (§5.2).
    #[command(subcommand)]
    Name(NameCommand),

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

    /// Epoch prekeys for this device (§8.1, D16).
    #[command(subcommand)]
    Prekeys(PrekeyCommand),

    /// Reply to a post, inheriting its area and thread.
    Reply {
        /// The post being replied to.
        parent: String,
        /// What to say.
        content: String,
        /// Claim a different creation time. Same format as `post --at`.
        // `allow_hyphen_values`, or clap reads `-3d` as an unknown flag.
        #[arg(long, value_name = "WHEN", allow_hyphen_values = true)]
        at: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ProfileCommand {
    /// Publish what this identity calls itself.
    ///
    /// Self-asserted, and shown to others with that caveat attached. It is not a
    /// name anyone else has agreed to -- that is `NameGranted`, and it is M8.
    SetName {
        /// The display name.
        name: String,
    },
    /// Clear the published display name.
    ClearName,
}

#[derive(Subcommand, Debug)]
enum NameCommand {
    /// Label an identity, for this node only.
    Set {
        /// The identity.
        identity: String,
        /// What to call them.
        label: String,
    },
    /// Forget a label.
    Remove {
        /// The identity.
        identity: String,
    },
    /// Show every local label.
    List,
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
enum PrekeyCommand {
    /// Publish prekeys for the epochs this node can still derive.
    Publish {
        /// How many epochs ahead to cover. Capped by the derivation window (D16).
        #[arg(long, default_value_t = 14)]
        lookahead: u64,
    },
    /// Show the current derivation window and when it runs out.
    Status,
    /// Open the next derivation window, using the cold prekey seed (D16).
    ///
    /// The seed is read from standard input, never from an argument: anything in
    /// argv is readable by every process on the machine.
    OpenWindow {
        /// Open the window containing this epoch. Defaults to the one after the
        /// current window, which is what a quarterly rotation wants.
        #[arg(long)]
        epoch: Option<u64>,
    },
    /// Give an identity created before D16 a cold seed and a usable window.
    ///
    /// For a keystore whose window predates the move from daily to weekly epochs
    /// and so covers nothing reachable. Generates a cold half, shows it once, and
    /// anchors a window at the current epoch. Prekeys published under the old
    /// numbering are already unusable and stay that way.
    Reanchor,
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
    /// Show areas, with what this node holds in each.
    List {
        /// Include areas held but not subscribed to.
        #[arg(long)]
        all: bool,
    },
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
        /// Date the identity earlier, so posts can be backdated into its
        /// lifetime: `-60d`, or raw milliseconds.
        ///
        /// A device key cannot sign objects from before it was granted, so an
        /// identity created today can never hold a post dated last week. This is
        /// for seeding a node with plausible history; it has no other use.
        #[arg(long, value_name = "WHEN", allow_hyphen_values = true)]
        at: Option<String>,
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
        Command::Identity(IdentityCommand::Create { name, at }) => {
            create_identity(&node, name.as_deref(), resolve_when(at.as_deref())?)
        }
        Command::Identity(IdentityCommand::Show) => show_identity(&node),
        Command::Object(ObjectCommand::Show { id }) => show_object(&node, &id),
        Command::Bundle(BundleCommand::Export { path, peer }) => {
            export_bundle(&node, &path, peer.as_deref())
        }
        Command::Bundle(BundleCommand::Import { path }) => import_bundle(&node, &path),
        Command::Echo(EchoCommand::Subscribe { area }) => {
            node.subscribe(&parse_area(&area)?)?;
            out!("subscribed to echo://{area}");
            Ok(())
        }
        Command::Echo(EchoCommand::Unsubscribe { area }) => {
            node.unsubscribe(&parse_area(&area)?)?;
            out!("unsubscribed from echo://{area}");
            Ok(())
        }
        Command::Echo(EchoCommand::List { all }) => list_areas(&node, all),
        Command::Echo(EchoCommand::Read { area }) => read_area(&node, &parse_area(&area)?),
        Command::Post { area, content, at } => {
            let when = resolve_when(at.as_deref())?;
            let id = node.post(&parse_area(&area)?, &content, &passphrase()?, when)?;
            report_created(id, at.is_some(), when);
            Ok(())
        }
        Command::Peer(PeerCommand::Add { address, expect }) => {
            let address = with_default_port(&address);
            let expect = expect
                .map(|text| NodeId::parse(&text).map_err(|e| anyhow::anyhow!("{e}")))
                .transpose()?;
            node.store().peer_add(&address, expect, now_millis()?)?;
            match expect {
                Some(id) => out!("added {address}, requiring {id}"),
                None => out!("added {address}; its identity pins on first sync"),
            }
            Ok(())
        }
        Command::Peer(PeerCommand::Remove { address }) => {
            let address = with_default_port(&address);
            if node.store().peer_remove(&address)? {
                out!("removed {address}");
            } else {
                out!("no such peer: {address}");
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
            out!("created  {id}");
            out!("queued   for the next sync");
            Ok(())
        }
        Command::Inbox => show_inbox(&node),
        Command::Profile(ProfileCommand::SetName { name }) => {
            let id = node.publish_profile(Some(name.clone()), &passphrase()?, now_millis()?)?;
            out!("published {id}");
            out!("others will see  {name}  (self-asserted)");
            Ok(())
        }
        Command::Profile(ProfileCommand::ClearName) => {
            let id = node.publish_profile(None, &passphrase()?, now_millis()?)?;
            out!("published {id}");
            out!("display name cleared");
            Ok(())
        }
        Command::Name(NameCommand::Set { identity, label }) => {
            let identity = parse_identity(&identity)?;
            node.set_local_name(identity, &label, now_millis()?)?;
            out!("{identity}");
            out!("  is now, to this node only: {label}");
            Ok(())
        }
        Command::Name(NameCommand::Remove { identity }) => {
            let identity = parse_identity(&identity)?;
            if node.remove_local_name(identity)? {
                out!("label removed");
            } else {
                out!("no label for that identity");
            }
            Ok(())
        }
        Command::Name(NameCommand::List) => {
            let names = node.local_names()?;
            if names.is_empty() {
                out!("no local labels -- try: nodectl name set <identity> <label>");
            }
            for (identity, label) in names {
                out!("{label:<20} {identity}");
            }
            Ok(())
        }
        Command::Expire => {
            let destroyed = node.destroy_expired_prekeys(&passphrase()?, now_millis()?)?;
            match destroyed {
                0 => out!("nothing has expired yet"),
                n => out!("destroyed {n} epoch secrets; messages sealed to them are gone"),
            }
            Ok(())
        }
        Command::Resolve { identity } => show_resolved(&node, &identity),
        Command::Prekeys(command) => run_prekeys(&node, command),
        Command::Reply {
            parent,
            content,
            at,
        } => {
            let parent = ObjectId::parse(&parent).map_err(|e| anyhow::anyhow!("{e}"))?;
            let when = resolve_when(at.as_deref())?;
            let id = node.reply(parent, &content, &passphrase()?, when)?;
            report_created(id, at.is_some(), when);
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

fn create_identity(node: &Node, name: Option<&str>, when: i64) -> Result<()> {
    let passphrase = passphrase()?;
    let created = node.create_identity(&passphrase, when)?;

    out!("Generating root key      ed25519 ........ ok");
    out!("Generating recovery key  ed25519 ........ ok");
    out!("Generating identity key  x25519  ........ ok");
    out!("Writing genesis object   IdentityCreated  ok");
    out!();
    out!("  Your identity is");
    out!("      {}", created.identity);
    out!();
    out!("  Fingerprint (read this aloud to verify in person)");
    for line in render::fingerprint(created.identity.as_bytes()) {
        out!("      {line}");
    }
    out!();
    out!(
        "Granting device key      {:<16} ok",
        name.unwrap_or("this-device")
    );
    out!("Locking keystore         argon2id         ok");
    out!();
    out!("  \u{26a0}  RECOVERY KEY — write this down, on paper, now.");
    out!();
    out!(
        "      {}",
        render::recovery_phrase(&created.recovery_secret)
    );
    out!();
    out!("     Not stored on this machine. Will not be shown again.");
    out!("     Without it, a lost or stolen root key ends this identity.");
    out!();
    out!("  \u{26a0}  COLD PREKEY SEED — write this down too (D16).");
    out!();
    out!(
        "      {}",
        render::recovery_phrase(&created.cold_prekey_seed)
    );
    out!();
    out!("     Also not stored here. Unlike the recovery key you will need this");
    out!("     roughly every quarter, to open the next derivation window:");
    out!("         nodectl prekeys open-window   < your-cold-seed-file");
    out!("     It is what stops a copy of this node's keystore decrypting");
    out!("     everything anyone sends you from now on.");
    out!();
    if when < now_millis()? - 60_000 {
        out!(
            "  dated        {}  (claimed, not proven)",
            render::iso8601(when)
        );
    }
    out!("  genesis      {}", created.genesis);
    out!("  device grant {}", created.device_grant);
    Ok(())
}

fn run_prekeys(node: &Node, command: PrekeyCommand) -> Result<()> {
    let passphrase = passphrase()?;
    match command {
        PrekeyCommand::Publish { lookahead } => {
            let published = node.publish_prekeys(&passphrase, now_millis()?, lookahead)?;
            match published.len() {
                0 => out!("already covered; nothing to publish"),
                n => out!(
                    "published {n} epoch prekeys, epochs {}..={}",
                    published.first().copied().unwrap_or(0),
                    published.last().copied().unwrap_or(0)
                ),
            }
            let (_, end) = node.prekey_window(&passphrase)?;
            let now_epoch = Node::epoch_at(now_millis()?);
            out!(
                "window ends at epoch {end}, {} epochs from now",
                end.saturating_sub(now_epoch)
            );
            Ok(())
        }
        PrekeyCommand::Status => {
            let (first, end) = node.prekey_window(&passphrase)?;
            let now_epoch = Node::epoch_at(now_millis()?);
            out!("epoch now     {now_epoch}");
            out!(
                "window        {first}..{end}  ({} epochs)",
                pigeonnet_node::EPOCHS_PER_WINDOW
            );
            match node.previous_prekey_window(&passphrase)? {
                Some((p_first, p_end)) => {
                    out!("retained      {p_first}..{p_end}  (outgoing, still within retention)")
                }
                None => out!("retained      none"),
            }
            // A window that does not contain the current epoch cannot be
            // described in terms of "remaining", and saying so plainly beats
            // printing a number that happens to be enormous.
            if !node.prekey_window_covers(&passphrase, now_epoch)? {
                out!();
                out!("This window does not cover the current epoch, so this node");
                out!("cannot publish prekeys or open anything sealed to it now.");
                if now_epoch < first {
                    out!();
                    out!("The stored window is far ahead of the clock, which is what a");
                    out!("keystore written before epochs became weekly looks like (D16).");
                    out!("  nodectl prekeys reanchor");
                } else {
                    out!("  nodectl prekeys open-window   < cold-seed-file");
                }
                return Ok(());
            }

            let left = end.saturating_sub(now_epoch);
            out!(
                "remaining     {left} epoch(s), about {} day(s)",
                left.saturating_mul(7)
            );
            out!();
            if left == 0 {
                out!("This window is spent. Until the next one is opened, senders");
                out!("fall back to the static identity key (fs: none, \u{a7}8.1).");
                out!("  nodectl prekeys open-window   < cold-seed-file");
            } else {
                out!("Opening the next window needs the cold prekey seed, which is");
                out!("not on this machine. That is the point (D16).");
            }
            Ok(())
        }
        PrekeyCommand::OpenWindow { epoch } => {
            let (_, current_end) = node.prekey_window(&passphrase)?;
            let target = epoch.unwrap_or(current_end);

            let cold = read_cold_seed()?;
            let (first, end) = node.open_prekey_window(&cold, target, &passphrase)?;
            out!("opened window {first}..{end}");
            out!("Publish into it with: nodectl prekeys publish");
            Ok(())
        }
        PrekeyCommand::Reanchor => {
            let now = now_millis()?;
            let now_epoch = Node::epoch_at(now);
            if node.prekey_window_covers(&passphrase, now_epoch)? {
                bail!(
                    "this node's window already covers epoch {now_epoch}; \
                     use `prekeys open-window` to rotate, which keeps the outgoing window"
                );
            }

            let cold = pigeonnet_node::ColdSeed::generate()?;
            let (first, end) = node.reanchor_prekeys(&cold, now_epoch, &passphrase)?;

            out!("  \u{26a0}  NEW COLD PREKEY SEED — write this down, on paper, now.");
            out!();
            out!("      {}", render::recovery_phrase(&cold.as_bytes()));
            out!();
            out!("     Not stored on this machine. Will not be shown again.");
            out!("     You will need it about every quarter, to open the next window.");
            out!();
            out!("anchored window {first}..{end}");
            out!("Publish into it with: nodectl prekeys publish");
            Ok(())
        }
    }
}

/// Read the cold prekey seed from standard input.
///
/// Not an argument: argv is world-readable. Accepts the base32 form shown at
/// genesis, with or without the spaces it is grouped into for transcription.
fn read_cold_seed() -> Result<pigeonnet_node::ColdSeed> {
    use std::io::Read as _;
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .context("reading the cold prekey seed from stdin")?;
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        bail!("no cold prekey seed on stdin");
    }
    let bytes = pigeonnet_core::base32::decode(&cleaned)
        .context("that is not a base32 cold prekey seed")?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("a cold prekey seed is 32 bytes, got {}", bytes.len()))?;
    Ok(pigeonnet_node::ColdSeed::from_bytes(seed))
}

fn show_identity(node: &Node) -> Result<()> {
    let passphrase = passphrase()?;
    let keyring = node.keyring(&passphrase)?;

    // Which identity is *ours* is recorded when it is created, not inferred from
    // the store. A node that has synced holds other people's genesis objects
    // too, and they are indistinguishable from its own -- scanning for one
    // returns whichever happens to sort first, which is wrong the moment the
    // node talks to anybody.
    let state = node.identity_state(node.local_identity()?)?;

    out!("identity      {}", state.id());
    out!("genesis       {}", state.id().genesis_object());
    out!("root key      {}", state.root_key());
    out!(
        "recovery key  {}   (private half is on paper only)",
        state.recovery_key()
    );
    out!("agreement key {}", state.agreement_key());
    out!();
    let device = keyring.device().public();
    match state.capabilities_of(device) {
        Some(capabilities) => out!("this device   {device}\n              {capabilities:?}"),
        None => out!("this device   {device}\n              not delegated"),
    }
    out!();
    out!("objects held  {}", node.store().len()?);

    // A keystore sealed with test parameters is readable by anyone holding the
    // file. Nothing else about a node would ever mention it, so it is said here.
    let params = node.keystore_params()?;
    if !params.is_production() {
        out!();
        out!(
            "\u{26a0}  keystore sealed with WEAK parameters ({} KiB, {} iterations).",
            params.memory_kib,
            params.iterations
        );
        out!("   Guessing this passphrase is cheap. Do not use this identity for");
        out!("   anything that matters.");
    }
    Ok(())
}

fn show_object(node: &Node, id: &str) -> Result<()> {
    let id = ObjectId::parse(id).map_err(|e| anyhow::anyhow!("{e}"))?;
    let object = node
        .object(id)?
        .context("object not found in this node's store")?;
    let tbs = object.tbs()?;

    out!("id            {}", object.id());
    out!("version       {}", tbs.version);
    match tbs.object_type() {
        Ok(t) => out!("type          {t:?} ({})", tbs.type_code),
        Err(_) => out!(
            "type          unknown ({}) — storable and relayable",
            tbs.type_code
        ),
    }
    out!(
        "author        {}",
        if tbs.is_genesis() {
            "(genesis — this object creates the identity)".to_string()
        } else {
            tbs.author.to_string()
        }
    );
    out!("signing key   {}", tbs.signing_key);
    out!(
        "timestamp     {} ({})",
        render::iso8601(tbs.timestamp.as_millis()),
        tbs.timestamp.as_millis()
    );
    out!("sequence      {}", tbs.sequence);
    out!("payload       {} bytes", tbs.payload.len());
    out!("signature     {}", object.signature());

    if tbs.object_type() == Ok(pigeonnet_core::ObjectType::IdentityCreated)
        && let Ok(payload) = IdentityCreated::decode_payload(&tbs.payload)
    {
        out!();
        out!("  root key      {}", payload.root_key);
        out!("  recovery key  {}", payload.recovery_key);
        out!("  agreement key {}", payload.agreement_key);
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

    out!("  objects   {}", node.store().len()?);
    out!("  origin    {origin}");
    out!("  size      {} bytes", bytes.len());
    out!("  written to {}", path.display());
    Ok(())
}

fn import_bundle(node: &Node, path: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let (report, requests) = node.import_bundle(&bytes, now_millis()?)?;

    out!("  {} objects accepted", report.accepted);
    out!("  {} already held", report.already_held);
    out!("  {} cursors advanced", report.cursors_advanced);
    if !requests.is_empty() {
        out!();
        out!("  the sender is missing everything after:");
        for request in requests {
            out!("    {:?} after {}", request.stream, request.after);
        }
    }
    Ok(())
}

fn parse_area(text: &str) -> Result<pigeonnet_core::AreaName> {
    pigeonnet_core::AreaName::parse(text).map_err(|e| anyhow::anyhow!("{e}"))
}

fn read_area(node: &Node, area: &pigeonnet_core::AreaName) -> Result<()> {
    let now = now_millis()?;
    let posts = node.read_area(area)?;
    if posts.is_empty() {
        out!("echo://{area} is empty");
        return Ok(());
    }
    for post in posts {
        let indent = "  ".repeat(post.depth);
        out!(
            "{indent}{}  {}",
            render::iso8601(post.timestamp.as_millis()),
            post.id
        );
        out!("{indent}  from {}", who(node, post.author, now));
        for line in post.post.content.lines() {
            out!("{indent}  {line}");
        }
        out!();
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

    out!("identity      {}", resolved.state.id());
    if let Some(profile) = &resolved.profile
        && let Some(name) = &profile.display_name
    {
        out!("calls itself  {name}   (self-asserted; not a bound name)");
    }
    out!("root key      {}", resolved.state.root_key());
    out!(
        "usable until  {}   (clamped to its contents, not the server's claim)",
        render::iso8601(resolved.valid_until.as_millis())
    );
    out!();

    out!("prekeys       {}", resolved.prekeys.len());
    let mut prekeys = resolved.prekeys.clone();
    prekeys.sort_by_key(|(_, prekey)| prekey.epoch);
    for (device, prekey) in &prekeys {
        out!(
            "  epoch {:<6} until {}  device {}",
            prekey.epoch,
            render::iso8601(prekey.valid_until.as_millis()),
            &device.to_string()[..24]
        );
    }
    out!();

    if resolved.carriers.is_empty() {
        out!("carriers      none confirmed");
    } else {
        out!("carriers      {} confirmed", resolved.carriers.len());
        for carrier in &resolved.carriers {
            out!("  cost {:<4} {}", carrier.cost, carrier.node);
        }
    }
    for carrier in &resolved.unconfirmed {
        out!(
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
        out!("no peers configured — try: nodectl peer add hub.example.net");
        return Ok(());
    }
    for peer in peers {
        out!("{}", peer.address);
        match peer.node_id {
            Some(id) => out!("  identity   {id}"),
            None => out!("  identity   not yet pinned"),
        }
        match peer.last_sync_at {
            Some(at) => out!("  last sync  {}", render::iso8601(at)),
            None => out!("  last sync  never"),
        }
        if let Some(error) = peer.last_error {
            out!("  last error {error}");
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
        out!("no peers to sync with");
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
                out!("{} objects, {direction}", report.accepted);
            }
            Err(error) => {
                // Recorded rather than only printed: a peer that has been
                // failing for a week is worth seeing in `peer list`.
                node.store()
                    .peer_record_sync(&peer.address, now, Some(&error.to_string()))?;
                out!("failed: {error}");
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
        out!("listening on {listen}");
        out!("identity   {local}");
        out!("serving    public areas and identity snapshots to anyone;");
        out!("           inboxes only to their owner (\u{a7}15.4)");
        if reciprocate {
            out!("           and pulling from whoever connects, so peers behind");
            out!("           a firewall can publish (--serve-only to stop)");
        }
        pigeonnet_net::serve(node, local, &listener, limits, reciprocate, || {
            now_millis().unwrap_or(0)
        })
        .await
        .context("serving")
    })
}

fn show_inbox(node: &Node) -> Result<()> {
    let now = now_millis()?;
    let messages = node.inbox(&passphrase()?, now)?;
    if messages.is_empty() {
        out!("inbox is empty");
        return Ok(());
    }
    for message in messages {
        let secrecy = match message.fs {
            pigeonnet_core::ForwardSecrecy::Epoch => "forward-secret",
            pigeonnet_core::ForwardSecrecy::None => "NOT forward-secret",
        };
        out!(
            "{}  {}",
            render::iso8601(message.timestamp.as_millis()),
            message.id
        );
        out!("  from     {}", who(node, message.sender, now));
        out!("  secrecy  {secrecy}");
        match message.body {
            pigeonnet_node::MessageBody::Opened(text) => {
                out!();
                for line in text.lines() {
                    out!("  {line}");
                }
            }
            pigeonnet_node::MessageBody::Expired => {
                out!("  (the epoch this was sealed to has been destroyed \u{2014} gone for good)");
            }
            pigeonnet_node::MessageBody::NotForThisDevice => {
                out!("  (sealed to another of your devices)");
            }
            pigeonnet_node::MessageBody::Unreadable => {
                out!("  (could not be opened)");
            }
        }
        out!();
    }
    Ok(())
}

fn parse_identity(text: &str) -> Result<pigeonnet_core::IdentityId> {
    pigeonnet_core::IdentityId::parse(text).map_err(|e| anyhow::anyhow!("{e}"))
}

/// How to show who authored something.
///
/// A local label stands alone -- it is this operator's own and needs no caveat. A
/// self-asserted one always carries the caveat, because nobody but its owner
/// vouches for it. With neither, the identifier is the name.
fn who(node: &Node, identity: pigeonnet_core::IdentityId, now: i64) -> String {
    match node.naming(identity, now) {
        Ok(naming) => match naming.best() {
            Some(label) if naming.best_is_asserted() => {
                format!("{label} (self-asserted)  {identity}")
            }
            Some(label) => format!("{label}  {identity}"),
            None => identity.to_string(),
        },
        Err(_) => identity.to_string(),
    }
}

/// Resolve an optional `--at` into a timestamp, defaulting to now.
fn resolve_when(at: Option<&str>) -> Result<i64> {
    let now = now_millis()?;
    match at {
        None => Ok(now),
        Some(text) => render::parse_when(text, now).map_err(|e| anyhow::anyhow!("{e}")),
    }
}

fn report_created(id: pigeonnet_core::ObjectId, backdated: bool, when: i64) {
    out!("created  {id}");
    if backdated {
        // Stated, not buried. The timestamp is what the author claims, and a
        // reader has no way to check it.
        out!("dated    {}  (claimed, not proven)", render::iso8601(when));
    }
    out!("queued   for subscribed peers");
}

fn list_areas(node: &Node, all: bool) -> Result<()> {
    let mut stats = node.area_stats()?;
    if !all {
        stats.retain(|s| s.subscribed);
    }
    if stats.is_empty() {
        out!("no areas -- try: nodectl echo subscribe GOSUB.DEV");
        return Ok(());
    }

    // Newest activity first: what changed recently is what you want to read.
    stats.sort_by(|a, b| b.latest.cmp(&a.latest).then_with(|| a.area.cmp(&b.area)));

    out!(
        "{:<22} {:>6} {:>8} {:>7} {:>12} {:>12}",
        "AREA",
        "POSTS",
        "THREADS",
        "VOICES",
        "EARLIEST",
        "LATEST"
    );
    let mut unsubscribed = false;
    for s in &stats {
        let mark = if s.subscribed { ' ' } else { '-' };
        unsubscribed |= !s.subscribed;
        let (earliest, latest) = if s.posts == 0 {
            ("-".to_owned(), "-".to_owned())
        } else {
            (day(s.first_held), day(s.latest))
        };
        out!(
            "{mark}{:<21} {:>6} {:>8} {:>7} {:>12} {:>12}",
            s.area.as_str(),
            s.posts,
            s.threads,
            s.voices,
            earliest,
            latest
        );
    }
    if unsubscribed {
        out!();
        out!("- held, but not subscribed. `echo subscribe` to carry it deliberately.");
    }
    out!();
    // Said once rather than in a column heading nobody would read twice.
    out!("Counts are what this node holds, not what the area contains: another");
    out!("node carrying the same area will report different numbers, and neither");
    out!("is wrong. EARLIEST is the oldest post held, not when the area began --");
    out!("nothing creates an area except somebody posting to it.");
    Ok(())
}

/// Just the date part, which is all a listing needs.
fn day(at: pigeonnet_core::Timestamp) -> String {
    render::iso8601(at.as_millis()).chars().take(10).collect()
}
