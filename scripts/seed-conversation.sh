#!/usr/bin/env bash
#
# Seed two nodes with message boards and a few months of conversation, so there
# is something worth looking at. A development convenience, not part of the
# product.
#
# Posts are dated across the past twelve weeks with `--at`, so the boards read
# like history rather than one lunchtime. That requires both identities to
# predate the oldest post: a device key cannot sign an object from before it was
# granted. Create them with something like:
#
#     nodectl identity create --at -120d
#
# The script checks and refuses up front rather than failing halfway.
#
# Environment:
#   REMOTE=joshua@mac         the other node, over ssh
#   REMOTE=local:/path/home   or a second node on this machine, for testing
#   NODECTL=...               local binary
#   NODECTL_REMOTE=...        remote binary (defaults to NODECTL)
#   PIGEONNET_PASSPHRASE=...  local node
#   LEAF_PASSPHRASE=...       remote node
#
# Passphrases are never placed in a command line: the remote half travels over
# ssh's stdin, so it does not appear in the remote process list.
#
# Usage:  REMOTE=joshua@mac ./scripts/seed-conversation.sh
set -euo pipefail

REMOTE="${REMOTE:?set REMOTE, e.g. REMOTE=joshua@mac or REMOTE=local:/tmp/leaf}"
NODECTL="${NODECTL:-$HOME/code/pigeonnet/target/release/nodectl}"
NODECTL_REMOTE="${NODECTL_REMOTE:-$NODECTL}"
: "${PIGEONNET_PASSPHRASE:?set PIGEONNET_PASSPHRASE for the local node}"
: "${LEAF_PASSPHRASE:?set LEAF_PASSPHRASE for the remote node}"

# The oldest post below. Both identities must be at least this old.
OLDEST_DAYS=84

AREAS=(
    GOSUB.DEV
    PIGEONNET.DESIGN
    TECH.RUST
    TECH.CRYPTO
    RETRO.C64
    LOCAL.NETHERLANDS
    OFFTOPIC
)

hub() { "$NODECTL" "$@"; }

leaf() {
    if [[ "$REMOTE" == local:* ]]; then
        PIGEONNET_HOME="${REMOTE#local:}" PIGEONNET_PASSPHRASE="$LEAF_PASSPHRASE" \
            "$NODECTL_REMOTE" "$@"
        return
    fi
    local args=""
    for a in "$@"; do args+=" $(printf '%q' "$a")"; done
    # shellcheck disable=SC2087
    # Client-side expansion is deliberate: the passphrase and arguments are
    # substituted here and travel over ssh's stdin. Quoting EOF would send the
    # literal `$(printf ...)` for the remote shell to evaluate.
    ssh -o BatchMode=yes "$REMOTE" 'bash -s' <<EOF
export PIGEONNET_PASSPHRASE=$(printf '%q' "$LEAF_PASSPHRASE")
$(printf '%q' "$NODECTL_REMOTE")$args
EOF
}

id_of() { awk '/^created/{print $2; exit}'; }
say()   { printf '\n\033[1m%s\033[0m\n' "$*"; }

# hp AREA WHEN TEXT   -- hub posts, prints the object id
hp() { hub  post  "$1" --at "$2" "$3" | id_of; }
lp() { leaf post  "$1" --at "$2" "$3" | id_of; }
hr() { hub  reply "$1" --at "$2" "$3" | id_of; }
lr() { leaf reply "$1" --at "$2" "$3" | id_of; }

# A reply can only be written by a node that already holds its parent, so the
# script works in waves: roots, sync, first replies, sync, and so on. That is
# also far fewer round trips than syncing after every post.
sync_now() {
    if [[ "$REMOTE" == local:* ]]; then
        # Two nodes on one machine have no peer to dial, so carry bundles both
        # ways instead. Same objects, same checks, no socket.
        local tmp
        tmp=$(mktemp -d)
        hub  bundle export "$tmp/hub.pack"  >/dev/null
        leaf bundle import "$tmp/hub.pack"  >/dev/null
        leaf bundle export "$tmp/leaf.pack" >/dev/null
        hub  bundle import "$tmp/leaf.pack" >/dev/null
        rm -rf "$tmp"
    else
        # One outbound connection carries both directions.
        leaf sync >/dev/null
    fi
}

genesis_time() { # genesis_time hub|leaf -- millis, from `object show`
    local side="$1" gid
    gid=$($side identity show | awk '/^genesis/{print $2}')
    $side object show "$gid" | awk '/^timestamp/{gsub(/[()]/,"",$3); print $3}'
}

check_age() {
    local label="$1" created="$2" now age
    now=$(date +%s)000
    age=$(( (now - created) / 86400000 ))
    if [ "$age" -lt "$OLDEST_DAYS" ]; then
        printf 'refusing: the %s identity is %s days old, but the oldest post here\n' "$label" "$age" >&2
        printf 'is dated %s days back, and a device key cannot sign from before it\n' "$OLDEST_DAYS" >&2
        printf 'was granted. Recreate both nodes with:\n\n' >&2
        printf '    rm -rf ~/.pigeonnet && nodectl identity create --at -120d\n\n' >&2
        exit 1
    fi
    printf '  %-7s %s days old\n' "$label" "$age"
}

say "checking both identities predate the oldest post"
check_age local  "$(genesis_time hub)"
check_age remote "$(genesis_time leaf)"

say "subscribing both nodes to ${#AREAS[@]} areas"
for area in "${AREAS[@]}"; do
    hub  echo subscribe "$area" >/dev/null
    leaf echo subscribe "$area" >/dev/null
    printf '  echo://%s\n' "$area"
done
sync_now

# ---------------------------------------------------------------------------
# Wave 1 -- thread roots. No dependencies, so both nodes can write freely.
# ---------------------------------------------------------------------------
say "wave 1: opening posts"

g1=$(hp GOSUB.DEV -84d "Anyone else running a node on a Pi? Curious what the sync cost
looks like over a full day rather than a benchmark.")
g2=$(lp GOSUB.DEV -71d "Proposal: a subcommand to dump an area as mbox, for people
migrating off mailing lists.")
g3=$(hp GOSUB.DEV -52d "The keystore unlock is noticeably slow on the Pi. Argon2 at
64 MiB is about four seconds there. Not wrong, just surprising the first time.")
g4=$(lp GOSUB.DEV -24d "Small thing that has bitten me twice now: posting does not
send. It creates an object and stops. I keep expecting a network error when there
is no network, and getting silence instead.")

d1=$(hp PIGEONNET.DESIGN -80d "Long one, sorry. I want to write down why the
identity is the hash of the genesis object rather than a public key, because I
keep re-deriving it and I would like to stop.

The obvious design is: your identity IS your public key. It is short, it is
self-certifying, and verification needs no lookup. Every system that has tried
it ends up in the same place, which is that keys have to be replaceable. Hardware
fails, algorithms age, devices get stolen. So you add rotation.

And the moment you add rotation to a key-as-identity scheme, rotating the key
changes who you are. Every reference to you breaks: thread parents, contact
entries, membership records, signed introductions. The usual patch is a chain of
signed statements saying the new key speaks for the old one, which works, but now
your identity is really the chain and the key was never the identity at all.

So we may as well say that out loud. The identity is the genesis object, named by
its hash. Keys live inside it and can all be replaced. Nothing breaks, because
nothing ever pointed at a key.

The cost is that verification needs the chain, which is a real cost and not free.
But the chain is tiny, and anyone holding one of your objects needed it anyway.")
d2=$(lp PIGEONNET.DESIGN -66d "Question about the no-bounce rule. If I send to
someone whose carrier is down, I get nothing back. How am I supposed to tell that
from a message that arrived and was ignored?")
d3=$(hp PIGEONNET.DESIGN -40d "I have come round on the retention window. Thirty
days felt arbitrary when I wrote it. It is not arbitrary, it is just not derived
from anything yet, which is different and worse.")
d4=$(lp PIGEONNET.DESIGN -14d "Naming. I do not want a global directory and I also
do not want to read hashes aloud on the phone. Where does that leave us?")

r1=$(hp TECH.RUST -76d "Reminder that clippy indexing_slicing is worth turning on
for anything that parses bytes off a socket. It is noisy, and the noise is mostly
in tests, which you can allow per test crate.")
r2=$(lp TECH.RUST -48d "Has anyone found a decent pattern for sans-io state
machines where the transport needs a timeout? I keep wanting to put a clock in
the state machine and I know that is wrong.")
r3=$(hp TECH.RUST -19d "Writeup of a bug that took me an afternoon, in case it
saves someone else the time.

Symptom: a test passed on its own and failed about half the time in the suite. No
shared state, no filesystem collisions, no obvious ordering dependency.

Cause: the code replayed an identity's objects ordered by signing key, then by
sequence. That reads like causal order and is not. Key management is signed by
one key, content by another, and when the content key happened to sort below the
management key, a post replayed before the grant that authorised it. The chain
then looked like it contained a key it had never delegated.

The keys are randomly generated, so which one sorts first is a coin flip. Hence
half the time.

Fix was to replay key management only, where there is a single signer and
sequence order really is causal. Authority for everything else is checked when it
is read instead.

Lesson I am taking: lexicographic is not causal, and a sort that happens to work
is not a sort that works.")

c1=$(lp TECH.CRYPTO -63d "Does anyone else find the phrase forward secrecy
actively misleading? It is not a property of the cipher. It is a property of your
willingness to delete things.")
c2=$(hp TECH.CRYPTO -35d "One-time prekeys need a trusted dispenser and we do not
have one. I spent a while convinced this was a small problem.")
c3=$(lp TECH.CRYPTO -11d "What is the actual threat model for a leaked node
backup? I can argue myself into and out of caring.")

k1=$(lp RETRO.C64 -58d "Found a working 1541 at a flea market for twenty euro.
Belt perished, head fine, and the alignment was closer than it had any right to
be.")
k2=$(hp RETRO.C64 -33d "Does anyone have a clean scan of the 1571 service manual?
Every copy online is the same bad photocopy, third generation at least, and the
schematic pages are unreadable where it matters.")
k3=$(lp RETRO.C64 -9d "Restoration log, for anyone about to do the same thing.

Bought: breadbin C64, untested, described as powers on. It did power on, into a
black screen with the power LED at about half brightness, which is usually the
5 volt rail sagging.

Replaced the electrolytics on the board first because they were original and one
had already vented. That got a screen but with vertical bars, which points at
RAM. Piggybacking the 4164s found one that was warm to the touch. Socketed and
replaced it.

Then the classic: works cold, drops out after twenty minutes. That was the PLA,
which everybody warns you about and everybody still diagnoses last. A modern
replacement fixed it and runs cool.

Total: about thirty euro in parts, two evenings, one burnt fingertip. The fingertip
was the PLA telling me what was wrong and me not listening.")

n1=$(hp LOCAL.NETHERLANDS -55d "Is anyone here running a node with a public
address in NL? Looking for a second carrier that is not at the same provider as
my first.")
n2=$(lp LOCAL.NETHERLANDS -21d "Went to the retro computing meetup in Utrecht at
the weekend. Smaller than last year but better tables. Someone had an entire wall
of Amigas running a demo loop and would not explain the sync.")

o1=$(lp OFFTOPIC -60d "What is everyone reading? I am halfway through a book about
the history of the telegraph and it is uncomfortably familiar.")
o2=$(hp OFFTOPIC -29d "Unpopular opinion: the terminal is fine and I am tired of
pretending I want a dashboard.")
o3=$(lp OFFTOPIC -6d "The cat has learned that standing on the keyboard produces
attention. I have learned to lock the screen.")

sync_now

# ---------------------------------------------------------------------------
# Wave 2 -- direct replies. Each node now holds the others roots.
# ---------------------------------------------------------------------------
say "wave 2: replies"

g1a=$(lr "$g1" -83d "A 3B+ here, syncing hourly. The cursor means the cost is
proportional to what is new, so an idle hour is almost free. The first sync was
the expensive one.")
g1b=$(hr "$g1" -82d "Same shape for me. Worth saying the bottleneck was disk, not
CPU or network.")
hr "$g2" -70d "Worth doing, but it would need a loud lossy-conversion
warning. Threading is explicit here and reconstructed there, so a round trip
loses information." >/dev/null
lr "$g3" -51d "Four seconds is the parameters working. I would rather it be
slow on my Pi than fast on somebody elses GPU." >/dev/null
g4a=$(hr "$g4" -23d "That gap is deliberate but I agree the wording does not carry
it. Queued is doing a lot of work in that one line.")

lr "$d1" -79d "This is the clearest version of it I have read. The part that
convinced me is that the chain exists either way, so naming yourself by the key
buys nothing and costs every reference." >/dev/null
d1b=$(hr "$d1" -78d "One caveat I should have included: it makes a cold identity
harder to reach. A bare hash on paper is not resolvable unless somebody near you
already holds the chain.")
d2a=$(hr "$d2" -65d "You cannot tell, and that is honest rather than good. The
recipient reports failures it saw; silence stays ambiguous and your client has to
resolve it with a timeout. A bounce would mean every relay could be pointed at a
forged sender.")
d3a=$(lr "$d3" -39d "Derived from what, though? Worst-case delivery delay is not a
number anyone has measured.")
d4a=$(hr "$d4" -13d "Three tiers, and only the middle one is hard. A local nickname
costs nothing and cannot be forged because it never leaves your machine.")

lr "$r1" -75d "Agreed. We ended up allowing it in test crates rather than
globally, which keeps it meaningful on the paths that matter." >/dev/null
r2a=$(hr "$r2" -47d "Keep the timeout entirely in the transport. The machine has no
clock, which is exactly what lets you drive it from a script with a hostile peer
in it.")
lr "$r3" -18d "The last line is the useful part. I have shipped that exact
bug with a different sort key." >/dev/null

c1a=$(hr "$c1" -62d "It is a fair complaint. Every mechanism we added turned out to
be a deletion schedule wearing a hat.")
c2a=$(lr "$c2" -34d "Small how? Two senders picking the same key is a collision,
and the recipient deleting on first use loses the other message.")
c3a=$(hr "$c3" -10d "The part I find hard to dismiss is that a backup is a wiretap
on the future, not a window on the past, if the seed reaches forward.")

hr "$k1" -57d "Belts are still made. Replacing one is fifteen minutes if you
own the right screwdriver and an hour if you do not." >/dev/null
k2a=$(lr "$k2" -32d "I have a second generation copy, better than what is online
but still not good. Happy to scan it properly if someone can lend a flatbed with
a decent lid.")
hr "$k3" -8d "The PLA being diagnosed last is practically a tradition.
Excellent writeup." >/dev/null

n1a=$(lr "$n1" -54d "Two machines at one provider is one carrier with extra steps,
so this is the right question. I am on a different AS if you want to pair up.")
hr "$n2" -20d "The Amiga wall is the same person every year and he has never
once explained the sync." >/dev/null

hr "$o1" -59d "The Victorian Internet? It should be required reading, mostly
for the parts about fraud." >/dev/null
o2a=$(lr "$o2" -28d "I will take a dashboard the day one of them can be piped into
grep.")
hr "$o3" -5d "Mine sits on the laptop when it is closed and looks betrayed
when I open it." >/dev/null

sync_now

# ---------------------------------------------------------------------------
# Wave 3 -- replies to replies, so some threads go three deep.
# ---------------------------------------------------------------------------
say "wave 3: deeper replies"

hr "$g1a" -81d "Disk is interesting. WAL mode should help but I have not measured
it on an SD card, which is probably the real variable." >/dev/null
lr "$g1b" -81d "SD cards are the variable in everything on that hardware." >/dev/null
lr "$g4a" -22d "Something like created locally, will travel on the next sync?" >/dev/null
hr "$d1b" -77d "Every ordinary way of meeting someone already carries the chain
with the name, which is why it took so long to notice this was a gap at all." >/dev/null
lr "$d2a" -64d "Silence being ambiguous is fine. Silence being ambiguous and
undocumented is not, and that is the bit to fix." >/dev/null
hr "$d3a" -38d "That is the honest answer and it is why the number is still in the
open questions list rather than the decisions list." >/dev/null
lr "$d4a" -12d "The middle tier is where every other system has quietly built a
directory and then pretended it was not one." >/dev/null
hr "$r2a" -46d "Which also means the timeout is testable separately, at the one
layer that is allowed to know what a second is." >/dev/null
lr "$c1a" -61d "A deletion schedule wearing a hat is going in the documentation,
whether you like it or not." >/dev/null
hr "$c2a" -33d "Reordering is worse than collisions. One sender is enough: a
delayed first message arrives after a later one and the key is already gone." >/dev/null
lr "$c3a" -9d "Then the mitigation is not cryptography, it is keeping key material
out of backups in the first place." >/dev/null
hr "$k2a" -31d "I have a flatbed with a proper lid. Postage both ways is cheaper
than another decade of that photocopy." >/dev/null
lr "$n1a" -53d "Different AS is exactly what I was after. Sending you a message." >/dev/null
hr "$o2a" -27d "This is the whole argument and I have never seen it answered." >/dev/null

sync_now

say "done"
printf '\n'
hub echo list
printf '\nobjects: local %s, remote %s\n' \
    "$(hub identity show | awk '/objects held/{print $3}')" \
    "$(leaf identity show | awk '/objects held/{print $3}')"
printf 'try:  nodectl echo read PIGEONNET.DESIGN\n'
