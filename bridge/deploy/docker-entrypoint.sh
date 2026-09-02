#!/bin/sh
# attest-bridge container entrypoint.
#
# On targets that mount bridge.toml / key-manifest.json / issuer.seed /
# issuer.mldsa.json directly as files before the container starts (Docker
# Compose's bind mounts, Fly.io's `[[files]]`), the four *_B64 env vars below
# are unset and every block here is a no-op: this script falls straight
# through to the real command, unchanged from a plain
# `ENTRYPOINT ["attest-bridge", "serve", ...]`.
#
# On targets with no way to mount a file at a fixed path before the first
# boot (Render: Secret Files always land at a fixed /etc/secrets/<filename>,
# not the /etc/attest-bridge/... or /secrets/... paths below, and a
# persistent Disk starts empty with no non-shell way to seed it — see
# bridge/docs/deploy.md's Render section), set the matching *_B64 env var
# (base64 of the file's content, `base64 < bridge.toml`) as a regular env var
# instead; this script decodes it to the exact path the `attest-bridge serve`
# invocation below expects, before that command ever runs — so the very
# first deploy comes up healthy, with no shell/SCP step and no crash loop.
#
# Whichever of those two shapes a target takes, the SERVER never runs as root:
# this script starts privileged only long enough to decode that material and to
# take ownership of a freshly mounted (root-owned) Ledger volume, then drops to
# the image's unprivileged account with setpriv before exec'ing the bridge. A
# container that is already unprivileged skips both steps and execs directly.
set -eu

# The account bridge/deploy/Dockerfile creates. Numeric, and quoted in
# bridge/docs/deploy.md, because a merchant bind-mounting keys from a host
# chowns them to a number: `chown -R 10001:10001 etc secrets`.
BRIDGE_UID=10001
BRIDGE_GID=10001

# The image's data directory and the mount point every deploy template uses.
LEDGER_DIR=/var/lib/attest-bridge

# Every file materialized below holds secret or trust material. umask 077 makes
# each created file 0600 from its first byte (not dependent on the image umask),
# and materialize() decodes to a temp path then atomically renames into place, so
# a failed/partial `base64 -d` never leaves readable bytes at the real path.
umask 077

# materialize <dest-path> <base64-content>: decode (tolerant of GNU line-wrapped
# base64) into a unique sibling temp file created 0600 by mktemp, then atomic
# rename into place. A failed decode removes the temp and aborts, so no partial
# or predictably-named file is left at (or beside) the real path, and the write
# never follows a pre-placed symlink. No secret is ever printed.
#
# The file stays 0600, so when this script is running as root the account that
# will actually read it has to be given it — otherwise the bridge starts
# unprivileged and cannot open its own signing key. The chown happens while the
# file is still only readable by its owner: the mode never widens.
materialize() {
    dest="$1"
    dir="$(dirname "$dest")"
    mkdir -p "$dir"
    tmp="$(mktemp "$dir/.attest-bridge.XXXXXX")"
    if ! printf '%s' "$2" | base64 -d > "$tmp"; then
        rm -f "$tmp"
        echo "attest-bridge entrypoint: failed to decode material for $dest" >&2
        exit 1
    fi
    mv "$tmp" "$dest"
    if [ "$(id -u)" = 0 ]; then
        chown "$BRIDGE_UID:$BRIDGE_GID" "$dest" "$dir"
    fi
}

if [ -n "${BRIDGE_TOML_B64:-}" ]; then
    materialize /etc/attest-bridge/bridge.toml "$BRIDGE_TOML_B64"
fi

if [ -n "${KEY_MANIFEST_B64:-}" ]; then
    materialize /etc/attest-bridge/key-manifest.json "$KEY_MANIFEST_B64"
fi

if [ -n "${ISSUER_SEED_B64:-}" ]; then
    materialize /secrets/issuer.seed "$ISSUER_SEED_B64"
fi

if [ -n "${ISSUER_MLDSA_B64:-}" ]; then
    materialize /secrets/issuer.mldsa.json "$ISSUER_MLDSA_B64"
fi

# Drop the decoded material from the environment before handing off to the
# long-lived server: an inherited *_B64 var would otherwise expose full copies
# of the signing key and config via /proc/<pid>/environ for the service
# lifetime. After this the bridge reads the signing key only from its 0600 file.
unset BRIDGE_TOML_B64 KEY_MANIFEST_B64 ISSUER_SEED_B64 ISSUER_MLDSA_B64

# The one command this script exists to run. Built as argv so the privilege
# drop below can wrap it without a second, drift-prone copy of it.
set -- attest-bridge serve --config /etc/attest-bridge/bridge.toml --host 0.0.0.0 --port 8080

if [ "$(id -u)" = 0 ]; then
    # A volume or disk mounted here for the first time (Fly.io, Render) arrives
    # owned by root, and the unprivileged bridge could not create the Ledger in
    # it. Recursive because a live Ledger in WAL is three files. If it is not
    # there at all, say nothing: refusing to start with a clear message about
    # the missing directory is the Ledger's own job (an unmounted volume must
    # never be papered over with an empty database).
    if [ -d "$LEDGER_DIR" ]; then
        chown -R "$BRIDGE_UID:$BRIDGE_GID" "$LEDGER_DIR" || echo \
            "attest-bridge entrypoint: could not give $LEDGER_DIR to uid $BRIDGE_UID" >&2
    fi

    # Refuse rather than fall through: a bridge that keeps running as root
    # because a tool was missing is the exact outcome dropping privileges
    # exists to prevent, and it would be invisible.
    if ! command -v setpriv > /dev/null 2>&1; then
        echo "attest-bridge entrypoint: setpriv is missing from this image —" \
             "refusing to run the bridge as root" >&2
        exit 1
    fi
    set -- setpriv --reuid="$BRIDGE_UID" --regid="$BRIDGE_GID" \
                   --init-groups --no-new-privs -- "$@"
fi

exec "$@"
