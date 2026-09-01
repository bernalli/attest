FROM python:3.12
# python:3.12 (not -slim): pqcrypto ships C sources; the full image carries a toolchain
# for platforms without a prebuilt wheel. attest-receipts is the published PyPI package;
# attest-bridge installs from the repo checkout (it is NOT on PyPI — unreleased).
#
# Build context is the REPO ROOT, not this directory — the COPY below needs the whole
# bridge/ tree. From the repo root: `docker build -f bridge/deploy/Dockerfile -t attest-bridge .`
COPY bridge /opt/attest-bridge
RUN pip install --no-cache-dir /opt/attest-bridge && chmod +x /opt/attest-bridge/deploy/docker-entrypoint.sh

# The bridge holds an issuer's signing key and parses bodies anyone can reach
# (webhook payloads, the itch claim form). Nothing it does needs privilege, so
# the server runs as this account and never as root.
#
# The uid/gid is FIXED (10001) rather than assigned: a merchant bind-mounting
# their keys from a host chowns them to a NUMBER — a name that exists only
# inside the image is no help — and that number must not move between
# rebuilds. Both the entrypoint and bridge/docs/deploy.md quote it.
#
# The three directories are created here, owned by that account, so the image
# is coherent on its own: /etc/attest-bridge (config + key manifest), /secrets
# (signing keys), /var/lib/attest-bridge (the Ledger — also the mount point
# every deploy template uses, which is what makes a Docker named volume
# inherit this ownership when it is first created).
#
# There is deliberately no `USER` line: the ENTRYPOINT starts as root just
# long enough to take ownership of a freshly mounted, root-owned volume
# (Fly.io, Render) and then drops to this account with setpriv before exec'ing
# the server — the same shape the official postgres/redis images use. What
# must never happen is the SERVER running as root, and that is what
# bridge/tests/test_bridge_container.py pins.
RUN groupadd --system --gid 10001 attest \
 && useradd --system --uid 10001 --gid 10001 --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin attest \
 && mkdir -p /etc/attest-bridge /secrets /var/lib/attest-bridge \
 && chown attest:attest /etc/attest-bridge /secrets /var/lib/attest-bridge \
 && chmod 0750 /etc/attest-bridge \
 && chmod 0700 /secrets /var/lib/attest-bridge
EXPOSE 8080
# /etc/attest-bridge (config + manifest) and /secrets (keys, 0600) are read-only mounts
# on Docker Compose/Fly.io. docker-entrypoint.sh additionally knows how to materialize
# both from base64 env vars, for targets (Render) with no way to mount a file at a
# fixed path before the first boot — see bridge/docs/deploy.md. Either way, the final
# command it execs is exactly `attest-bridge serve --config /etc/attest-bridge/bridge.toml
# --host 0.0.0.0 --port 8080`.
ENTRYPOINT ["/opt/attest-bridge/deploy/docker-entrypoint.sh"]
