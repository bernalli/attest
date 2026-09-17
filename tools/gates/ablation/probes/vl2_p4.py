"""The suite's own fixture, but reporting the MESSAGE the test never looks at."""
import hashlib, tempfile, pathlib
from attest import bundle, issue, keys, manifests
from tests.helpers import make_payload
ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
KP = keys.from_seed(bytes([21]) * 32)
LEGAL_TEXT = b"attest-test-legal-text-v1"
MIRROR = b"attest-test-mirror-policy-v1"
LS, MS = hashlib.sha256(LEGAL_TEXT).hexdigest(), hashlib.sha256(MIRROR).hexdigest()
km = manifests.build_key_manifest(
    ISSUER, 1, "2026-01-01T00:00:00Z",
    [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z")], KP, KID)
out = []
for broken in ("missing", "scalar"):
    r = issue.issue(make_payload(receipt_id="01HZX0000000000000000000AA",
                                 license={"legal_text_sha256": LS},
                                 survivability={"mirror_policy_sha256": MS}),
                    KP, KID, salt=bytes([1]) * 16)
    if broken == "missing":
        del r["payload"]
    else:
        r["payload"] = "not-an-object"
    with tempfile.TemporaryDirectory() as d:
        try:
            bundle.export([r], [km], [], {LS: LEGAL_TEXT, MS: MIRROR},
                          pathlib.Path(d), "receipts")
            out.append(f"{broken}=NO-RAISE")
        except Exception as exc:
            out.append(f"{broken}={type(exc).__name__}:{exc}")
print(" | ".join(out))
