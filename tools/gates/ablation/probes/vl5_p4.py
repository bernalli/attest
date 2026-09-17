"""Two GENUINE statements at different times: does T take the max, or the last?"""
import json
from attest import issue, keys, manifests, revocation, verify
from tests.helpers import make_payload, store
ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
KP = keys.from_seed(bytes([9]) * 32)
entries = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active")]
manifest = manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)
ts = store({ISSUER: manifest}, {ISSUER: "tls"})
def rec(rid, when):
    return revocation.build_record(rid, "revoked", when, KP, KID)
LATER = "2026-08-01T00:00:00Z"
OLDER = "2026-07-05T00:00:00Z"
# Two genuine, registered-status records for OTHER receipts: the anchor must be the MAX.
records = [rec("01J1V5B4M9Z8QWERTY99999999", LATER), rec("01J1V5B4M9Z8QWERTY88888888", OLDER)]
env = issue.issue(make_payload(license={"revocability": "policy"}), KP, KID)
r = verify.verify(json.dumps(env).encode(), ts, revocation_view=records)
print(r.revocation)
