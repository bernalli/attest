"""Probe the door itself: what does _manifest_data admit?"""
from attest import trust_material, keys, manifests
KP = keys.from_seed(bytes([3]) * 32)
ISSUER = "publisher.example"
KID = f"{ISSUER}/keys/a#ed25519-1"
km = manifests.build_key_manifest(
    ISSUER, 1, "2026-01-01T00:00:00Z",
    [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z")], KP, KID)
out = [f"is_dict={isinstance(km, dict)}", f"type={type(km).__name__}"]
for label, snap in (("plain-dict", {"issuer": ISSUER, "keys": []}), ("real", km)):
    try:
        r = trust_material._manifest_data(snap)
        out.append(f"{label}={'admitted' if r is not None else 'None'}")
    except Exception as exc:
        out.append(f"{label}={type(exc).__name__}")
print(" | ".join(out))
