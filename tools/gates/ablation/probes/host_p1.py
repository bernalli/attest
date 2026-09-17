"""Sweep depths to find the boundary the headroom is supposed to move."""

from attest import canon


def build(n):
    v = "leaf"
    for _ in range(n):
        v = [v]
    return v


res = []
for n in (canon.MAX_DEPTH - 4, canon.MAX_DEPTH - 3, canon.MAX_DEPTH - 2, canon.MAX_DEPTH - 1):
    ok, mat = canon.admit_value(build(n), canon.VIEW_ARRAY_ELEMENT_NESTING)
    if not ok:
        res.append(f"{n}:refused")
        continue
    try:
        canon.dumps({"authorizations": [mat]})
        res.append(f"{n}:ok")
    except Exception:
        res.append(f"{n}:ADMITTED-BUT-UNCANONICALIZABLE")
print(" ".join(res))
