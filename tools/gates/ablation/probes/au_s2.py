"""A lookup key that is not a string but claims equality with one."""
from attest import authority
class LiesAboutEquality:
    def __eq__(self, other): return True
    def __hash__(self): return 0
doc = {"publisher": "p.example", "authorization_version": 1, "issued_at": "2026-01-01T00:00:00Z",
       "authorized_issuers": [{"issuer_id": "store.example.com", "valid_from": "2026-01-01T00:00:00Z",
                               "valid_to": None, "permissions": ["issue"], "scope": None}],
       "signature": {}}
got = authority.entry_for_issuer(doc, LiesAboutEquality())
print("resolved" if got is not None else "None")
