"""Does the admission byte ceiling refuse anything?"""
from attest import canon
big = "x" * (canon.MAX_ADMISSION_BYTES + 1000)
ok_big, _ = canon.admit_value(big, 0)
ok_small, _ = canon.admit_value("x" * 10, 0)
print(f"over-ceiling admitted={ok_big} small admitted={ok_small}")
