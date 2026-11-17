import sys

print(f"argc = {len(sys.argv)}")
for i, a in enumerate(sys.argv):
    print(f"[{i}] {a!r}")
