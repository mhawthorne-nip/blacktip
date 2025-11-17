#!/usr/bin/env python3
"""Test MAC vendor lookup directly"""

from mac_vendor_lookup import MacLookup
import os

print("=== MAC Vendor Lookup Test ===\n")

# Check cache location
cache_file = os.path.expanduser("~/.cache/mac-vendors.txt")
print(f"Cache file location: {cache_file}")
print(f"Cache file exists: {os.path.exists(cache_file)}")

if os.path.exists(cache_file):
    size = os.path.getsize(cache_file)
    print(f"Cache file size: {size:,} bytes ({size/1024/1024:.2f} MB)")

    # Show first few lines
    print("\nFirst 5 lines of cache:")
    with open(cache_file, 'rb') as f:
        for i in range(5):
            line = f.readline()
            print(f"  {line.decode('utf-8', errors='replace').strip()}")

    # Count lines
    with open(cache_file, 'rb') as f:
        line_count = sum(1 for _ in f)
    print(f"\nTotal lines in cache: {line_count:,}")

    # Check for specific prefixes
    print("\nSearching for test prefixes in raw file:")
    test_prefixes = [b'30138B', b'401A58', b'687FF0', b'600194']
    with open(cache_file, 'rb') as f:
        content = f.read()
        for prefix in test_prefixes:
            if prefix in content:
                # Find the full line
                for line in content.split(b'\n'):
                    if line.startswith(prefix + b':'):
                        print(f"  ✓ {line.decode('utf-8', errors='replace')}")
                        break
            else:
                print(f"  ✗ {prefix.decode()} NOT FOUND in file")
else:
    print("\n✗ Cache file does not exist!")
    print("This means update_vendors() either failed or hasn't run yet.")

print("\n=== Testing MacLookup class ===\n")

mac = MacLookup()

# Check internal state
print("MacLookup internal state:")
for attr in ['prefixes', '_cache', 'cache_path']:
    if hasattr(mac, attr):
        val = getattr(mac, attr)
        if isinstance(val, dict):
            print(f"  {attr}: dict with {len(val)} entries")
        else:
            print(f"  {attr}: {val}")

# Test lookups
test_macs = [
    "30:13:8b:ee:ca:4b",
    "40:1a:58:db:08:10",
    "68:7f:f0:3f:d6:84",
    "60:01:94:f3:b2:8e",
]

print("\nTesting lookups:")
for mac_addr in test_macs:
    # Show sanitized version
    sanitized = mac_addr.replace(":", "").replace("-", "").upper()
    prefix = sanitized[:6]
    print(f"\n  MAC: {mac_addr}")
    print(f"  Sanitized: {sanitized}")
    print(f"  Prefix: {prefix}")

    try:
        vendor = mac.lookup(mac_addr)
        print(f"  ✓ Vendor: {vendor}")
    except KeyError as e:
        print(f"  ✗ KeyError: {e}")
    except Exception as e:
        print(f"  ✗ Error: {type(e).__name__}: {e}")
