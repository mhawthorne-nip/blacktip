#!/usr/bin/env python3
"""Test if mac_vendor_lookup works now that we have a valid cache"""

from mac_vendor_lookup import MacLookup
import os

cache_file = os.path.expanduser("~/.cache/mac-vendors.txt")

print("=== Testing MAC Vendor Lookup with Valid Cache ===\n")

if os.path.exists(cache_file):
    size = os.path.getsize(cache_file)
    print(f"✓ Cache exists: {size:,} bytes")
else:
    print(f"✗ Cache missing: {cache_file}")
    exit(1)

print("\nCreating MacLookup instance...")
mac = MacLookup()

test_macs = [
    ("30:13:8b:ee:ca:4b", "HP Inc."),
    ("40:1a:58:db:08:10", "Wistron Neweb Corporation"),
    ("68:7f:f0:3f:d6:84", "TP-Link Systems Inc."),
    ("60:01:94:f3:b2:8e", "Espressif Inc."),
]

print("\nTesting lookups:")
success = 0
failed = 0

for mac_addr, expected in test_macs:
    try:
        vendor = mac.lookup(mac_addr)
        if vendor:
            print(f"  ✓ {mac_addr}: {vendor}")
            success += 1
        else:
            print(f"  ✗ {mac_addr}: Empty result")
            failed += 1
    except KeyError as e:
        print(f"  ✗ {mac_addr}: KeyError - {e}")
        failed += 1
    except Exception as e:
        print(f"  ✗ {mac_addr}: {type(e).__name__} - {e}")
        failed += 1

print(f"\n{'='*60}")
if failed == 0:
    print(f"SUCCESS! All {success} lookups worked!")
    print("\nThe cache is valid and mac_vendor_lookup can use it.")
    print("\nThe issue is that update_vendors() in the mac-vendor-lookup")
    print("library is broken. We need to replace it in blacktip.")
else:
    print(f"FAILED: {failed}/{len(test_macs)} lookups failed")
    print("Even with a valid cache, lookups are failing.")
