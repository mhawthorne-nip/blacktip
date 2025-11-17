#!/usr/bin/env python3
"""Test update_vendors() to see why it creates an empty cache"""

from mac_vendor_lookup import MacLookup
import os
import traceback

print("=== Testing update_vendors() ===\n")

cache_file = os.path.expanduser("~/.cache/mac-vendors.txt")
print(f"Cache file: {cache_file}")

# Delete existing cache to force fresh download
if os.path.exists(cache_file):
    print(f"Removing existing cache ({os.path.getsize(cache_file)} bytes)...")
    os.remove(cache_file)

print("\nCreating MacLookup instance...")
mac = MacLookup()

print("\nCalling update_vendors()...")
try:
    # Enable verbose output if possible
    mac.update_vendors()
    print("✓ update_vendors() succeeded (no exception)")
except Exception as e:
    print(f"✗ update_vendors() failed with exception:")
    print(f"  {type(e).__name__}: {e}")
    traceback.print_exc()

print("\n=== Checking cache file ===")
if os.path.exists(cache_file):
    size = os.path.getsize(cache_file)
    print(f"✓ Cache file exists: {size:,} bytes")

    if size == 0:
        print("✗ ERROR: Cache file is EMPTY!")
        print("\nThis means update_vendors() created the file but didn't write anything.")
        print("Possible causes:")
        print("  - Network error downloading from IEEE")
        print("  - Parsing error (IEEE changed the format)")
        print("  - SSL/TLS error")
        print("  - Timeout")
    else:
        print(f"✓ Cache has content ({size/1024:.1f} KB)")
        print("\nFirst 10 lines:")
        with open(cache_file, 'rb') as f:
            for i in range(10):
                line = f.readline()
                if not line:
                    break
                print(f"  {line.decode('utf-8', errors='replace').strip()}")
else:
    print("✗ Cache file was NOT created")

print("\n=== Testing manual download ===")
print("Attempting to download IEEE OUI database directly...")

import urllib.request
import ssl

urls_to_try = [
    "http://standards-oui.ieee.org/oui/oui.txt",
    "https://standards-oui.ieee.org/oui/oui.txt",
]

for url in urls_to_try:
    print(f"\nTrying: {url}")
    try:
        # Try with and without SSL verification
        contexts = [None]
        if url.startswith('https'):
            # Add unverified SSL context as fallback
            contexts.append(ssl._create_unverified_context())

        for ctx in contexts:
            try:
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'blacktip-debug/1.0')

                if ctx:
                    print(f"  Trying with unverified SSL context...")
                    response = urllib.request.urlopen(req, context=ctx, timeout=10)
                else:
                    print(f"  Trying with default SSL context...")
                    response = urllib.request.urlopen(req, timeout=10)

                # Read first 1000 bytes
                data = response.read(1000)
                print(f"  ✓ Success! Got {len(data)} bytes")
                print(f"  First 200 chars:")
                print(f"    {data[:200].decode('utf-8', errors='replace')}")

                # Check if it contains expected format
                if b'base 16' in data or b'(hex)' in data:
                    print(f"  ✓ Data contains expected IEEE OUI format")
                else:
                    print(f"  ✗ Data does NOT contain expected format")

                break  # Success, don't try other contexts
            except Exception as e:
                print(f"  ✗ Failed: {type(e).__name__}: {e}")
                continue

    except Exception as e:
        print(f"  ✗ Failed: {type(e).__name__}: {e}")
