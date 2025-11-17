#!/usr/bin/env python3
"""Download and inspect the IEEE OUI file to see its actual format"""

import urllib.request

url = "http://standards-oui.ieee.org/oui/oui.txt"

print(f"=== Downloading from {url} ===\n")

try:
    req = urllib.request.Request(url)
    req.add_header('User-Agent', 'blacktip-debug/1.0')
    response = urllib.request.urlopen(req, timeout=30)

    # Read entire file
    data = response.read()
    print(f"✓ Downloaded {len(data):,} bytes ({len(data)/1024/1024:.2f} MB)")

    # Decode to text
    text = data.decode('utf-8', errors='replace')
    lines = text.split('\n')
    print(f"✓ Total lines: {len(lines):,}")

    # Show first 30 lines
    print(f"\n{'='*60}")
    print("First 30 lines:")
    print('='*60)
    for i, line in enumerate(lines[:30]):
        print(f"{i+1:3d}: {line}")

    # Count lines with "(base 16)"
    base16_count = sum(1 for line in lines if "(base 16)" in line)
    print(f"\n{'='*60}")
    print(f"Lines containing '(base 16)': {base16_count:,}")
    print('='*60)

    if base16_count == 0:
        print("✗ NO LINES contain '(base 16)'!")
        print("This is why update_vendors() creates an empty cache!")
        print("\nThe IEEE OUI file format has likely changed.")

        # Look for our test prefixes
        print(f"\n{'='*60}")
        print("Searching for test MAC prefixes in file:")
        print('='*60)
        test_prefixes = ['30-13-8B', '30138B', '40-1A-58', '401A58',
                         '68-7F-F0', '687FF0', '60-01-94', '600194']

        for prefix in test_prefixes:
            matching = [line for line in lines if prefix in line]
            if matching:
                print(f"\n✓ Found {prefix}:")
                for line in matching[:3]:  # Show first 3 matches
                    print(f"  {line}")
            else:
                print(f"\n✗ {prefix} NOT FOUND")
    else:
        print(f"✓ File has {base16_count:,} entries with '(base 16)'")
        print("\nShowing first 5 entries with '(base 16)':")
        count = 0
        for line in lines:
            if "(base 16)" in line:
                print(f"  {line}")
                count += 1
                if count >= 5:
                    break

        # Check for our test prefixes
        print(f"\n{'='*60}")
        print("Checking if test prefixes are in the file:")
        print('='*60)
        test_macs = ['30138B', '401A58', '687FF0', '600194']
        for prefix in test_macs:
            found = any(prefix in line for line in lines)
            print(f"  {prefix}: {'✓ Found' if found else '✗ NOT FOUND'}")

except Exception as e:
    print(f"✗ Error: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
