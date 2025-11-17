#!/usr/bin/env python3
"""Manually implement update_vendors() with verbose logging to see where it fails"""

import asyncio
import aiohttp
import aiofiles
import os
import traceback

OUI_URL = "http://standards-oui.ieee.org/oui/oui.txt"
CACHE_PATH = os.path.expanduser("~/.cache/mac-vendors.txt")

async def manual_update_vendors():
    """Manually implement the update_vendors logic with verbose debugging"""

    print(f"=== Manual Update Vendors ===\n")
    print(f"URL: {OUI_URL}")
    print(f"Cache: {CACHE_PATH}")

    # Ensure cache directory exists
    cache_dir = os.path.dirname(CACHE_PATH)
    if not os.path.exists(cache_dir):
        print(f"\nCreating cache directory: {cache_dir}")
        os.makedirs(cache_dir, exist_ok=True)

    print(f"\nStarting download...")

    try:
        async with aiohttp.ClientSession() as session:
            print(f"  ✓ Created aiohttp session")

            async with session.get(OUI_URL) as response:
                print(f"  ✓ GET request sent")
                print(f"  Status: {response.status}")
                print(f"  Headers: {dict(response.headers)}")

                if response.status != 200:
                    print(f"  ✗ Bad status code: {response.status}")
                    return

                print(f"\n  Opening cache file for writing...")
                async with aiofiles.open(CACHE_PATH, mode='wb') as f:
                    print(f"  ✓ Opened {CACHE_PATH}")

                    line_count = 0
                    match_count = 0
                    bytes_written = 0

                    print(f"\n  Reading and parsing lines...")
                    while True:
                        try:
                            line = await response.content.readline()
                        except Exception as e:
                            print(f"  ✗ Error reading line {line_count}: {e}")
                            traceback.print_exc()
                            break

                        if not line:
                            break

                        line_count += 1

                        if line_count % 10000 == 0:
                            print(f"    Processed {line_count:,} lines, {match_count:,} matches, {bytes_written:,} bytes written")

                        if b"(base 16)" in line:
                            try:
                                prefix, vendor = (i.strip() for i in line.split(b"(base 16)", 1))

                                # Show first few matches
                                if match_count < 5:
                                    print(f"    Match {match_count+1}: {prefix.decode('utf-8', errors='replace')} -> {vendor.decode('utf-8', errors='replace')}")

                                to_write = prefix + b":" + vendor + b"\n"
                                await f.write(to_write)
                                bytes_written += len(to_write)
                                match_count += 1
                            except Exception as e:
                                print(f"  ✗ Error processing line {line_count}: {e}")
                                print(f"    Line: {line[:100]}")
                                traceback.print_exc()

                    print(f"\n  ✓ Finished reading")
                    print(f"    Total lines: {line_count:,}")
                    print(f"    Matches: {match_count:,}")
                    print(f"    Bytes written: {bytes_written:,}")

                print(f"\n  File closed")

    except Exception as e:
        print(f"\n✗ Exception during update:")
        print(f"  {type(e).__name__}: {e}")
        traceback.print_exc()

    # Verify cache file
    print(f"\n{'='*60}")
    print("Verifying cache file:")
    print('='*60)

    if os.path.exists(CACHE_PATH):
        size = os.path.getsize(CACHE_PATH)
        print(f"✓ Cache exists: {size:,} bytes")

        if size > 0:
            print(f"\nFirst 5 lines:")
            with open(CACHE_PATH, 'rb') as f:
                for i in range(5):
                    line = f.readline()
                    if line:
                        print(f"  {line.decode('utf-8', errors='replace').strip()}")

            # Check for test prefixes
            print(f"\nSearching for test prefixes:")
            with open(CACHE_PATH, 'rb') as f:
                content = f.read()
                for prefix in [b'30138B', b'401A58', b'687FF0', b'600194']:
                    if prefix + b':' in content:
                        print(f"  ✓ {prefix.decode()}")
                    else:
                        print(f"  ✗ {prefix.decode()} NOT FOUND")
        else:
            print(f"✗ Cache is EMPTY!")
    else:
        print(f"✗ Cache file NOT created")

if __name__ == "__main__":
    asyncio.run(manual_update_vendors())
