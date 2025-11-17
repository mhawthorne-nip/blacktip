#!/usr/bin/env python3
"""Check if required dependencies for mac-vendor-lookup are installed"""

print("=== Checking Dependencies ===\n")

# Check each required module
required = ['asyncio', 'aiohttp', 'aiofiles', 'mac_vendor_lookup']
missing = []

for module in required:
    try:
        __import__(module)
        print(f"✓ {module}")
    except ImportError as e:
        print(f"✗ {module} - MISSING: {e}")
        missing.append(module)

if missing:
    print(f"\n{'='*60}")
    print("PROBLEM FOUND!")
    print('='*60)
    print(f"\nMissing dependencies: {', '.join(missing)}")
    print("\nThese are required for mac-vendor-lookup to work.")
    print("\nTo fix, run:")
    print("  pip install aiohttp aiofiles")
    print("\nOr reinstall mac-vendor-lookup with all dependencies:")
    print("  pip uninstall mac-vendor-lookup")
    print("  pip install mac-vendor-lookup")
else:
    print("\n✓ All dependencies are installed!")
    print("\nThe issue must be something else...")
