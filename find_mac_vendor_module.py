#!/usr/bin/env python3
"""Find mac_vendor_lookup module location and version"""

import mac_vendor_lookup
import inspect

print(f"Module file: {mac_vendor_lookup.__file__}")

if hasattr(mac_vendor_lookup, '__version__'):
    print(f"Version: {mac_vendor_lookup.__version__}")
else:
    print("Version: (no __version__ attribute)")

print(f"\nModule docstring:")
print(f"  {mac_vendor_lookup.__doc__}")

print(f"\nModule contents:")
for name in dir(mac_vendor_lookup):
    if not name.startswith('_'):
        obj = getattr(mac_vendor_lookup, name)
        print(f"  {name}: {type(obj).__name__}")

# Show the update_vendors source code
print(f"\n{'='*60}")
print("MacLookup class methods:")
print('='*60)
mac = mac_vendor_lookup.MacLookup()
for name in dir(mac):
    if not name.startswith('_'):
        print(f"  {name}")

# Check if it's async
print(f"\nIs MacLookup.update_vendors a coroutine?")
import asyncio
if asyncio.iscoroutinefunction(mac.update_vendors):
    print("  YES - it's async!")
else:
    print("  NO - it's synchronous")
