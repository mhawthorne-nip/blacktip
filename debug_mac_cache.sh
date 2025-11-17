#!/bin/bash
# Check MAC vendor lookup cache

echo "=== Checking cache file location ==="
ls -lh ~/.cache/mac-vendors.txt 2>&1

if [ -f ~/.cache/mac-vendors.txt ]; then
    echo ""
    echo "=== First 20 lines of cache ==="
    head -20 ~/.cache/mac-vendors.txt

    echo ""
    echo "=== Total lines in cache ==="
    wc -l ~/.cache/mac-vendors.txt

    echo ""
    echo "=== Searching for test MAC prefixes ==="
    for prefix in "30138B" "401A58" "687FF0" "600194"; do
        if grep -q "^${prefix}:" ~/.cache/mac-vendors.txt; then
            vendor=$(grep "^${prefix}:" ~/.cache/mac-vendors.txt)
            echo "  ✓ Found: $vendor"
        else
            echo "  ✗ NOT FOUND: $prefix"
        fi
    done
else
    echo "Cache file does not exist!"
    echo "Checking if running as root (sudo)..."
    if [ "$EUID" -eq 0 ]; then
        echo "Running as root - checking /root/.cache/"
        ls -lh /root/.cache/mac-vendors.txt 2>&1
    fi
fi
