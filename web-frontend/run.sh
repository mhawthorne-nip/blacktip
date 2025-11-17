#!/bin/bash
#
# Blacktip Web Frontend Startup Script
#

# Default configuration
DEFAULT_DB="/var/lib/blacktip/blacktip.db"
DEFAULT_PORT="5000"

# Use environment variables or defaults
BLACKTIP_DB="${BLACKTIP_DB:-$DEFAULT_DB}"
PORT="${PORT:-$DEFAULT_PORT}"

# Check if database exists
if [ ! -f "$BLACKTIP_DB" ]; then
    echo "ERROR: Blacktip database not found at: $BLACKTIP_DB"
    echo ""
    echo "Please set BLACKTIP_DB environment variable to the correct path:"
    echo "  export BLACKTIP_DB=/path/to/blacktip.db"
    echo ""
    echo "Or create a test database with Blacktip scanner:"
    echo "  sudo blacktip -f /tmp/blacktip.db"
    exit 1
fi

# Check if database is readable
if [ ! -r "$BLACKTIP_DB" ]; then
    echo "ERROR: Cannot read database at: $BLACKTIP_DB"
    echo ""
    echo "Please ensure the file has read permissions:"
    echo "  sudo chmod 644 $BLACKTIP_DB"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if dependencies are installed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "ERROR: Flask is not installed"
    echo ""
    echo "Please install dependencies:"
    echo "  pip install -r requirements.txt"
    exit 1
fi

# Display configuration
echo "======================================"
echo "  Blacktip Web Frontend"
echo "======================================"
echo ""
echo "Configuration:"
echo "  Database: $BLACKTIP_DB"
echo "  Port:     $PORT"
echo "  URL:      http://localhost:$PORT"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the web server
cd "$SCRIPT_DIR"
export BLACKTIP_DB
export PORT
python3 app.py
