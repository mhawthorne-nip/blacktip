#!/bin/bash
#
# Initialize and start the Blacktip state monitor
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
DB_PATH="/var/lib/blacktip/blacktip.db"
CHECK_INTERVAL=60
DEBUG=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--datafile)
            DB_PATH="$2"
            shift 2
            ;;
        -i|--interval)
            CHECK_INTERVAL="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -f, --datafile PATH    Path to blacktip database (default: /var/lib/blacktip/blacktip.db)"
            echo "  -i, --interval SEC     Check interval in seconds (default: 60)"
            echo "  -d, --debug            Enable debug output"
            echo "  -h, --help             Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}Blacktip State Monitor Setup${NC}"
echo "================================"
echo ""

# Check if database exists
if [ ! -f "$DB_PATH" ]; then
    echo -e "${RED}Error: Database not found at $DB_PATH${NC}"
    echo "Please specify the correct path with -f option"
    exit 1
fi

echo -e "${GREEN}✓${NC} Database found: $DB_PATH"

# Check if blacktip-state-monitor is installed
if ! command -v blacktip-state-monitor &> /dev/null; then
    echo -e "${RED}Error: blacktip-state-monitor command not found${NC}"
    echo "Please install with: pip install -e ."
    exit 1
fi

echo -e "${GREEN}✓${NC} blacktip-state-monitor is installed"

# Build command
CMD="blacktip-state-monitor -f $DB_PATH -i $CHECK_INTERVAL"
if [ "$DEBUG" = true ]; then
    CMD="$CMD -d"
fi

echo ""
echo "Configuration:"
echo "  Database: $DB_PATH"
echo "  Check interval: ${CHECK_INTERVAL}s"
echo "  Debug mode: $DEBUG"
echo ""
echo "Starting state monitor..."
echo "Command: $CMD"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo ""

# Run the monitor
exec $CMD
