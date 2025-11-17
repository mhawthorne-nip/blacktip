# CLAUDE.md - AI Assistant Guide for Blacktip

**Last Updated**: 2025-11-17
**Project Version**: 1.0.0
**Repository**: https://github.com/mhawthorne-nip/blacktip

This document provides comprehensive guidance for AI assistants working with the Blacktip codebase.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Repository Structure](#repository-structure)
3. [Development Environment](#development-environment)
4. [Code Conventions & Patterns](#code-conventions--patterns)
5. [Key Components](#key-components)
6. [Testing Strategy](#testing-strategy)
7. [Common Development Workflows](#common-development-workflows)
8. [Security Considerations](#security-considerations)
9. [Deployment & Operations](#deployment--operations)
10. [Troubleshooting Guide](#troubleshooting-guide)
11. [AI Assistant Guidelines](#ai-assistant-guidelines)

---

## Project Overview

### What is Blacktip?

**Blacktip** is a passive network security scanner for real-time ARP traffic analysis, device fingerprinting, and threat detection on Linux systems. It operates by:

- **Passively monitoring** ARP (Address Resolution Protocol) traffic
- **Discovering devices** on the network without sending probe packets
- **Fingerprinting devices** using integrated nmap scans
- **Detecting anomalies** like ARP spoofing, IP conflicts, and MAC changes
- **Storing data** in a persistent SQLite database

### Key Characteristics

- **Platform**: Linux only (requires raw packet capture capabilities)
- **Language**: Python 3.8+
- **Architecture**: Command-line tool designed for 24/7 operation
- **Privileges**: Requires root/sudo for packet capture
- **Output Format**: Structured JSON events to stdout

### Project Goals

1. **Zero-footprint monitoring** - No active network traffic generation
2. **Security-focused** - Input validation, anomaly detection, privilege separation
3. **Production-ready** - Robust error handling, atomic database operations
4. **Extensible** - Custom event handlers via command execution
5. **Observable** - Built-in metrics and structured logging

---

## Repository Structure

```
blacktip/
├── src/blacktip/              # Main Python package
│   ├── __init__.py           # Package metadata and configuration constants
│   ├── blacktip.py           # Core monitoring logic and main Blacktip class
│   ├── cli/                  # Command-line interface
│   │   ├── __init__.py
│   │   └── entrypoints.py    # Argument parsing and CLI entry point
│   ├── utils/                # Utility modules
│   │   ├── __init__.py
│   │   ├── database.py       # SQLite database operations
│   │   ├── sniffer.py        # ARP packet capture with scapy
│   │   ├── security.py       # Security utilities and privilege management
│   │   ├── metrics.py        # Performance metrics collection
│   │   ├── nmap_parser.py    # XML parsing for nmap scan results
│   │   ├── logger.py         # Centralized logging configuration
│   │   ├── exe.py            # Command execution framework
│   │   ├── config.py         # Configuration management
│   │   ├── dns_resolver.py   # DNS lookup utilities
│   │   ├── classifier.py     # Device classification logic
│   │   ├── validation.py     # Input validation and sanitization
│   │   └── utils.py          # General utility functions
│   └── exceptions/           # Custom exception classes
│       └── __init__.py
├── tests/                    # Test suite
│   ├── __init__.py
│   └── test_validation.py    # Validation unit tests
├── pyproject.toml            # PEP 517/518 build configuration
├── setup.py                  # Setuptools compatibility shim
├── requirements.txt          # Runtime dependencies
├── requirements-dev.txt      # Development dependencies
├── .gitignore               # Git ignore patterns
├── README.md                # User-facing documentation
├── SYSTEMD_SETUP.md         # Service deployment guide
├── install-service.sh       # Automated service installer
├── uninstall-service.sh     # Service removal script
└── blacktip.service         # Systemd unit file template
```

### File Organization Principles

- **src/ layout**: Modern Python packaging with source directory
- **Flat utils/**: Utility modules are peers, not nested
- **Single responsibility**: Each module has a focused purpose
- **Tests mirror src/**: Test file structure reflects package structure

---

## Development Environment

### Prerequisites

```bash
# System requirements
OS: Linux (tested on Ubuntu 16.04+)
Python: 3.8.0 or higher
Privileges: Root/sudo for packet capture

# Optional tools
nmap: For automated device scanning
sqlite3: For database inspection
```

### Installation for Development

```bash
# Clone repository
git clone https://github.com/mhawthorne-nip/blacktip.git
cd blacktip

# Install in editable mode with all dependencies
sudo pip install --break-system-packages -e ".[all]"

# Or for non-externally-managed environments
sudo pip install -e ".[all]"

# Verify installation
blacktip --version
```

### Development Dependencies

**Runtime** (requirements.txt):
- `scapy[basic]>=2.5.0,<3.0.0` - Packet manipulation and capture
- `psutil>=5.9.0,<6.0.0` - System and process utilities
- `mac-vendor-lookup>=0.1.0,<1.0.0` - MAC address vendor identification
- `validators>=0.20.0,<1.0.0` - Input validation

**Development** (requirements-dev.txt):
- `pytest>=6.0,<9.0` - Testing framework
- `pytest-cov>=2.10,<6.0` - Coverage reporting
- `pytest-timeout>=2.1,<3.0` - Test timeout enforcement

**Optional**:
- `PyYAML>=5.1,<7.0` - YAML configuration support

### Environment Variables

```bash
# Logging configuration
export BLACKTIP_LOG_LEVEL=debug        # Logging level (default: info)
export BLACKTIP_LOG_FILE=/path/to/log  # Enable file logging (default: console)

# Development
export PYTHONPATH=/path/to/blacktip/src  # If not installed
```

---

## Code Conventions & Patterns

### Python Style

- **PEP 8 compliant** with some pragmatic exceptions
- **Python 3.8+ compatibility** - Avoid newer syntax features
- **Type hints**: Not currently used, but acceptable to add
- **String formatting**: Use `.format()` for consistency (not f-strings)
- **Line length**: Reasonable, not strict 80 chars

### Naming Conventions

```python
# Classes: PascalCase
class BlacktipDatabase:
    pass

# Functions/methods: snake_case
def validate_ip_address(ip):
    pass

# Constants: UPPER_SNAKE_CASE (in __init__.py)
__save_data_interval__default__ = 30
NMAP_EXEC = "nmap -n -T4 ..."

# Private: Leading underscore
def _get_connection(self):
    pass
```

### Module Organization Pattern

Each module typically follows this structure:

```python
# 1. Imports
import stdlib_modules
from third_party import something
from blacktip.utils import local_module

# 2. Module-level constants
CONSTANT_VALUE = 42

# 3. Exception classes (if any)
class ModuleException(Exception):
    pass

# 4. Helper functions
def _internal_helper():
    pass

# 5. Public classes
class PublicClass:
    def __init__(self):
        pass

    def public_method(self):
        pass

    def _private_method(self):
        pass

# 6. Public functions
def public_function():
    pass
```

### Error Handling

```python
# Use specific exceptions
from blacktip.exceptions import BlacktipException

# Log errors before raising
from blacktip.utils import logger

try:
    risky_operation()
except SpecificError as e:
    logger.error("Operation failed: {}".format(e))
    raise BlacktipException("User-friendly message") from e

# Use context managers for resources
with self._get_connection() as conn:
    conn.execute(...)
```

### Logging Patterns

```python
from blacktip.utils import logger

# Initialize logger (in main class __init__)
logger.init(name=NAME, level=logger_level)

# Use appropriate levels
logger.debug("Detailed diagnostic info")      # Development
logger.info("Normal operation milestones")    # Production
logger.warning("Unexpected but handled")      # Potential issues
logger.error("Error that may affect function") # Failures
logger.critical("System cannot continue")      # Fatal errors

# Always format with .format() for consistency
logger.info("Processing {} packets from {}".format(count, interface))
```

### Database Patterns

```python
# Always use context manager
with self._get_connection() as conn:
    cursor = conn.cursor()
    cursor.execute(query, params)
    result = cursor.fetchall()
    # Commit happens automatically on success
    # Rollback happens automatically on exception

# Use parameterized queries
cursor.execute(
    "SELECT * FROM devices WHERE ip_address = ?",
    (ip_address,)
)

# Access rows by name
conn.row_factory = sqlite3.Row
for row in cursor.fetchall():
    print(row['ip_address'])
```

---

## Key Components

### 1. Core Monitoring Logic (`blacktip.py`)

**Class**: `Blacktip`

**Responsibilities**:
- Main application orchestration
- Packet batch processing loop
- Database persistence scheduling
- Metrics collection coordination
- Nmap scan triggering

**Key Methods**:
- `do_version()` - Return version information
- `do_query(datafile, query)` - Query database for IP/MAC
- `do_sniffer(...)` - Main monitoring loop (runs indefinitely)

**Configuration Constants** (in `__init__.py`):
```python
__sniff_batch_size__ = 16           # Packets per batch
__sniff_batch_timeout__ = 2         # Seconds to wait for batch
__save_data_interval__default__ = 30  # Database write interval
__nmap__exec__ = "nmap -n -T4 ..."  # Nmap command template
__exec_max_runtime__ = 600          # Max command execution time
```

### 2. CLI Entry Point (`cli/entrypoints.py`)

**Function**: `blacktip()`

**Responsibilities**:
- Argument parsing with argparse
- Signal handling (SIGINT)
- Mode selection (version, query, sniffer)
- User input validation

**Argument Groups**:
1. **Datafile arguments**: Database path, save interval, interface
2. **Event selection**: Request/reply filtering (new/all/none)
3. **Command execution**: Custom commands, nmap control, user switching
4. **Run modes**: Query, version, debug, metrics

### 3. Database Layer (`utils/database.py`)

**Class**: `BlacktipDatabase`

**Schema**:
```sql
-- Metadata table
metadata (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)

-- Devices table
devices (
    id INTEGER PRIMARY KEY,
    ip_address TEXT,
    mac_address TEXT,
    vendor TEXT,
    first_seen TEXT,
    last_seen TEXT,
    packet_count INTEGER,
    request_count INTEGER,
    reply_count INTEGER,
    UNIQUE(ip_address, mac_address)
)

-- ARP events history
arp_events (
    id INTEGER PRIMARY KEY,
    device_id INTEGER,
    event_type TEXT,
    timestamp TEXT,
    is_gratuitous INTEGER,
    FOREIGN KEY (device_id) REFERENCES devices(id)
)

-- Nmap scan results
nmap_scans (
    id INTEGER PRIMARY KEY,
    ip_address TEXT UNIQUE,
    xml_data TEXT,
    scan_timestamp TEXT
)
```

**Key Methods**:
- `_get_connection()` - Context manager for safe DB access
- `increment_starts()` - Track application starts
- `get_statistics()` - Query DB stats
- `query_by_address(address)` - Search by IP or MAC
- `save_device(...)` - Atomic device record update
- `save_nmap_result(...)` - Store nmap XML output

**Patterns**:
- Uses context managers for automatic commit/rollback
- Implements retry logic for locked database
- Validates file permissions on initialization
- Row factory for dict-like access

### 4. Packet Capture (`utils/sniffer.py`)

**Class**: `BlacktipSniffer`

**Responsibilities**:
- ARP packet capture using scapy
- MAC vendor lookup with caching
- Batch packet collection

**Key Methods**:
- `sniff_arp_packet_batch(interface=None)` - Capture batch of ARP packets
- `_get_mac_vendor(mac_address)` - Lookup with cache

**Important Notes**:
- Requires CAP_NET_RAW capability (root privileges)
- Uses scapy's sniff() with timeout for batching
- Caches MAC vendor lookups to avoid repeated queries
- Skips MAC vendor DB updates if valid cache exists

### 5. Security & Validation (`utils/validation.py`, `utils/security.py`)

**Validation Functions**:
```python
validate_ip_address(ip) -> (bool, Optional[str])
validate_mac_address(mac) -> (bool, Optional[str])
validate_username(username) -> (bool, Optional[str])
validate_command_template(cmd) -> (bool, List[str])
validate_interface_name(interface) -> (bool, Optional[str])
validate_port(port) -> (bool, Optional[str])

sanitize_ip_address(ip) -> str
sanitize_mac_address(mac) -> str
```

**Security Utilities**:
- User privilege checks
- Command injection prevention
- Safe subprocess execution
- User context switching (for exec commands)

**Validation Patterns**:
- Return tuple of (is_valid, error_message)
- Sanitization functions return cleaned string or empty
- Warnings for potentially dangerous but valid inputs
- Strict validation for network addresses

### 6. Logging System (`utils/logger.py`)

**Classes**:
- `Logger` - Main logger wrapper
- `LoggerColoredFormatter` - ANSI color formatting for console

**Features**:
- Colored console output (with ANSI escape codes)
- Plain file output (via BLACKTIP_LOG_FILE env var)
- Prevents duplicate handlers
- Disables propagation to root logger
- Configurable via environment or parameter

**Usage**:
```python
from blacktip.utils import logger

# Initialize once
logger.init(name="blacktip", level="info")

# Use throughout application
logger.debug("message")
logger.info("message")
logger.warning("message")
logger.error("message")
logger.critical("message")
```

### 7. Metrics Collection (`utils/metrics.py`)

**Function**: `get_metrics()`

**Tracked Metrics**:
- Packet processing rates
- Database operation timing
- Command execution counts
- Error rates
- Batch processing duration

**Usage**:
```python
metrics = get_metrics() if enable_metrics else None

if metrics:
    metrics.increment("counter_name")
    metrics.record_time("timer_name", duration_seconds)
    metrics.log_stats()  # Periodic statistics dump
```

### 8. Command Execution (`utils/exe.py`)

**Class**: `BlacktipExec`

**Features**:
- Template substitution: `{IP}`, `{HW}`, `{TS}`, `{ts}`
- User context switching (run as non-root)
- Timeout enforcement
- Security validation

**Template Variables**:
- `{IP}` - IP address (e.g., `192.168.1.100`)
- `{HW}` - MAC address (e.g., `aa:bb:cc:dd:ee:ff`)
- `{TS}` - Full timestamp (e.g., `2025-01-15T14:23:45.678901Z`)
- `{ts}` - Short timestamp (e.g., `2025-01-15T14:23:45Z`)

### 9. Nmap Integration (`utils/nmap_parser.py`)

**Responsibilities**:
- Parse nmap XML output
- Extract port, service, OS information
- Handle scan errors gracefully

**Nmap Command** (from `__init__.py`):
```bash
nmap -n -T4 -Pn -sV -O \
  --script http-title,http-server-header,http-methods,http-favicon,\
            ssl-cert,ssl-enum-ciphers,ssh-hostkey,ssh2-enum-algos,\
            nbstat,smb-os-discovery,smb-protocols,smb-security-mode,\
            dns-service-discovery,ftp-anon \
  -oX - {IP}
```

**Flags Explained**:
- `-n` - No DNS resolution (faster, DNS done separately)
- `-T4` - Aggressive timing
- `-Pn` - Skip ping (assume host is up)
- `-sV` - Service version detection
- `-O` - OS detection
- `--script` - NSE scripts for comprehensive enumeration
- `-oX -` - XML output to stdout

---

## Testing Strategy

### Test Organization

```
tests/
├── __init__.py
└── test_validation.py    # Input validation tests
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=src/blacktip --cov-report=html

# Run specific test types (markers)
pytest -m unit
pytest -m integration
pytest -m slow

# Run specific test file
pytest tests/test_validation.py

# Run specific test class or function
pytest tests/test_validation.py::TestIPValidation
pytest tests/test_validation.py::TestIPValidation::test_valid_ip_addresses
```

### Test Markers

Defined in `pyproject.toml`:
```toml
[tool.pytest.ini_options]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
    "unit: marks tests as unit tests",
]
```

### Test Patterns

```python
import pytest

class TestFeature:
    """Group related tests in classes"""

    def test_valid_input(self):
        """Test happy path"""
        result = function_under_test(valid_input)
        assert result == expected

    def test_invalid_input(self):
        """Test error handling"""
        result = function_under_test(invalid_input)
        assert not result

    @pytest.mark.slow
    def test_expensive_operation(self):
        """Mark slow tests"""
        pass
```

### Coverage Configuration

Defined in `pyproject.toml`:
```toml
[tool.coverage.run]
source = ["src/blacktip"]
omit = ["*/tests/*", "*/test_*.py"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
    "if TYPE_CHECKING:",
]
```

### Testing Best Practices

1. **Test validation extensively** - Security-critical code
2. **Mock external dependencies** - nmap, scapy packet capture
3. **Use fixtures** - For database setup/teardown
4. **Test edge cases** - Empty strings, null values, extreme values
5. **Integration tests require root** - For packet capture tests

---

## Common Development Workflows

### Adding a New Feature

1. **Create feature branch**:
   ```bash
   git checkout -b feature/description
   ```

2. **Identify affected modules**:
   - Core logic → `blacktip.py`
   - New utility → `utils/new_module.py`
   - CLI changes → `cli/entrypoints.py`
   - Database schema → `utils/database.py`

3. **Write tests first** (TDD):
   ```bash
   # Create test file
   touch tests/test_new_feature.py

   # Write failing tests
   pytest tests/test_new_feature.py  # Should fail
   ```

4. **Implement feature**:
   - Follow code conventions
   - Add logging
   - Handle errors
   - Validate inputs

5. **Verify tests pass**:
   ```bash
   pytest tests/test_new_feature.py
   pytest  # Run all tests
   ```

6. **Update documentation**:
   - `README.md` for user-facing features
   - `CLAUDE.md` for architecture changes
   - Docstrings for public APIs

7. **Commit and push**:
   ```bash
   git add .
   git commit -m "Add feature: description"
   git push origin feature/description
   ```

### Modifying Database Schema

**IMPORTANT**: Database migrations are NOT automated. Changes require careful handling.

1. **Update schema in `utils/database.py`**:
   ```python
   def _init_database(self):
       cursor.execute("""
           CREATE TABLE IF NOT EXISTS new_table (
               id INTEGER PRIMARY KEY,
               ...
           )
       """)
   ```

2. **Handle existing databases**:
   - Option A: Check if table exists, add if missing
   - Option B: Document manual migration steps
   - Option C: Version the database (add to metadata table)

3. **Test with fresh database**:
   ```bash
   sudo blacktip -f /tmp/test.db
   sqlite3 /tmp/test.db ".schema"
   ```

4. **Test with existing database**:
   ```bash
   # Copy production DB for testing
   cp /var/lib/blacktip/network.db /tmp/test.db
   sudo blacktip -f /tmp/test.db
   ```

5. **Document migration** in commit message and SYSTEMD_SETUP.md

### Adding Configuration Options

1. **Define constant in `__init__.py`**:
   ```python
   __new_option_default__ = "default_value"
   ```

2. **Add CLI argument in `cli/entrypoints.py`**:
   ```python
   parser.add_argument(
       "--new-option",
       required=False,
       default=NEW_OPTION_DEFAULT,
       type=str,
       help="Description of new option"
   )
   ```

3. **Pass to core logic**:
   ```python
   bt.do_sniffer(
       ...,
       new_option=args.new_option
   )
   ```

4. **Use in implementation**:
   ```python
   def do_sniffer(self, ..., new_option=NEW_OPTION_DEFAULT):
       logger.debug("Using new_option={}".format(new_option))
   ```

5. **Update README.md** with new option documentation

### Debugging Network Issues

1. **Enable debug logging**:
   ```bash
   sudo blacktip -f /tmp/test.db --debug
   ```

2. **Verify interface selection**:
   ```bash
   ip link show
   sudo blacktip -f /tmp/test.db --interface eth0 --debug
   ```

3. **Check packet capture**:
   ```bash
   # Verify ARP traffic exists
   sudo tcpdump -i eth0 arp -c 10
   ```

4. **Test with all traffic**:
   ```bash
   sudo blacktip -f /tmp/test.db --all-request --all-reply --debug
   ```

5. **Check database writes**:
   ```bash
   sqlite3 /tmp/test.db "SELECT COUNT(*) FROM devices;"
   sqlite3 /tmp/test.db "SELECT * FROM devices ORDER BY last_seen DESC LIMIT 10;"
   ```

### Performance Profiling

1. **Enable metrics**:
   ```bash
   sudo blacktip -f /tmp/test.db --metrics --metrics-interval 60
   ```

2. **Monitor resource usage**:
   ```bash
   # In another terminal
   top -p $(pgrep -f blacktip)
   ```

3. **Profile with cProfile** (add to code temporarily):
   ```python
   import cProfile
   import pstats

   profiler = cProfile.Profile()
   profiler.enable()
   # ... code to profile ...
   profiler.disable()
   stats = pstats.Stats(profiler)
   stats.sort_stats('cumulative')
   stats.print_stats(20)
   ```

---

## Security Considerations

### Privilege Management

**Blacktip requires root privileges for**:
- Raw packet capture (CAP_NET_RAW)
- Opening network interfaces in promiscuous mode
- Running nmap scans (optional)

**Security implications**:
1. **Runs as root** - Entire process has elevated privileges
2. **Packet capture** - Can see all network traffic
3. **Command execution** - Custom commands run with root by default
4. **Database access** - SQLite files should be permission-restricted

**Mitigation strategies**:
```bash
# 1. Use user switching for command execution
sudo blacktip -f network.db -e "/path/script.sh {IP}" -u nobody

# 2. Grant capabilities instead of full root (advanced)
sudo setcap cap_net_raw+ep $(which blacktip)
# Then modify service to run as non-root user

# 3. Restrict database permissions
sudo chmod 600 /var/lib/blacktip/network.db
sudo chown root:root /var/lib/blacktip/network.db
```

### Input Validation

**All external inputs MUST be validated**:

1. **Network addresses**:
   ```python
   from blacktip.utils.validation import validate_ip_address, sanitize_ip_address

   is_valid, error = validate_ip_address(user_input)
   if not is_valid:
       logger.error("Invalid IP: {}".format(error))
       return

   clean_ip = sanitize_ip_address(user_input)
   ```

2. **Command templates**:
   ```python
   from blacktip.utils.validation import validate_command_template

   is_safe, warnings = validate_command_template(command)
   if not is_safe:
       logger.error("Unsafe command: {}".format(warnings))
       return
   ```

3. **User names**:
   ```python
   from blacktip.utils.validation import validate_username

   is_valid, error = validate_username(username)
   if not is_valid:
       logger.error("Invalid username: {}".format(error))
       return
   ```

### Command Injection Prevention

**Template substitution is NOT shell-safe by default**:

```python
# WRONG - Direct shell execution
os.system(command.format(IP=user_ip))  # Vulnerable!

# CORRECT - Use BlacktipExec with validation
from blacktip.utils.exe import BlacktipExec
from blacktip.utils.validation import validate_command_template

is_safe, warnings = validate_command_template(command)
if not is_safe:
    raise BlacktipException("Unsafe command")

executor = BlacktipExec(db=db)
executor.execute(command, ip=ip, mac=mac)
```

**Blacklisted patterns**:
- Backticks: `` `command` ``
- Command substitution: `$(command)`
- Shell variables: `$VAR`
- Semicolons in suspicious contexts: `; rm -rf /`

### Database Security

1. **SQL Injection Prevention**:
   ```python
   # WRONG
   cursor.execute("SELECT * FROM devices WHERE ip = '{}'".format(ip))

   # CORRECT
   cursor.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
   ```

2. **File Permissions**:
   ```bash
   # Production databases should be restricted
   chmod 600 /var/lib/blacktip/network.db
   chown root:root /var/lib/blacktip/network.db
   ```

3. **Backup Security**:
   ```bash
   # Backups contain network intel - encrypt them
   sqlite3 network.db ".backup network.db.bak"
   gpg -c network.db.bak
   rm network.db.bak
   ```

### Network Security

1. **Passive Monitoring** - No active traffic by default
2. **Nmap is Active** - Port scanning may trigger IDS/IPS
3. **ARP Cache Poisoning Detection** - Built-in anomaly detection
4. **Data Sensitivity** - Database contains network topology

---

## Deployment & Operations

### Systemd Service Setup

**Quick Install**:
```bash
cd blacktip
sudo bash install-service.sh [interface]
```

**Manual Setup**:
```bash
# 1. Install package
sudo pip install --break-system-packages .

# 2. Create directories
sudo mkdir -p /var/lib/blacktip /var/log/blacktip

# 3. Install service file
sudo cp blacktip.service /etc/systemd/system/
sudo chmod 644 /etc/systemd/system/blacktip.service

# 4. Configure service (edit ExecStart line)
sudo nano /etc/systemd/system/blacktip.service

# 5. Enable and start
sudo systemctl daemon-reload
sudo systemctl enable blacktip.service
sudo systemctl start blacktip.service
```

### Service Configuration

**Default service file** (`blacktip.service`):
```ini
[Unit]
Description=Blacktip Network Security Scanner
After=network.target
Documentation=https://github.com/mhawthorne-nip/blacktip

[Service]
Type=simple
User=root
Environment="BLACKTIP_LOG_FILE=/var/log/blacktip/blacktip.log"
Environment="BLACKTIP_LOG_LEVEL=info"
ExecStart=/usr/local/bin/blacktip \
    --datafile /var/lib/blacktip/blacktip.db \
    --interval 300 \
    --nmap \
    --metrics \
    --metrics-interval 300
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Customization options**:
- `--interface eth0` - Specify network interface
- `--no-nmap` - Disable port scanning
- `--no-metrics` - Disable metrics collection
- `-i 60` - Change save interval (seconds)
- `--all-request --all-reply` - Monitor all traffic (high volume)

### Log Management

**File Logging**:
```bash
# Configured via environment variable
Environment="BLACKTIP_LOG_FILE=/var/log/blacktip/blacktip.log"

# View logs
sudo tail -f /var/log/blacktip/blacktip.log
```

**Journald Logging**:
```bash
# View service logs
sudo journalctl -u blacktip.service -f

# View recent logs
sudo journalctl -u blacktip.service -n 100

# View logs from specific time
sudo journalctl -u blacktip.service --since "2025-01-15 10:00:00"
```

**Log Rotation** (`/etc/logrotate.d/blacktip`):
```
/var/log/blacktip/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        systemctl reload blacktip.service >/dev/null 2>&1 || true
    endscript
}
```

### Database Management

**Location**: `/var/lib/blacktip/blacktip.db` (default)

**Backup**:
```bash
# Online backup (safe while running)
sqlite3 /var/lib/blacktip/blacktip.db ".backup /backup/blacktip-$(date +%Y%m%d).db"

# Encrypted backup
sqlite3 /var/lib/blacktip/blacktip.db ".backup /tmp/blacktip.db"
gpg -c /tmp/blacktip.db
mv /tmp/blacktip.db.gpg /backup/
rm /tmp/blacktip.db
```

**Maintenance**:
```bash
# Vacuum and optimize (run weekly)
sqlite3 /var/lib/blacktip/blacktip.db 'VACUUM; ANALYZE;'

# Check integrity
sqlite3 /var/lib/blacktip/blacktip.db 'PRAGMA integrity_check;'

# View statistics
sqlite3 /var/lib/blacktip/blacktip.db "
SELECT
    (SELECT COUNT(*) FROM devices) as total_devices,
    (SELECT COUNT(DISTINCT ip_address) FROM devices) as unique_ips,
    (SELECT COUNT(DISTINCT mac_address) FROM devices) as unique_macs,
    (SELECT COUNT(*) FROM nmap_scans) as nmap_scans
"
```

### Monitoring the Monitor

**Health Checks**:
```bash
# Service status
sudo systemctl status blacktip.service

# Check if process is running
pgrep -f blacktip

# Resource usage
top -p $(pgrep -f blacktip)

# Database activity
sudo lsof /var/lib/blacktip/blacktip.db
```

**Performance Metrics**:
```bash
# Enable metrics in service
ExecStart=/usr/local/bin/blacktip ... --metrics --metrics-interval 60

# Metrics are logged to file/journal
sudo journalctl -u blacktip.service | grep "Metrics:"
```

---

## Troubleshooting Guide

### Common Issues

#### 1. Permission Denied

**Symptoms**:
```
ERROR: blacktip requires root privileges to sniff network interfaces!
```

**Solutions**:
```bash
# Run with sudo
sudo blacktip -f network.db

# Or grant capabilities (advanced)
sudo setcap cap_net_raw=eip $(readlink -f $(which python3))
```

#### 2. No Packets Captured

**Symptoms**: Blacktip runs but never outputs events

**Diagnostics**:
```bash
# Check interface has traffic
ip -s link show

# Verify ARP traffic exists
sudo tcpdump -i eth0 arp -c 5

# Test with specific interface
sudo blacktip -f /tmp/test.db --interface eth0 --debug

# Monitor all traffic
sudo blacktip -f /tmp/test.db --all-request --all-reply
```

#### 3. Database Locked

**Symptoms**: `database is locked` error

**Causes**:
- Multiple blacktip instances writing to same DB
- Long-running transaction
- NFS/network filesystem issues

**Solutions**:
```bash
# Check for multiple instances
ps aux | grep blacktip

# Kill duplicate processes
sudo pkill -f blacktip

# Use separate databases for multiple interfaces
sudo blacktip -f /var/lib/blacktip/eth0.db --interface eth0
sudo blacktip -f /var/lib/blacktip/eth1.db --interface eth1
```

#### 4. Nmap Not Found

**Symptoms**: No nmap scan results in database

**Solutions**:
```bash
# Install nmap
sudo apt-get install nmap  # Debian/Ubuntu
sudo dnf install nmap      # Fedora
sudo yum install nmap      # RHEL/CentOS

# Verify installation
which nmap
nmap --version

# Or disable nmap
sudo blacktip -f network.db --no-nmap
```

#### 5. High CPU Usage

**Symptoms**: Blacktip consuming significant CPU

**Causes**:
- High ARP traffic volume
- `--all-request --all-reply` on busy network
- Continuous nmap scans

**Solutions**:
```bash
# Reduce overhead
sudo blacktip -f network.db --no-nmap --no-metrics -i 120

# Monitor only new devices (default)
sudo blacktip -f network.db

# Check network traffic volume
sudo tcpdump -i eth0 arp | pv > /dev/null
```

#### 6. MAC Vendor Lookup Fails

**Symptoms**: `hw.vendor` is `null` in output

**Causes**:
- MAC not in OUI database
- Locally administered MAC address
- Network connectivity issue during DB update

**Solutions**:
- **Normal for private MACs** - Not an error
- **Check network** - Initial setup requires internet for OUI DB download
- **Cache is used** - Vendor DB updates are skipped if valid cache exists

### Debug Mode

**Enable comprehensive logging**:
```bash
sudo blacktip -f /tmp/test.db --debug
```

**Debug output includes**:
- Function entry/exit
- Packet processing details
- Database operations
- Command execution
- MAC vendor lookups
- Nmap scan triggers

### Getting Help

1. **Check README.md** - User documentation
2. **Check SYSTEMD_SETUP.md** - Service deployment
3. **Check CLAUDE.md** - This file for architecture
4. **Check GitHub Issues** - Known issues and solutions
5. **Enable debug logging** - Capture detailed diagnostics

---

## AI Assistant Guidelines

### When Working with This Codebase

#### 1. Understand the Context

**Always consider**:
- **Security implications** - This tool runs as root and captures network traffic
- **Production usage** - Code runs 24/7 in security monitoring contexts
- **Error handling** - Network operations can fail unpredictably
- **Performance** - Busy networks generate high packet rates

**Before suggesting changes**:
- Read related code in `utils/` modules
- Check how similar functionality is implemented
- Consider backward compatibility
- Think about error conditions

#### 2. Code Changes

**When adding features**:
1. Follow existing patterns (see Code Conventions section)
2. Add input validation for all external inputs
3. Include comprehensive error handling
4. Add logging at appropriate levels
5. Write tests for new functionality
6. Update relevant documentation

**When fixing bugs**:
1. Understand root cause before patching
2. Check if bug exists in related code
3. Add test to prevent regression
4. Consider if fix requires database migration
5. Document fix in commit message

**When refactoring**:
1. Maintain existing behavior
2. Update tests to match changes
3. Consider impact on production deployments
4. Document breaking changes clearly

#### 3. Security Focus

**Always**:
- Validate and sanitize all inputs
- Use parameterized SQL queries
- Avoid shell command execution
- Check for command injection vectors
- Consider privilege implications
- Review error messages for information leakage

**Never**:
- Execute arbitrary user commands without validation
- Trust network packet contents without verification
- Use string formatting for SQL queries
- Disable security checks for convenience
- Assume inputs are safe

#### 4. Testing Requirements

**For all changes**:
1. Run existing tests: `pytest`
2. Add new tests for new functionality
3. Test with both fresh and existing databases
4. Test error conditions
5. Test as root (for packet capture features)

**For security-related changes**:
1. Test input validation thoroughly
2. Test edge cases and boundary conditions
3. Test with malicious inputs
4. Verify sanitization functions work correctly

#### 5. Documentation Updates

**Update documentation when**:
- Adding CLI arguments → README.md
- Changing architecture → CLAUDE.md (this file)
- Modifying database schema → SYSTEMD_SETUP.md
- Adding dependencies → README.md, pyproject.toml
- Changing service configuration → SYSTEMD_SETUP.md

**Documentation standards**:
- Use clear, concise language
- Include code examples
- Explain why, not just what
- Update version/date stamps
- Maintain table of contents

#### 6. Git Workflow

**Commit messages**:
```
Brief summary of change (50 chars or less)

Detailed explanation of:
- What changed and why
- Any breaking changes
- Migration steps if needed
- Related issue numbers

Examples:
- Fix MAC vendor lookup by replacing broken library update_vendors()
- Add systemd service setup and remove deprecated scripts
- Prevent duplicate logging handlers in Logger initialization
```

**Branch naming**:
- `feature/description` - New features
- `fix/description` - Bug fixes
- `refactor/description` - Code refactoring
- `docs/description` - Documentation only
- `test/description` - Test improvements

#### 7. Communication Style

**When explaining code**:
- Reference specific files and line numbers
- Use format: `file_path:line_number`
- Quote relevant code snippets
- Explain design decisions
- Mention alternatives considered

**When suggesting changes**:
- Explain rationale clearly
- Note potential risks
- Suggest testing approach
- Indicate if breaking change
- Provide migration path

#### 8. Common Tasks

**Adding a CLI option**:
1. Add constant to `__init__.py`
2. Add argument to `cli/entrypoints.py`
3. Pass to `blacktip.py` method
4. Implement functionality
5. Add tests
6. Update README.md

**Adding a database field**:
1. Modify schema in `utils/database.py`
2. Handle existing databases (migration)
3. Update related queries
4. Test with fresh and existing DBs
5. Document migration steps

**Adding a validation function**:
1. Add to `utils/validation.py`
2. Return `(bool, Optional[str])` format
3. Write comprehensive tests
4. Use in appropriate locations
5. Consider adding sanitization function

#### 9. Red Flags to Watch For

**Code smells**:
- Bare `except:` clauses → Use specific exceptions
- String concatenation for SQL → Use parameterized queries
- `.format()` for shell commands → Use subprocess with list
- Global state → Use instance variables
- Hardcoded paths → Use configuration constants
- Missing error handling → Add try/except with logging

**Security concerns**:
- User input in commands → Validate and sanitize
- Shell=True in subprocess → Avoid or validate heavily
- Root privilege required → Document why necessary
- Network data trusted → Validate all packet contents
- File operations → Check permissions first

#### 10. Testing Philosophy

**Test pyramid**:
1. **Unit tests** - Fast, focused, numerous
   - Validation functions
   - Utility functions
   - Parsing logic

2. **Integration tests** - Slower, broader, fewer
   - Database operations
   - Command execution
   - Packet processing

3. **Manual tests** - Slowest, comprehensive, rare
   - Full system operation
   - Service deployment
   - Performance under load

**What to test**:
- ✅ Input validation
- ✅ Error handling
- ✅ Edge cases
- ✅ Security functions
- ✅ Database operations
- ❌ External dependencies (mock them)
- ❌ Third-party libraries
- ❌ Trivial getters/setters

---

## Quick Reference

### File Locations

| Purpose | Path |
|---------|------|
| Main logic | `src/blacktip/blacktip.py` |
| CLI entry | `src/blacktip/cli/entrypoints.py` |
| Configuration | `src/blacktip/__init__.py` |
| Database | `src/blacktip/utils/database.py` |
| Validation | `src/blacktip/utils/validation.py` |
| Logging | `src/blacktip/utils/logger.py` |
| Tests | `tests/test_*.py` |
| User docs | `README.md` |
| Service docs | `SYSTEMD_SETUP.md` |
| AI guide | `CLAUDE.md` (this file) |

### Key Commands

```bash
# Development
pip install -e ".[all]"                    # Install dev mode
pytest                                     # Run tests
pytest --cov=src/blacktip                  # Run with coverage
blacktip --version                         # Check installation

# Running
sudo blacktip -f network.db                # Basic monitoring
sudo blacktip -f network.db --debug        # Debug mode
sudo blacktip -f network.db -q 192.168.1.1 # Query database

# Service
sudo systemctl status blacktip.service     # Check status
sudo journalctl -u blacktip.service -f     # Follow logs
sudo systemctl restart blacktip.service    # Restart service

# Database
sqlite3 network.db ".schema"               # View schema
sqlite3 network.db "SELECT * FROM devices" # Query devices
sqlite3 network.db "VACUUM; ANALYZE;"      # Optimize
```

### Important Patterns

```python
# Logging
from blacktip.utils import logger
logger.info("Message with {}".format(var))

# Database access
with self._get_connection() as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE ip = ?", (ip,))

# Validation
from blacktip.utils.validation import validate_ip_address
is_valid, error = validate_ip_address(ip)
if not is_valid:
    logger.error("Invalid IP: {}".format(error))
    return

# Error handling
try:
    operation()
except SpecificException as e:
    logger.error("Operation failed: {}".format(e))
    raise BlacktipException("User message") from e
```

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2025-11-17 | 1.0 | Initial CLAUDE.md creation |

---

## Additional Resources

- **GitHub Repository**: https://github.com/mhawthorne-nip/blacktip
- **User Documentation**: README.md
- **Service Setup**: SYSTEMD_SETUP.md
- **Issue Tracker**: https://github.com/mhawthorne-nip/blacktip/issues

---

**End of CLAUDE.md**
