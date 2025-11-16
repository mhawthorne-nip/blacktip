# blacktip

[![PyPi](https://img.shields.io/pypi/v/blacktip.svg)](https://pypi.python.org/pypi/blacktip/)
[![Python Versions](https://img.shields.io/pypi/pyversions/blacktip.svg)](https://github.com/mhawthorne-nip/blacktip/)
[![Build Tests](https://github.com/mhawthorne-nip/blacktip/actions/workflows/build-tests.yml/badge.svg)](https://github.com/mhawthorne-nip/blacktip/actions/workflows/build-tests.yml)
[![Read the Docs](https://img.shields.io/readthedocs/blacktip)](https://blacktip.readthedocs.io)
![License](https://img.shields.io/github/license/mhawthorne-nip/blacktip.svg)

A modern network monitoring tool with JSON formatted outputs and easy options to exec commands when network changes are 
observed.

Includes a convenience `--exec` definition to invoke nmap when new network-addresses are observed.

## Features
* Uses the Python `scapy` module to watch for network ARPs
* Filter ARP events based on new addresses only, or select all ARP events
* Easy to define `--exec` actions on ARP related events
* Quick to use `--nmap` action to invoke nmap if installed, easy network device landscaping
* Lookup of hardware addresses against the OUI database for manufacturer resolution
* ARP anomaly detection (IP/MAC conflicts, spoofing detection)
* Metrics collection and monitoring
* Atomic file operations with automatic backups
* Privilege dropping for enhanced security (Unix)
* Network interface selection
* Configuration file support (YAML/JSON)
* Logging available to STDERR
* Easy installation using PyPI `pip`

## Security Features
* Atomic file writes prevent data corruption
* File locking prevents concurrent access issues
* Privilege dropping reduces attack surface
* Comprehensive input validation
* Command injection protection

## Installation

### Using pip (system-wide)
```shell
user@computer:~$ pip install blacktip
```

### Using Python Virtual Environment (recommended)
```shell
# Create virtual environment
user@computer:~$ python3 -m venv ~/blacktip-venv

# Activate virtual environment
user@computer:~$ source ~/blacktip-venv/bin/activate

# Install blacktip
(blacktip-venv) user@computer:~$ pip install blacktip
```

### Installing from source (development)
```shell
# Create and activate virtual environment
user@computer:~$ python3 -m venv ~/blacktip-venv
user@computer:~$ source ~/blacktip-venv/bin/activate

# Install in editable mode
(blacktip-venv) user@computer:~$ cd /path/to/blacktip
(blacktip-venv) user@computer:~$ pip install -e .
```

## Command line usage
Use blacktip to nmap all new hosts on the network
```shell
# If installed system-wide
user@computer:~$ sudo blacktip --nmap --datafile /tmp/blacktip.dat

# If using virtual environment
user@computer:~$ sudo ~/blacktip-venv/bin/blacktip --nmap --datafile /tmp/blacktip.dat
```

Monitor a specific interface with metrics enabled
```shell
# If installed system-wide
user@computer:~$ sudo blacktip --interface eth0 --datafile /var/lib/blacktip/data.dat --metrics

# If using virtual environment
user@computer:~$ sudo ~/blacktip-venv/bin/blacktip --interface eth0 --datafile /var/lib/blacktip/data.dat --metrics
```

Run as systemd service (recommended for production)
```shell
user@computer:~$ sudo cp docs/blacktip.service /etc/systemd/system/
user@computer:~$ sudo systemctl enable --now blacktip
```

## Project
* Github - [github.com/mhawthorne-nip/blacktip](https://github.com/mhawthorne-nip/blacktip)
* PyPI - [pypi.python.org/pypi/blacktip](https://pypi.python.org/pypi/blacktip/)
* ReadTheDocs - [blacktip.readthedocs.io](https://blacktip.readthedocs.io)

---
Copyright &copy; 2021 Nicholas de Jong
