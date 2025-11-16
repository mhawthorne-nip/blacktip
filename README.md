# blacktip

## Installation

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
