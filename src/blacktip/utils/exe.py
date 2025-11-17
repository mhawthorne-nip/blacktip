import time
import subprocess
import shlex
from threading import Thread
from typing import Optional, Dict, Any, List
import psutil

from blacktip import __exec_max_runtime__ as EXEC_MAX_RUNTIME
from .utils import timestamp
from . import logger
from .nmap_parser import parse_nmap_xml
from .dns_resolver import reverse_dns_lookup
from .classifier import DeviceClassifier


class BlacktipExec:
    """Execute commands asynchronously with proper security and error handling"""

    def __init__(self, db=None):
        """Initialize BlacktipExec

        Args:
            db: BlacktipDatabase instance for storing nmap results (optional)
        """
        self.db = db
        self.subprocess_list: List[Dict[str, Any]] = []  # Instance variable, not class variable

    def async_command_exec_thread(self, exec_command: str, packet_data: Dict[str, Any], as_user: Optional[str] = None) -> None:
        """Execute command asynchronously in a thread

        Args:
            exec_command: Command template with {IP}, {HW}, {TS} placeholders
            packet_data: Packet data dictionary with ip/hw information
            as_user: Optional user to execute command as (via sudo)
        """
        if exec_command is None:
            return

        logger.debug("BlacktipExec.async_command_exec_thread(exec_command={}, as_user={})".format(
            exec_command[:50] + "..." if len(exec_command) > 50 else exec_command,
            as_user
        ))

        try:
            # Format command with packet data
            command_line = exec_command.format(
                IP=packet_data["ip"]["addr"],
                HW=packet_data["hw"]["addr"],
                TS=timestamp(),
                ts=timestamp().replace("+00:00", "").replace(":", "").replace("-", "").replace("T", "Z"),
            )
        except KeyError as e:
            logger.error("Unsupported {{KEY}} in exec command: {}. Valid values are {{IP}}, {{HW}}, {{TS}}".format(e))
            return  # Don't exit, just skip this command
        except Exception as e:
            logger.error("Error formatting exec command: {}".format(e))
            return

        # If as_user specified, construct sudo command securely
        if as_user is not None:
            # Validate username (prevent injection)
            if not as_user.replace('_', '').replace('-', '').isalnum():
                logger.error("Invalid username for sudo: {}. Username must be alphanumeric with _ or -".format(as_user))
                return

            # Build command as list for security
            cmd_parts = shlex.split(command_line)
            command_line = ['sudo', '-u', as_user] + cmd_parts

        thread = Thread(target=self.command_exec, args=(command_line,), daemon=True)
        thread.start()

    def async_command_exec_threads_wait(self, wait_max: int = EXEC_MAX_RUNTIME) -> None:
        """Wait for async command threads to complete

        Args:
            wait_max: Maximum time to wait in seconds
        """
        wait_elapsed = 0
        wait_start = time.time()
        logger.debug("BlacktipExec.async_command_exec_threads_wait(wait_max={})".format(wait_max))

        while len(self.subprocess_list) > 0 and wait_elapsed < wait_max:
            for i in range(len(self.subprocess_list) - 1, -1, -1):  # Iterate backwards for safe removal
                sp_data = self.subprocess_list[i]
                sp = sp_data['process']
                is_nmap = sp_data['is_nmap']
                command = sp_data.get('command', 'unknown')

                if sp.poll() is not None:
                    # Process has completed
                    if sp.returncode == 0 and is_nmap and self.db is not None:
                        # Successfully completed nmap scan - parse and store results
                        try:
                            stdout, stderr = sp.communicate(timeout=1)
                            if stdout:
                                xml_content = stdout.decode('utf-8', errors='ignore')
                                scan_data = parse_nmap_xml(xml_content)
                                if scan_data:
                                    # Insert nmap scan data
                                    self.db.insert_nmap_scan(scan_data)
                                    logger.info("Nmap scan saved to database for {}".format(
                                        scan_data.get('ip_address')))

                                    ip_address = scan_data.get('ip_address')

                                    # Perform DNS reverse lookup
                                    try:
                                        hostname, response_time_ms, forward_validates = reverse_dns_lookup(ip_address)
                                        if hostname or response_time_ms is not None:
                                            self.db.upsert_dns_data(
                                                ip_address,
                                                hostname,
                                                forward_validates,
                                                response_time_ms
                                            )
                                            logger.debug("DNS lookup completed for {}: {}".format(
                                                ip_address, hostname or 'no PTR record'))
                                    except Exception as e:
                                        logger.warning("DNS lookup failed for {}: {}".format(ip_address, e))

                                    # Perform device classification
                                    try:
                                        # Gather classification data
                                        classification_input = {
                                            'vendor': scan_data.get('mac_vendor'),
                                            'os_name': scan_data.get('os_name'),
                                            'ports': scan_data.get('ports', []),
                                            'hostname': hostname if hostname else scan_data.get('hostname'),
                                            'netbios_name': None
                                        }

                                        # Get NetBIOS computer name if available
                                        netbios_data = scan_data.get('netbios')
                                        if netbios_data:
                                            classification_input['netbios_name'] = (
                                                netbios_data.get('netbios_computer_name') or
                                                netbios_data.get('smb_computer_name')
                                            )

                                        # Classify device
                                        classification = DeviceClassifier.classify_device(classification_input)

                                        # Store classification if we got something useful
                                        if classification.get('device_type') != 'unknown':
                                            self.db.upsert_classification_data(ip_address, classification)
                                            logger.debug("Device classified as {} (confidence: {:.2f})".format(
                                                classification['device_type'],
                                                classification['confidence_score']))
                                    except Exception as e:
                                        logger.warning("Device classification failed for {}: {}".format(ip_address, e))

                                else:
                                    logger.warning("Failed to parse nmap XML output for command: {}".format(command[:100]))
                            else:
                                logger.warning("Nmap command produced no output: {}".format(command[:100]))
                        except subprocess.TimeoutExpired:
                            logger.error("Timeout waiting for nmap output: {}".format(command[:100]))
                        except Exception as e:
                            logger.error("Failed to process nmap output for command '{}': {}".format(command[:100], e))
                    elif sp.returncode > 0:
                        # Command failed
                        try:
                            stdout, stderr = sp.communicate(timeout=1) if sp.stdout else (None, None)
                            if stderr:
                                logger.warning("Command '{}' returned error (code {}): {}".format(
                                    command[:100], sp.returncode, stderr.decode('utf-8', errors='ignore')[:200]))
                            else:
                                logger.warning("Command '{}' returned non-zero code: {}".format(
                                    command[:100], sp.returncode))
                        except subprocess.TimeoutExpired:
                            logger.warning("Command '{}' failed (code {}) and timed out reading output".format(
                                command[:100], sp.returncode))
                        except Exception as e:
                            logger.error("Error reading output from failed command '{}': {}".format(command[:100], e))

                    self.subprocess_list.pop(i)

            time.sleep(0.10)  # 100ms
            wait_elapsed = time.time() - wait_start

        # Clean up any remaining processes that exceeded timeout
        if len(self.subprocess_list) > 0:
            logger.warning("Terminating {} subprocess(es) that exceeded timeout of {}s".format(
                len(self.subprocess_list), wait_max))

        for i in range(len(self.subprocess_list) - 1, -1, -1):
            sp_data = self.subprocess_list[i]
            sp = sp_data['process']
            command = sp_data.get('command', 'unknown')
            if sp.poll() is None:
                logger.warning("Terminating subprocess that exceeded timeout: {}".format(command[:100]))
                self.terminate_process(sp.pid)
                self.subprocess_list.pop(i)

        logger.debug("BlacktipExec.async_command_exec_threads_wait() - done")

    def command_exec(self, command_line) -> None:
        """Execute command and store process handle

        Args:
            command_line: Command as string or list of arguments
        """
        # Convert to string for logging and nmap detection
        if isinstance(command_line, list):
            command_str = ' '.join(command_line)
        else:
            command_str = command_line

        logger.debug('BlacktipExec.command_exec(command_line="{}")'.format(
            command_str[:100] + "..." if len(command_str) > 100 else command_str
        ))

        # Check if this is an nmap command
        is_nmap = 'nmap' in command_str.lower() and '-oX' in command_str

        try:
            # Parse command securely - NEVER use shell=True
            if isinstance(command_line, list):
                # Already a list (e.g., from sudo construction)
                cmd_parts = command_line
            else:
                # Parse string into list
                try:
                    cmd_parts = shlex.split(command_line)
                except ValueError as e:
                    logger.error('Failed to parse command: {}'.format(e))
                    return

            # Execute without shell for security (Linux only - no Windows support)
            process = subprocess.Popen(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                shell=False  # NEVER use shell=True
            )

            # Store process with metadata
            self.subprocess_list.append({
                'process': process,
                'is_nmap': is_nmap,
                'command': command_str[:200]  # Store truncated command for debugging
            })
            logger.debug('Started subprocess with PID: {}'.format(process.pid))

        except FileNotFoundError as e:
            logger.error('Command not found: {}. Error: {}'.format(cmd_parts[0] if cmd_parts else 'unknown', e))
        except PermissionError as e:
            logger.error('Permission denied executing command: {}. Error: {}'.format(command_str[:100], e))
        except Exception as e:
            logger.error('Failed to execute command: {}. Error: {}'.format(command_str[:100], e))

    def terminate_process(self, pid: int) -> None:
        """Terminate a process gracefully, then forcefully if needed

        Args:
            pid: Process ID to terminate
        """
        logger.warning("BlacktipExec.terminate_process(pid={})".format(pid))

        try:
            process = psutil.Process(pid)

            # Terminate all child processes first
            for process_child in process.children(recursive=True):
                try:
                    process_child.terminate()
                except psutil.NoSuchProcess:
                    pass

            # Terminate parent process
            process.terminate()

            # Wait up to 5 seconds for graceful termination
            try:
                process.wait(timeout=5)
                logger.debug("Process {} terminated gracefully".format(pid))
            except psutil.TimeoutExpired:
                # Force kill if still running
                logger.warning("Process {} did not terminate gracefully, forcing kill".format(pid))
                for process_child in process.children(recursive=True):
                    try:
                        process_child.kill()
                    except psutil.NoSuchProcess:
                        pass
                process.kill()
                logger.debug("Process {} forcefully killed".format(pid))

        except psutil.NoSuchProcess:
            logger.debug("Process {} already terminated".format(pid))
        except PermissionError as e:
            logger.error("Permission denied terminating process {}: {}".format(pid, e))
        except Exception as e:
            logger.error("Error terminating process {}: {}".format(pid, e))
