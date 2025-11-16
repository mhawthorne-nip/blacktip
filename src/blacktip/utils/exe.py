import time
import subprocess
import shlex
import os
from threading import Thread
import psutil

from blacktip import __exec_max_runtime__ as EXEC_MAX_RUNTIME
from .utils import timestamp
from . import logger
from .nmap_parser import parse_nmap_xml


class BlacktipExec:

    subprocess_list = []

    def __init__(self, db=None):
        """Initialize BlacktipExec

        Args:
            db: BlacktipDatabase instance for storing nmap results (optional)
        """
        self.db = db

    def async_command_exec_thread(self, exec_command, packet_data, as_user=None):
        if exec_command is None:
            return

        logger.debug("Blacktip.async_command_exec(<exec_command>, <packet_data>, <as_user>)")

        try:
            command_line = exec_command.format(
                IP=packet_data["ip"]["addr"],
                HW=packet_data["hw"]["addr"],
                TS=timestamp(),
                ts=timestamp().replace("+00:00", "").replace(":", "").replace("-", "").replace("T", "Z"),
            )
        except KeyError:
            logger.critical("Unsupported {KEY} supplied in exec command, valid values are {IP}, {HW} and {TS}")
            exit(1)

        if as_user is not None:
            command_line = "sudo -u {} {}".format(as_user, command_line)

        thread = Thread(target=self.command_exec, args=(command_line,))
        thread.start()

    def async_command_exec_threads_wait(self, wait_max=EXEC_MAX_RUNTIME):
        wait_elapsed = 0
        wait_start = time.time()
        logger.debug("Blacktip.async_command_exec_threads_wait(wait_max={})".format(wait_max))

        while len(self.subprocess_list) > 0 and wait_elapsed < wait_max:
            for i in range(len(self.subprocess_list) - 1, -1, -1):  # Iterate backwards for safe removal
                sp_data = self.subprocess_list[i]
                sp = sp_data['process']
                is_nmap = sp_data['is_nmap']

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
                                    self.db.insert_nmap_scan(scan_data)
                                    logger.info("Nmap scan saved to database for {}".format(
                                        scan_data.get('ip_address')))
                                else:
                                    logger.warning("Failed to parse nmap XML output")
                        except Exception as e:
                            logger.error("Failed to process nmap output: {}".format(e))
                    elif sp.returncode > 0:
                        stdout, stderr = sp.communicate(timeout=1) if sp.stdout else (None, None)
                        if stderr:
                            logger.warning("exec thread returned error: {}".format(stderr.decode('utf-8', errors='ignore')[:200]))
                        else:
                            logger.warning("exec thread returned with non-zero returncode: {}".format(sp.returncode))

                    self.subprocess_list.pop(i)
            time.sleep(0.10)  # 100ms
            wait_elapsed = time.time() - wait_start

        # Clean up any remaining processes
        for i in range(len(self.subprocess_list) - 1, -1, -1):
            sp_data = self.subprocess_list[i]
            sp = sp_data['process']
            if sp.poll() is None:
                self.terminate_process(sp.pid)
                self.subprocess_list.pop(i)
        logger.debug("Blacktip.async_command_exec_threads_wait() - done")

    def command_exec(self, command_line):
        logger.debug('Blacktip.command_exec(command_line="{}")'.format(command_line))

        # Check if this is an nmap command
        is_nmap = 'nmap' in command_line.lower() and '-oX' in command_line

        try:
            # Parse command securely - don't use shell=True to prevent injection
            if os.name == 'nt':  # Windows
                # On Windows, we need shell for some commands
                process = subprocess.Popen(
                    command_line,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL
                )
            else:  # Unix/Linux
                # On Unix, use shlex.split for security
                try:
                    cmd_parts = shlex.split(command_line)
                    process = subprocess.Popen(
                        cmd_parts,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.DEVNULL
                    )
                except ValueError as e:
                    logger.error('Failed to parse command: {}'.format(e))
                    return

            # Store process with metadata
            self.subprocess_list.append({
                'process': process,
                'is_nmap': is_nmap
            })
            logger.debug('Started subprocess with PID: {}'.format(process.pid))
        except Exception as e:
            logger.error('Failed to execute command: {}'.format(e))

    def terminate_process(self, pid):
        logger.warning("Blacktip.terminate_process(pid={})".format(pid))

        try:
            # https://stackoverflow.com/questions/4789837/how-to-terminate-a-python-subprocess-launched-with-shell-true
            process = psutil.Process(pid)
            for process_child in process.children(recursive=True):
                try:
                    process_child.terminate()
                except psutil.NoSuchProcess:
                    pass
            process.terminate()
            
            # Wait up to 5 seconds for graceful termination
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                # Force kill if still running
                logger.warning("Process {} did not terminate, forcing kill".format(pid))
                for process_child in process.children(recursive=True):
                    try:
                        process_child.kill()
                    except psutil.NoSuchProcess:
                        pass
                process.kill()
        except psutil.NoSuchProcess:
            logger.debug("Process {} already terminated".format(pid))
        except Exception as e:
            logger.error("Error terminating process {}: {}".format(pid, e))
