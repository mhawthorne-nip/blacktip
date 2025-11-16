"""Security utilities for blacktip (Linux only)"""
import os
from typing import Optional, Tuple, List
import pwd
import grp

from . import logger
from .validation import validate_username, validate_command_template
from blacktip.exceptions import BlacktipException


class SecurityManager:
    """Manage security features like privilege dropping and command validation"""

    @staticmethod
    def drop_privileges(username: Optional[str] = None, groupname: Optional[str] = None) -> bool:
        """Drop root privileges to a less privileged user (Linux only)

        Should be called after opening raw sockets.

        Args:
            username: Username to drop to (default: 'nobody')
            groupname: Group to drop to (default: username's primary group)

        Returns:
            True if privileges were dropped successfully, False otherwise

        Raises:
            BlacktipException: If not running on Linux
        """
        if os.getuid() != 0:
            logger.debug("Not running as root, skipping privilege drop")
            return False

        try:
            # Default to nobody user
            if username is None:
                username = 'nobody'

            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                logger.error("Invalid username: {}".format(error_msg))
                return False

            # Get user info
            try:
                pwnam = pwd.getpwnam(username)
            except KeyError:
                logger.error("User '{}' not found, cannot drop privileges".format(username))
                return False

            uid = pwnam.pw_uid
            gid = pwnam.pw_gid

            # If groupname specified, use that instead
            if groupname:
                is_valid, error_msg = validate_username(groupname)  # Groups follow same rules
                if not is_valid:
                    logger.warning("Invalid group name: {}. Using user's primary group".format(error_msg))
                else:
                    try:
                        gid = grp.getgrnam(groupname).gr_gid
                    except KeyError:
                        logger.warning("Group '{}' not found, using user's primary group".format(groupname))

            # Remove group privileges
            os.setgroups([])

            # Set GID and UID
            os.setgid(gid)
            os.setuid(uid)

            # Ensure privileges were dropped
            if os.getuid() == 0 or os.geteuid() == 0:
                logger.error("Failed to drop privileges!")
                return False

            logger.info("Dropped privileges to user '{}' (uid={}, gid={})".format(username, uid, gid))
            return True

        except Exception as e:
            logger.error("Error dropping privileges: {}".format(e))
            return False

    @staticmethod
    def validate_command_safe(command_template: str, raise_on_unsafe: bool = False) -> Tuple[bool, List[str]]:
        """Validate that a command template is safe from injection attacks

        Args:
            command_template: The command template string with placeholders
            raise_on_unsafe: If True, raise exception on unsafe patterns (default: False)

        Returns:
            Tuple of (is_safe: bool, warnings: list)

        Raises:
            BlacktipException: If command is unsafe and raise_on_unsafe is True
        """
        is_safe, warnings = validate_command_template(command_template)

        # Log warnings
        for warning in warnings:
            logger.warning("Command template security warning: {}".format(warning))

        # Raise exception if unsafe and requested
        if not is_safe and raise_on_unsafe:
            raise BlacktipException(
                "Unsafe command template detected: {}. Warnings: {}".format(
                    command_template[:100], ', '.join(warnings)
                )
            )

        return is_safe, warnings
