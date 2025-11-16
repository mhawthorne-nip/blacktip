"""Security utilities for blacktip"""
import os
import sys

try:
    import pwd
    import grp
except ImportError:
    pwd = None
    grp = None

from . import logger


class SecurityManager:
    """Manage security features like privilege dropping"""
    
    @staticmethod
    def drop_privileges(username=None, groupname=None):
        """
        Drop root privileges to a less privileged user.
        Should be called after opening raw sockets.
        
        Args:
            username: Username to drop to (default: 'nobody')
            groupname: Group to drop to (default: 'nogroup' or username's group)
        """
        if os.name == 'nt' or not pwd or not grp:
            logger.warning("Privilege dropping not supported on Windows")
            return False
        
        if os.getuid() != 0:
            logger.debug("Not running as root, skipping privilege drop")
            return False
        
        try:
            # Default to nobody user
            if username is None:
                username = 'nobody'
            
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
    def validate_command_safe(command_template):
        """
        Validate that a command template is reasonably safe.
        Checks for obvious shell injection patterns.
        
        Args:
            command_template: The command template string
            
        Returns:
            tuple: (is_safe: bool, warnings: list)
        """
        if not command_template:
            return True, []
        
        warnings = []
        dangerous_patterns = [
            (';', 'contains semicolon (command chaining)'),
            ('&&', 'contains && (command chaining)'),
            ('||', 'contains || (command chaining)'),
            ('`', 'contains backticks (command substitution)'),
            ('$(', 'contains $( (command substitution)'),
            ('|', 'contains pipe (command chaining)'),
            ('>', 'contains redirect'),
            ('<', 'contains redirect'),
        ]
        
        # Allow pipes and redirects in the template itself, but warn
        for pattern, message in dangerous_patterns:
            if pattern in command_template:
                # Check if it's in the template variables
                if pattern not in ['{IP}', '{HW}', '{TS}', '{ts}']:
                    warnings.append(message)
        
        # Critical issues that make it unsafe
        critical_patterns = ['$(', '`']
        is_safe = not any(p in command_template for p, _ in dangerous_patterns if p in critical_patterns)
        
        return is_safe, warnings
