"""Configuration management for blacktip"""
import os
import json
import yaml
from . import logger


class Config:
    """Configuration manager supporting JSON and YAML config files"""
    
    DEFAULT_CONFIG = {
        "datafile": None,
        "save_interval": 30,
        "interface": None,
        "request_select": "new",  # new, all, nil
        "reply_select": "new",    # new, all, nil
        "exec_command": None,
        "exec_user": None,
        "drop_privileges": False,
        "drop_privileges_user": "nobody",
        "batch_size": 16,
        "batch_timeout": 2,
        "max_datafile_size_mb": 100,
        "enable_metrics": False,
        "metrics_interval": 300,  # Log metrics every 5 minutes
        "log_level": "info",
        # Active probing configuration
        "enable_active_probing": True,  # Enable active ARP/ICMP probing
        "probe_timeout": 1.0,  # Timeout in seconds per probe attempt
        "probe_retry_count": 2,  # Number of retries for failed probes
        "probe_failure_threshold": 2,  # Consecutive failures before marking offline
        "enable_icmp_fallback": True,  # Fall back to ICMP if ARP fails
        "probe_before_offline": True,  # Probe device before marking offline
        "periodic_probe_interval": 5,  # Probe all online devices every N cycles (0 = disabled)
        # State monitoring configuration
        "offline_threshold_seconds": 300,  # Mark offline after N seconds (default: 5 minutes)
        "state_monitor_interval": 60,  # Check interval in seconds
    }
    
    def __init__(self, config_file=None):
        """Initialize configuration from file or defaults"""
        self.config = self.DEFAULT_CONFIG.copy()
        
        if config_file:
            self.load_from_file(config_file)
    
    def load_from_file(self, filepath):
        """Load configuration from JSON or YAML file"""
        if not os.path.exists(filepath):
            logger.warning("Config file not found: {}".format(filepath))
            return False
        
        try:
            with open(filepath, 'r') as f:
                if filepath.endswith('.yaml') or filepath.endswith('.yml'):
                    try:
                        import yaml
                        loaded_config = yaml.safe_load(f)
                    except ImportError:
                        logger.error("PyYAML not installed, cannot load YAML config")
                        return False
                else:
                    loaded_config = json.load(f)
            
            # Merge loaded config with defaults
            self.config.update(loaded_config)
            logger.info("Loaded configuration from: {}".format(filepath))
            return True
            
        except Exception as e:
            logger.error("Error loading config file: {}".format(e))
            return False
    
    def get(self, key, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """Set configuration value"""
        self.config[key] = value
    
    def save_to_file(self, filepath):
        """Save current configuration to file"""
        try:
            with open(filepath, 'w') as f:
                if filepath.endswith('.yaml') or filepath.endswith('.yml'):
                    try:
                        import yaml
                        yaml.safe_dump(self.config, f, default_flow_style=False)
                    except ImportError:
                        logger.error("PyYAML not installed, cannot save YAML config")
                        return False
                else:
                    json.dump(self.config, f, indent=2)
            
            logger.info("Saved configuration to: {}".format(filepath))
            return True
            
        except Exception as e:
            logger.error("Error saving config file: {}".format(e))
            return False
    
    def to_dict(self):
        """Return configuration as dictionary"""
        return self.config.copy()
