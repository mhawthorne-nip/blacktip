import os
import json
import tempfile
import shutil
try:
    import fcntl
except ImportError:
    fcntl = None
import time

from blacktip import __version__ as VERSION
from .utils import timestamp
from . import logger


class BlacktipDataFile:
    
    @staticmethod
    def _lock_file(file_handle):
        """Lock file for exclusive access (Unix only)"""
        if fcntl:
            try:
                fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except IOError:
                logger.warning("Could not acquire file lock, waiting...")
                fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX)
                return True
        return True
    
    @staticmethod
    def _unlock_file(file_handle):
        """Unlock file (Unix only)"""
        if fcntl:
            try:
                fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)
            except Exception as e:
                logger.warning("Error unlocking file: {}".format(e))
    
    @staticmethod
    def read(filename):
        logger.debug("BlacktipDataFile.read(filename={})".format(filename))

        if os.path.isfile(filename):
            try:
                with open(filename, "r") as f:
                    BlacktipDataFile._lock_file(f)
                    try:
                        data = json.load(f)
                    finally:
                        BlacktipDataFile._unlock_file(f)
                
                # Validate data structure
                if not isinstance(data, dict) or "meta" not in data or "ip" not in data or "hw" not in data:
                    logger.error("Invalid data file structure, creating new file")
                    data = BlacktipDataFile._create_empty_data()
                else:
                    logger.debug("BlacktipDataFile.read() - data file loaded")
                    # Ensure all required meta fields exist
                    required_meta_fields = ["blacktip", "starts", "ts_first", "ts_last", "hw_count", "ip_count"]
                    for field in required_meta_fields:
                        if field not in data["meta"]:
                            logger.warning("Missing meta field: {}, adding default".format(field))
                            if field == "blacktip":
                                data["meta"][field] = VERSION
                            elif field in ["starts", "hw_count", "ip_count"]:
                                data["meta"][field] = 0
                            else:
                                data["meta"][field] = timestamp()
            except json.JSONDecodeError as e:
                logger.error("Corrupted data file: {}".format(e))
                # Try to backup corrupted file
                backup_name = "{}.corrupted.{}".format(filename, int(time.time()))
                try:
                    shutil.copy2(filename, backup_name)
                    logger.warning("Backed up corrupted file to: {}".format(backup_name))
                except Exception as be:
                    logger.error("Could not backup corrupted file: {}".format(be))
                data = BlacktipDataFile._create_empty_data()
            except Exception as e:
                logger.error("Error reading data file: {}".format(e))
                data = BlacktipDataFile._create_empty_data()
        else:
            logger.warning("BlacktipDataFile.read() - no existing data file found")
            data = BlacktipDataFile._create_empty_data()

        for meta_field in data["meta"]:
            logger.debug("{}: {}".format(meta_field, data["meta"][meta_field]))

        return data
    
    @staticmethod
    def _create_empty_data():
        """Create empty data structure"""
        return {
            "meta": {
                "blacktip": VERSION,
                "starts": 0,
                "ts_first": timestamp(),
                "ts_last": timestamp(),
                "hw_count": 0,
                "ip_count": 0,
            },
            "ip": {},
            "hw": {},
        }

    @staticmethod
    def write(filename, data):
        logger.debug("BlacktipDataFile.write(filename={}, data=<data>)".format(filename))

        # Create backup of existing file if it exists
        if os.path.isfile(filename):
            backup_name = "{}.backup".format(filename)
            try:
                shutil.copy2(filename, backup_name)
                logger.debug("Created backup: {}".format(backup_name))
            except Exception as e:
                logger.warning("Could not create backup: {}".format(e))
        
        # Atomic write: write to temp file then move
        temp_fd = None
        temp_path = None
        try:
            # Create temp file in same directory to ensure same filesystem
            dir_name = os.path.dirname(os.path.abspath(filename)) or '.'
            temp_fd, temp_path = tempfile.mkstemp(dir=dir_name, prefix='.blacktip_tmp_', suffix='.json')
            
            # Write to temp file
            with os.fdopen(temp_fd, 'w') as f:
                temp_fd = None  # Prevent double close
                json.dump(data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())  # Ensure data is written to disk
            
            # Atomic move (replace existing file)
            if os.name == 'nt':  # Windows
                # Windows doesn't allow atomic replace with rename
                if os.path.exists(filename):
                    os.remove(filename)
                shutil.move(temp_path, filename)
            else:  # Unix/Linux
                # Atomic replace on Unix
                os.rename(temp_path, filename)
            
            logger.debug("BlacktipDataFile.write() - datafile written")
            
        except Exception as e:
            logger.error("Error writing datafile: {}".format(e))
            # Clean up temp file on error
            if temp_fd is not None:
                try:
                    os.close(temp_fd)
                except:
                    pass
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:
                    pass
            raise
