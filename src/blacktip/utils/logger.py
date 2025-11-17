import time
import logging
import os
from pathlib import Path

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S %Z%z"


class LoggerException(Exception):
    pass


class LoggerColoredFormatter(logging.Formatter):

    color_line = "\x1b[90m"  # grey
    color_reset = "\x1b[0m"  # reset

    def __init__(self, **kwargs):
        if "fmt" in kwargs:
            kwargs["fmt"] = "{}{}{}".format(self.color_line, kwargs["fmt"], self.color_reset)
        logging.Formatter.__init__(self, **kwargs)

    def format(self, record):

        levelname = record.levelname.upper()

        if levelname == "CRITICAL":
            color_code = "\x1b[41m"  # white-on-red
        elif levelname == "ERROR":
            color_code = "\x1b[31m"  # red
        elif levelname in ("WARNING", "WARN"):
            color_code = "\x1b[33m"  # yellow
        elif levelname == "INFO":
            color_code = "\x1b[36m"  # cyan
        elif levelname == "DEBUG":
            color_code = "\x1b[37m"  # white
        else:
            color_code = "\x1b[90m"  # grey

        record.levelname = "{}{}{}".format(color_code, levelname, self.color_line)

        return logging.Formatter.format(self, record)


class Logger:

    name = None
    logger = None

    def __init__(self, name, level=None):

        if level is not None:
            log_level = level
        else:
            log_level = os.environ.get("BLACKTIP_LOG_LEVEL", "info")

        logger_init = logging.getLogger(name)
        
        # Check if already configured to prevent duplicate handlers
        if logger_init.handlers:
            self.logger = logger_init
            return

        logger_init.setLevel(logging.DEBUG)

        log_level = log_level.upper()
        
        # Determine the logging level
        if log_level in ("CRITICAL", "FATAL"):
            handler_level = logging.CRITICAL
        elif log_level == "ERROR":
            handler_level = logging.ERROR
        elif log_level in ("WARNING", "WARN"):
            handler_level = logging.WARNING
        elif log_level == "INFO":
            handler_level = logging.INFO
        elif log_level == "DEBUG":
            handler_level = logging.DEBUG
        elif log_level is not None:
            raise LoggerException("unknown loglevel value", log_level)
        else:
            handler_level = logging.NOTSET

        # Check if file logging is enabled via environment variable
        log_file = os.environ.get("BLACKTIP_LOG_FILE")
        
        if log_file:
            # File logging mode - use file handler with plain formatter
            log_file_path = Path(log_file)
            
            # Create log directory if it doesn't exist
            log_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, mode='a')
            file_handler.setLevel(handler_level)
            
            # Use plain formatter for file logging (no color codes)
            plain_formatter = logging.Formatter(
                fmt="%(asctime)s - %(levelname)s - %(message)s",
                datefmt=TIMESTAMP_FORMAT
            )
            logging.Formatter.converter = time.localtime
            
            file_handler.setFormatter(plain_formatter)
            logger_init.addHandler(file_handler)
        else:
            # Console logging mode - use stream handler with colored formatter
            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(handler_level)
            
            formatter = LoggerColoredFormatter(
                fmt="%(asctime)s - %(levelname)s - %(message)s",
                datefmt=TIMESTAMP_FORMAT
            )
            logging.Formatter.converter = time.localtime
            
            stream_handler.setFormatter(formatter)
            logger_init.addHandler(stream_handler)
        
        # Disable propagation to root logger to prevent duplicate console output
        logger_init.propagate = False

        self.logger = logger_init


def init(name, level="info"):
    global __logger
    __logger = Logger(name, level=level).logger


def debug(message):
    __logger.debug(message)


def info(message):
    __logger.info(message)


def warning(message):
    __logger.warning(message)


def error(message):
    __logger.error(message)


def critical(message):
    __logger.critical(message)
