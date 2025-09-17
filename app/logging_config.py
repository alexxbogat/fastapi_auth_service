import logging
import os
from enum import Enum
from settings import LOGGING_MODE

LOG_DIR = 'app/logs'
os.makedirs(LOG_DIR, exist_ok=True)


class LoggingMode(str, Enum):
    LOCAL = 'local'
    DEV = 'dev'
    PROD = 'prod'


def configure_logging():
    logger = logging.getLogger()
    logger.handlers.clear()
    formatter = logging.Formatter(
        fmt='[%(asctime)s] %(levelname)-8s - %(module)s:%(lineno)d - %(funcName)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    try:
        mode = LoggingMode(LOGGING_MODE)
    except ValueError:
        raise ValueError(f'Invalid logging mode: {LOGGING_MODE}')

    log_level = logging.INFO if mode != LoggingMode.PROD else logging.ERROR
    logger.setLevel(log_level)

    file_handler = logging.FileHandler(os.path.join(LOG_DIR, f'{mode.value}.log'))
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if mode == LoggingMode.DEV:
        logging.getLogger('sqlalchemy.engine').setLevel(logging.CRITICAL)
