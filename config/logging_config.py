# config/logging_config.py file

from config.env_config import LOG_FILE, LOG_LEVEL


def get_logging_config():
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s - %(levelname)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "standard",
            },
            "file": {
                "class": "logging.FileHandler",
                "filename": LOG_FILE,
                "formatter": "standard",
            },
        },
        "root": {
            "handlers": ["console", "file"],
            "level": LOG_LEVEL.upper(),
        },
    }

    return logging_config
