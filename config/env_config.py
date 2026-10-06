# config/env_config.py
"""
Configuration module for environment variables.
Loads from .env and .env.secret files, with .env.secret taking precedence,
and environment variables taking precedence over both.
"""

import os
from dotenv import dotenv_values

# Variables in .env.secret override those with the same name in .env, and environment variables
# override both (Docker and production; .env.secret is not copied into the image)
config = {
    **dotenv_values(".env"),
    **dotenv_values(".env.secret"),
    **os.environ,
}

# API Keys for Threat Intelligence Services
ALIENVAULT_API_KEY = config.get('ALIENVAULT_API_KEY', '')
VIRUSTOTAL_API_KEY = config.get('VIRUSTOTAL_API_KEY', '')
GOOGLESAFEBROWSING_API_KEY = config.get('GOOGLESAFEBROWSING_API_KEY', '')
THREATFOX_API_KEY = config.get('THREATFOX_API_KEY', '')

# Text-to-speech for spoken briefings (/brief/)
ELEVENLABS_API_KEY = config.get('ELEVENLABS_API_KEY', '')
ELEVENLABS_VOICE_ID = config.get('ELEVENLABS_VOICE_ID', 'JBFqnCBsd6RMkjVDRZzb')

# Database Configuration
DATABASE_URL = config.get('DATABASE_URL', '')

# Application Settings
DEBUG = config.get('DEBUG', 'False').lower() in ('true', '1', 't')
LOG_LEVEL = config.get('LOG_LEVEL', 'INFO')
LOG_FILE = config.get('LOG_FILE', 'app.log')

# Validate critical configuration
if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in environment or config files")
