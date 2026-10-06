# config/env_config.py
"""
Configuration module for environment variables.
Loads from .env and .env.secret files, with .env.secret taking precedence.
"""

import os
from dotenv import dotenv_values

# Load environment variables from .env and .env.secret files
# Variables in .env.secret will override those with the same name in .env
config = {
    **dotenv_values(".env"),
    **dotenv_values(".env.secret")
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

# Allow environment variables to override config files
# This is useful for Docker and production environments
if os.environ.get('DATABASE_URL'):
    DATABASE_URL = os.environ.get('DATABASE_URL')
if os.environ.get('ELEVENLABS_API_KEY'):
    ELEVENLABS_API_KEY = os.environ.get('ELEVENLABS_API_KEY')

# Validate critical configuration
if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in environment or config files")
