# config/env_config.py file

from dotenv import dotenv_values

config = {
    **dotenv_values(".env.shared"),
    **dotenv_values(".env.secret")
}

ALIENVAULT_API_KEY = config['ALIENVAULT_API_KEY']
VIRUSTOTAL_API_KEY = config['VIRUSTOTAL_API_KEY']
GOOGLESAFEBROWSING_API_KEY = config['GOOGLESAFEBROWSING_API_KEY']
WHOISXML_API_KEY = config['WHOISXML_API_KEY']
DATABASE_URL = config['DATABASE_URL']
