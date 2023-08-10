# threatquery/modules/alienvault.py

import logging
import httpx
from config.env_config import ALIENVAULT_API_KEY

logger = logging.getLogger(__name__)


class AnalysisResult:
    def __init__(self, geo_location, malicious, blacklist):
        self.geo_location = geo_location
        self.malicious = malicious
        self.blacklist = blacklist


class AlienVaultAnalyzer:
    def __init__(self):
        self.name = "AlienVault"
        self.api_key = ALIENVAULT_API_KEY

    async def analyze(self, ioc_value, ioc_type):
        geo_location = await self.get_geo_location(ioc_value)
        malicious = await self.check_malicious(ioc_value)
        blacklist = await self.check_blacklist(ioc_value)

        return AnalysisResult(
            geo_location=geo_location,
            malicious=malicious,
            blacklist=blacklist,
        )

    async def get_geo_location(self, ioc_value):

        geo_location = "United State America"
        return geo_location

    async def check_malicious(self, ioc_value):

        malicious = "False"
        return malicious

    async def check_blacklist(self, ioc_value):

        blacklist = "True"
        return blacklist


