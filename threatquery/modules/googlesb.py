# threatquery/modules/googlesb.py

import logging
import httpx
from config.env_config import GOOGLESAFEBROWSING_API_KEY

logger = logging.getLogger(__name__)


class AnalysisResult:
    def __init__(self, whois, geo_location, malicious, blacklist):
        self.whois = whois
        self.geo_location = geo_location
        self.malicious = malicious
        self.blacklist = blacklist


class GoogleSBAnalyzer:
    def __init__(self):
        self.name = "GoogleSB"
        self.api_key = GOOGLESAFEBROWSING_API_KEY

    async def analyze(self, ioc_value, ioc_type):
        whois = await self.get_whois_info(ioc_value)
        geo_location = await self.get_geo_location(ioc_value)
        malicious = await self.check_malicious(ioc_value)
        blacklist = await self.check_blacklist(ioc_value)

        return AnalysisResult(
            whois=whois,
            geo_location=geo_location,
            malicious=malicious,
            blacklist=blacklist,
        )

    async def get_whois_info(self, ioc_value):

        whois_info = "God whois info"
        return whois_info

    async def get_geo_location(self, ioc_value):

        geo_location = "America"
        return geo_location

    async def check_malicious(self, ioc_value):

        malicious = "False"
        return malicious

    async def check_blacklist(self, ioc_value):

        blacklist = "True"
        return blacklist


