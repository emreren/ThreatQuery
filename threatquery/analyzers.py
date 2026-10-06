# threatquery/analyzers.py

import asyncio
from threatquery.modules.alienvault import AlienVaultAnalyzer
from threatquery.modules.virustotal import VirusTotalAnalyzer
from threatquery.modules.threatfox import ThreatFoxAnalyzer
from threatquery.modules.googlesb import GoogleSBAnalyzer


ANALYZER_TYPES = {"ipv4": "ip", "ipv6": "ip", "hash": "file_hash"}
FIELDS = ("whois", "geo_location", "malicious", "blacklist", "suspicious",
          "threat_type", "malware_family", "first_seen", "tags")


class AnalysisResults:
    def __init__(self):
        self.whois = {}
        self.geo_location = {}
        self.malicious = {}
        self.blacklist = {}
        self.suspicious = {}
        self.threat_type = {}
        self.malware_family = {}
        self.first_seen = {}
        self.tags = {}


class IOCAnalyzer:
    def __init__(self):
        self.results = AnalysisResults()
        self.analyzers = [
            AlienVaultAnalyzer(),
            VirusTotalAnalyzer(),
            ThreatFoxAnalyzer(),
            GoogleSBAnalyzer(),
        ]

    async def analyze(self, ioc_value, ioc_type):
        # determine_ioc_type returns ipv4/ipv6/hash, the analyzers expect ip/file_hash
        analyzer_type = ANALYZER_TYPES.get(ioc_type, ioc_type)
        # The sources are independent, so they are queried at the same time; each analyzer
        # catches its own errors, and results keep the order of self.analyzers
        results = await asyncio.gather(
            *(analyzer.analyze(ioc_value, analyzer_type) for analyzer in self.analyzers)
        )
        for analyzer, result in zip(self.analyzers, results):
            for field in FIELDS:
                if hasattr(result, field):
                    getattr(self.results, field)[analyzer.name] = getattr(result, field)

        return self.results
