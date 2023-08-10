# threatquery/analyzers.py

import logging
from threatquery.modules.alienvault import AlienVaultAnalyzer
from threatquery.modules.virustotal import VirusTotalAnalyzer
from threatquery.modules.threatfox import ThreatFoxAnalyzer
from threatquery.modules.googlesb import GoogleSBAnalyzer
from threatquery.modules.ioc_type_identifier import determine_ioc_type


class AnalysisResults:
    def __init__(self):
        self.whois = {}
        self.geo_location = {}
        self.malicious = {}
        self.blacklist = {}


class IOCAnalyzer:
    def __init__(self):
        self.results = AnalysisResults()
        self.analyzers = [
            AlienVaultAnalyzer(),
            VirusTotalAnalyzer(),
            ThreatFoxAnalyzer(),
            GoogleSBAnalyzer(),
        ]

    async def analyze(self, ioc_value):
        ioc_type = determine_ioc_type(ioc_value)

        for analyzer in self.analyzers:
            result = await analyzer.analyze(ioc_value, ioc_type)

            if hasattr(result, 'whois'):
                self.results.whois[analyzer.name] = result.whois

            if hasattr(result, 'geo_location'):
                self.results.geo_location[analyzer.name] = result.geo_location

            if hasattr(result, 'malicious'):
                self.results.malicious[analyzer.name] = result.malicious

            if hasattr(result, 'blacklist'):
                self.results.blacklist[analyzer.name] = result.blacklist

        return self.results




