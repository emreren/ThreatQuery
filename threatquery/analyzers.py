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
                
            if hasattr(result, 'suspicious'):
                self.results.suspicious[analyzer.name] = result.suspicious
                
            if hasattr(result, 'threat_type'):
                self.results.threat_type[analyzer.name] = result.threat_type
                
            if hasattr(result, 'malware_family'):
                self.results.malware_family[analyzer.name] = result.malware_family
                
            if hasattr(result, 'first_seen'):
                self.results.first_seen[analyzer.name] = result.first_seen
                
            if hasattr(result, 'tags'):
                self.results.tags[analyzer.name] = result.tags

        return self.results




