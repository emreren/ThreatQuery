# threatquery/modules/threatfox.py

import logging
import httpx
import json
from urllib.parse import urlparse
from config.env_config import THREATFOX_API_KEY

logger = logging.getLogger(__name__)


class AnalysisResult:
    def __init__(self, whois, geo_location, malicious, blacklist):
        self.whois = whois
        self.geo_location = geo_location
        self.malicious = malicious
        self.blacklist = blacklist


class ThreatFoxAnalyzer:
    def __init__(self):
        self.name = "ThreatFox"
        self.api_key = THREATFOX_API_KEY
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.headers = {
            "API-KEY": self.api_key,
            "Content-Type": "application/json"
        }

    async def analyze(self, ioc_value, ioc_type):
        try:
            whois = await self.get_whois_info(ioc_value, ioc_type)
            geo_location = await self.get_geo_location(ioc_value, ioc_type)
            malicious = await self.check_malicious(ioc_value, ioc_type)
            blacklist = await self.check_blacklist(ioc_value, ioc_type)

            return AnalysisResult(
                whois=whois,
                geo_location=geo_location,
                malicious=malicious,
                blacklist=blacklist,
            )
        except Exception as e:
            logger.error(f"Error analyzing {ioc_value} with ThreatFox: {str(e)}")
            return AnalysisResult(
                whois="Error retrieving data",
                geo_location="Unknown",
                malicious="Unknown",
                blacklist="Unknown"
            )

    def _map_ioc_type(self, ioc_type):
        """Map our IOC types to ThreatFox IOC types"""
        mapping = {
            "url": "url",
            "domain": "domain",
            "ip": "ip:port",  # ThreatFox uses ip:port, but can handle just IP
            "file_hash": "md5"  # Default to md5, will refine based on hash length
        }
        
        return mapping.get(ioc_type, "")

    def _extract_domain_from_url(self, url):
        """Extract domain from URL for certain queries"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            return parsed.netloc
        except Exception as e:
            logger.error(f"Error extracting domain from URL {url}: {str(e)}")
            return None

    async def get_whois_info(self, ioc_value, ioc_type):
        """
        ThreatFox doesn't provide direct WHOIS information
        We'll enhance this with metadata from ThreatFox IOC records
        """
        try:
            # ThreatFox doesn't have explicit WHOIS data
            # We'll gather metadata about the IOC from ThreatFox
            threatfox_type = self._map_ioc_type(ioc_type)
            if not threatfox_type:
                return "Not available for this IOC type"
            
            # For URLs, we need to use the domain
            if ioc_type == "url":
                ioc_value = self._extract_domain_from_url(ioc_value)
                if not ioc_value:
                    return "Could not extract domain from URL"
                threatfox_type = "domain"
            
            # Adjust hash type based on length for file hashes
            if ioc_type == "file_hash":
                if len(ioc_value) == 32:
                    threatfox_type = "md5"
                elif len(ioc_value) == 40:
                    threatfox_type = "sha1"
                elif len(ioc_value) == 64:
                    threatfox_type = "sha256"
            
            # Query ThreatFox API
            data = {
                "query": "search_ioc",
                "search_term": ioc_value,
                "days": 90  # Look back 90 days
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.base_url,
                    json=data,
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    if result.get("query_status") == "ok" and "data" in result:
                        ioc_data = result["data"]
                        
                        if ioc_data and len(ioc_data) > 0:
                            # Get the first entry with information about this IOC
                            metadata = {
                                "malware_family": ioc_data[0].get("malware", "Unknown"),
                                "first_seen": ioc_data[0].get("first_seen", "Unknown"),
                                "threat_type": ioc_data[0].get("threat_type", "Unknown"),
                                "tags": ioc_data[0].get("tags", [])
                            }
                            
                            return json.dumps(metadata)
                        
                    return "No ThreatFox data available"
                else:
                    return f"Error: {response.status_code}"
        except Exception as e:
            logger.error(f"Error retrieving metadata for {ioc_value}: {str(e)}")
            return "Error retrieving metadata"

    async def get_geo_location(self, ioc_value, ioc_type):
        """
        Get geolocation information for the IOC
        ThreatFox doesn't directly provide geo data, so we'll use a placeholder
        or integrate with another source in a real implementation
        """
        try:
            # For IP addresses, we could integrate with IP geolocation services
            if ioc_type == "ip":
                # In a real implementation, you'd call an IP geolocation service here
                return "Geolocation data not directly provided by ThreatFox"
            
            # For domains and URLs, we would resolve to IP and then geolocate
            elif ioc_type in ["domain", "url"]:
                if ioc_type == "url":
                    domain = self._extract_domain_from_url(ioc_value)
                    if not domain:
                        return "Could not extract domain from URL"
                else:
                    domain = ioc_value
                
                # In a real implementation, you'd resolve domain to IP and then geolocate
                return "Geolocation data not directly provided by ThreatFox"
            
            return "Not applicable for this IOC type"
        except Exception as e:
            logger.error(f"Error retrieving geo location for {ioc_value}: {str(e)}")
            return "Unknown"

    async def check_malicious(self, ioc_value, ioc_type):
        """
        Check if the IOC is known to be malicious in ThreatFox database
        """
        try:
            threatfox_type = self._map_ioc_type(ioc_type)
            if not threatfox_type:
                return "Not applicable for this IOC type"
            
            # For URLs, we need to use the domain
            search_value = ioc_value
            if ioc_type == "url":
                domain = self._extract_domain_from_url(ioc_value)
                if not domain:
                    return "Could not extract domain from URL"
                search_value = domain
                threatfox_type = "domain"
            
            # Adjust hash type based on length for file hashes
            if ioc_type == "file_hash":
                if len(ioc_value) == 32:
                    threatfox_type = "md5"
                elif len(ioc_value) == 40:
                    threatfox_type = "sha1"
                elif len(ioc_value) == 64:
                    threatfox_type = "sha256"
            
            # Query ThreatFox API
            data = {
                "query": "search_ioc",
                "search_term": search_value,
                "days": 90  # Look back 90 days
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.base_url,
                    json=data,
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    if result.get("query_status") == "ok" and "data" in result:
                        ioc_data = result["data"]
                        
                        # If any data is returned, the IOC is known to be malicious
                        if ioc_data and len(ioc_data) > 0:
                            return "True"
                        
                    return "False"
                else:
                    logger.error(f"ThreatFox API error: {response.status_code}")
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error checking malicious status for {ioc_value}: {str(e)}")
            return "Unknown"

    async def check_blacklist(self, ioc_value, ioc_type):
        """
        For ThreatFox, blacklist check is equivalent to malicious check
        since ThreatFox is a database of known malicious indicators
        """
        try:
            # Use the same logic as check_malicious
            malicious = await self.check_malicious(ioc_value, ioc_type)
            return malicious
        except Exception as e:
            logger.error(f"Error checking blacklist status for {ioc_value}: {str(e)}")
            return "Unknown"

