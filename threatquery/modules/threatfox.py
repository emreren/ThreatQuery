# threatquery/modules/threatfox.py

import logging
import httpx
import json
from urllib.parse import urlparse
from config.env_config import THREATFOX_API_KEY

logger = logging.getLogger(__name__)


class AnalysisResult:
    def __init__(self, whois, geo_location, malicious, blacklist, suspicious=None, threat_type=None, malware_family=None, first_seen=None, tags=None):
        self.whois = whois
        self.geo_location = geo_location
        self.malicious = malicious
        self.blacklist = blacklist
        self.suspicious = suspicious or "Unknown"
        self.threat_type = threat_type or "Unknown"  
        self.malware_family = malware_family or "Unknown"
        self.first_seen = first_seen or "Unknown"
        self.tags = tags or "[]"


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
            suspicious = await self.check_suspicious(ioc_value, ioc_type)
            threat_type = await self.get_threat_type(ioc_value, ioc_type)
            malware_family = await self.get_malware_family(ioc_value, ioc_type)
            first_seen = await self.get_first_seen(ioc_value, ioc_type)
            tags = await self.get_tags(ioc_value, ioc_type)

            return AnalysisResult(
                whois=whois,
                geo_location=geo_location,
                malicious=malicious,
                blacklist=blacklist,
                suspicious=suspicious,
                threat_type=threat_type,
                malware_family=malware_family,
                first_seen=first_seen,
                tags=tags
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
    
    async def check_suspicious(self, ioc_value, ioc_type):
        """
        ThreatFox doesn't directly distinguish between malicious and suspicious,
        but we can implement a confidence-based approach
        """
        try:
            threatfox_type = self._map_ioc_type(ioc_type)
            if not threatfox_type:
                return "Not applicable for this IOC type"
            
            # For URLs, use the domain
            search_value = ioc_value
            if ioc_type == "url":
                domain = self._extract_domain_from_url(ioc_value)
                if not domain:
                    return "Could not extract domain from URL"
                search_value = domain
                threatfox_type = "domain"
            
            # Adjust hash type for file hashes
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
                "days": 90
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
                            # Check confidence level - if medium or low, consider it suspicious rather than confirmed
                            confidence = ioc_data[0].get("confidence_level")
                            if confidence and confidence in ["medium", "low"]:
                                return "True"
                            
                    return "False"
                else:
                    logger.error(f"ThreatFox API error: {response.status_code}")
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error checking suspicious status for {ioc_value}: {str(e)}")
            return "Unknown"
            
    async def get_threat_type(self, ioc_value, ioc_type):
        """
        Get threat type information from ThreatFox
        """
        try:
            threatfox_type = self._map_ioc_type(ioc_type)
            if not threatfox_type:
                return "Not applicable for this IOC type"
            
            # For URLs, use the domain
            search_value = ioc_value
            if ioc_type == "url":
                domain = self._extract_domain_from_url(ioc_value)
                if not domain:
                    return "Could not extract domain from URL"
                search_value = domain
                threatfox_type = "domain"
            
            # Query ThreatFox API
            data = {
                "query": "search_ioc",
                "search_term": search_value,
                "days": 90
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
                            # ThreatFox provides a threat_type field
                            return ioc_data[0].get("threat_type", "Unknown")
                    
                    return "Unknown"
                else:
                    logger.error(f"ThreatFox API error: {response.status_code}")
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error retrieving threat type for {ioc_value}: {str(e)}")
            return "Unknown"
            
    async def get_malware_family(self, ioc_value, ioc_type):
        """
        Get malware family information from ThreatFox
        """
        try:
            threatfox_type = self._map_ioc_type(ioc_type)
            if not threatfox_type:
                return "Not applicable for this IOC type"
            
            # For URLs, use the domain
            search_value = ioc_value
            if ioc_type == "url":
                domain = self._extract_domain_from_url(ioc_value)
                if not domain:
                    return "Could not extract domain from URL"
                search_value = domain
                threatfox_type = "domain"
            
            # Query ThreatFox API
            data = {
                "query": "search_ioc",
                "search_term": search_value,
                "days": 90
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
                            # ThreatFox provides a malware field
                            return ioc_data[0].get("malware", "Unknown")
                    
                    return "Unknown"
                else:
                    logger.error(f"ThreatFox API error: {response.status_code}")
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error retrieving malware family for {ioc_value}: {str(e)}")
            return "Unknown"
            
    async def get_first_seen(self, ioc_value, ioc_type):
        """
        Get first seen date information from ThreatFox
        """
        try:
            threatfox_type = self._map_ioc_type(ioc_type)
            if not threatfox_type:
                return "Not applicable for this IOC type"
            
            # For URLs, use the domain
            search_value = ioc_value
            if ioc_type == "url":
                domain = self._extract_domain_from_url(ioc_value)
                if not domain:
                    return "Could not extract domain from URL"
                search_value = domain
                threatfox_type = "domain"
            
            # Query ThreatFox API
            data = {
                "query": "search_ioc",
                "search_term": search_value,
                "days": 90
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
                            # ThreatFox provides a first_seen field
                            return ioc_data[0].get("first_seen", "Unknown")
                    
                    return "Unknown"
                else:
                    logger.error(f"ThreatFox API error: {response.status_code}")
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error retrieving first seen date for {ioc_value}: {str(e)}")
            return "Unknown"
            
    async def get_tags(self, ioc_value, ioc_type):
        """
        Get tags information from ThreatFox
        """
        try:
            threatfox_type = self._map_ioc_type(ioc_type)
            if not threatfox_type:
                return "[]"
            
            # For URLs, use the domain
            search_value = ioc_value
            if ioc_type == "url":
                domain = self._extract_domain_from_url(ioc_value)
                if not domain:
                    return "[]"
                search_value = domain
                threatfox_type = "domain"
            
            # Query ThreatFox API
            data = {
                "query": "search_ioc",
                "search_term": search_value,
                "days": 90
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
                            # ThreatFox provides a tags field
                            tags = ioc_data[0].get("tags", [])
                            return json.dumps(tags)
                    
                    return "[]"
                else:
                    logger.error(f"ThreatFox API error: {response.status_code}")
                    return "[]"
        except Exception as e:
            logger.error(f"Error retrieving tags for {ioc_value}: {str(e)}")
            return "[]"

