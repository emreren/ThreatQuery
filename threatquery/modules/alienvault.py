# threatquery/modules/alienvault.py

import logging
import httpx
import json
from urllib.parse import urlparse
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
        self.base_url = "https://otx.alienvault.com/api/v1/"
        self.headers = {
            "X-OTX-API-KEY": self.api_key,
            "Content-Type": "application/json"
        }

    async def analyze(self, ioc_value, ioc_type):
        try:
            geo_location = await self.get_geo_location(ioc_value, ioc_type)
            malicious = await self.check_malicious(ioc_value, ioc_type)
            blacklist = await self.check_blacklist(ioc_value, ioc_type)

            return AnalysisResult(
                geo_location=geo_location,
                malicious=malicious,
                blacklist=blacklist,
            )
        except Exception as e:
            logger.error(f"Error analyzing {ioc_value} with AlienVault: {str(e)}")
            return AnalysisResult(
                geo_location="Unknown",
                malicious="Unknown",
                blacklist="Unknown"
            )

    def _get_indicator_path(self, ioc_value, ioc_type):
        """Determine the appropriate AlienVault OTX indicator path"""
        if ioc_type == "url":
            return f"indicators/url/{ioc_value}"
        elif ioc_type == "domain":
            return f"indicators/domain/{ioc_value}"
        elif ioc_type == "ip":
            return f"indicators/IPv4/{ioc_value}"
        elif ioc_type == "file_hash":
            # Detect hash type based on length
            if len(ioc_value) == 32:  # MD5
                return f"indicators/file/{ioc_value}"
            elif len(ioc_value) == 40:  # SHA-1
                return f"indicators/file/{ioc_value}"
            elif len(ioc_value) == 64:  # SHA-256
                return f"indicators/file/{ioc_value}"
            else:
                raise ValueError(f"Unsupported hash length: {len(ioc_value)}")
        else:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")

    def _extract_domain_from_url(self, url):
        """Extract domain from URL for certain queries"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception as e:
            logger.error(f"Error extracting domain from URL {url}: {str(e)}")
            return None

    async def get_geo_location(self, ioc_value, ioc_type):
        try:
            # For URLs, we might need to extract the domain or IP
            if ioc_type == "url":
                # Extract domain from URL
                domain = self._extract_domain_from_url(ioc_value)
                if not domain:
                    return "Unknown"
                
                # First try as domain
                indicator_path = f"indicators/domain/{domain}/geo"
            elif ioc_type == "domain":
                indicator_path = f"indicators/domain/{ioc_value}/geo"
            elif ioc_type == "ip":
                indicator_path = f"indicators/IPv4/{ioc_value}/geo"
            else:
                return "Not available for this IOC type"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{indicator_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract country information
                    if "country_name" in data:
                        return data["country_name"]
                    
                    # If we tried domain and got nothing useful, try IP resolution
                    if ioc_type in ["url", "domain"] and ("error" in data or not data):
                        # For domains, try to get IP and then geo for that IP
                        ip_path = f"indicators/domain/{domain if ioc_type == 'url' else ioc_value}/general"
                        ip_response = await client.get(
                            f"{self.base_url}{ip_path}",
                            headers=self.headers
                        )
                        
                        if ip_response.status_code == 200:
                            ip_data = ip_response.json()
                            if "geo" in ip_data and "country_name" in ip_data["geo"]:
                                return ip_data["geo"]["country_name"]
                
                return "Unknown"
        except Exception as e:
            logger.error(f"Error retrieving geo location for {ioc_value}: {str(e)}")
            return "Unknown"

    async def check_malicious(self, ioc_value, ioc_type):
        try:
            indicator_path = self._get_indicator_path(ioc_value, ioc_type)
            
            # Add /general to get overall analysis
            general_path = f"{indicator_path}/general"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{general_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Check for malicious indicators
                    if "pulse_info" in data:
                        pulse_count = data["pulse_info"].get("count", 0)
                        if pulse_count > 0:
                            # If any security pulse references this indicator, consider it malicious
                            return "True"
                    
                    return "False"
                else:
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error checking malicious status for {ioc_value}: {str(e)}")
            return "Unknown"

    async def check_blacklist(self, ioc_value, ioc_type):
        try:
            # For AlienVault, we'll check reputation in addition to malicious status
            # Reputation might come from different sources
            
            indicator_path = self._get_indicator_path(ioc_value, ioc_type)
            reputation_path = f"{indicator_path}/reputation"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{reputation_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Check reputation values
                    if isinstance(data, dict) and "reputation" in data:
                        if data["reputation"] < 0:  # Negative value indicates bad reputation
                            return "True"
                    
                    # Also check if it appears in AlienVault blacklists
                    malicious = await self.check_malicious(ioc_value, ioc_type)
                    if malicious == "True":
                        return "True"
                    
                    return "False"
                else:
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error checking blacklist status for {ioc_value}: {str(e)}")
            return "Unknown"


