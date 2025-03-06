# threatquery/modules/googlesb.py

import logging
import httpx
import json
from urllib.parse import urlparse
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
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    async def analyze(self, ioc_value, ioc_type):
        try:
            # Google Safe Browsing mostly deals with URLs, so some data is limited
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
            logger.error(f"Error analyzing {ioc_value} with Google Safe Browsing: {str(e)}")
            return AnalysisResult(
                whois="Error retrieving data",
                geo_location="Unknown",
                malicious="Unknown",
                blacklist="Unknown"
            )

    def _normalize_url(self, url):
        """Normalize URL for Google Safe Browsing API"""
        # Make sure the URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url

    def _extract_domain_from_url(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(self._normalize_url(url))
            return parsed.netloc
        except Exception as e:
            logger.error(f"Error extracting domain from URL {url}: {str(e)}")
            return None

    async def get_whois_info(self, ioc_value, ioc_type):
        """
        Google Safe Browsing doesn't provide WHOIS information
        We'll include domain info extracted from URLs as a fallback
        """
        try:
            if ioc_type == "url":
                domain = self._extract_domain_from_url(ioc_value)
                if domain:
                    return f"Domain: {domain}"
            
            # For other IOC types or if domain extraction fails
            return "Not available from Google Safe Browsing"
        except Exception as e:
            logger.error(f"Error in get_whois_info for {ioc_value}: {str(e)}")
            return "Not available"

    async def get_geo_location(self, ioc_value, ioc_type):
        """
        Google Safe Browsing doesn't provide geolocation information
        We'll use a generic response for consistency
        """
        try:
            if ioc_type in ["url", "domain", "ip"]:
                # Note: In a real implementation, you might integrate with
                # a secondary geolocation service here
                return "Location data not provided by Google Safe Browsing"
            return "Not applicable for this IOC type"
        except Exception as e:
            logger.error(f"Error in get_geo_location for {ioc_value}: {str(e)}")
            return "Unknown"

    async def check_malicious(self, ioc_value, ioc_type):
        """
        Check if the URL or domain is flagged as malicious by Google Safe Browsing
        """
        try:
            # Google Safe Browsing primarily works with URLs
            if ioc_type not in ["url", "domain"]:
                return "Not applicable for this IOC type"
            
            # For domains, create a URL
            if ioc_type == "domain":
                url = f"http://{ioc_value}"
            else:
                url = self._normalize_url(ioc_value)
            
            # Prepare the request payload
            data = {
                "client": {
                    "clientId": "threatquery",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", 
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE", 
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            # Make the API request
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}?key={self.api_key}",
                    json=data,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # If there are matches, the URL is malicious
                    if "matches" in result and len(result["matches"]) > 0:
                        return "True"
                    return "False"
                elif response.status_code == 400:
                    error_msg = response.json().get("error", {}).get("message", "Unknown error")
                    logger.error(f"Google Safe Browsing API error: {error_msg}")
                    return "Error"
                else:
                    logger.error(f"Google Safe Browsing API error: {response.status_code}")
                    return "Error"
        except Exception as e:
            logger.error(f"Error checking malicious status for {ioc_value}: {str(e)}")
            return "Error"

    async def check_blacklist(self, ioc_value, ioc_type):
        """
        For Google Safe Browsing, blacklist check is equivalent to malicious check
        """
        try:
            # Use the same logic as check_malicious
            malicious = await self.check_malicious(ioc_value, ioc_type)
            return malicious
        except Exception as e:
            logger.error(f"Error checking blacklist status for {ioc_value}: {str(e)}")
            return "Error"

