# threatquery/modules/virustotal.py

import logging
import httpx
import hashlib
import json
from urllib.parse import urlparse
from config.env_config import VIRUSTOTAL_API_KEY

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
        self.tags = tags or "Unknown"


class VirusTotalAnalyzer:
    def __init__(self):
        self.name = "VirusTotal"
        self.api_key = VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "x-apikey": self.api_key,
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
            logger.error(f"Error analyzing {ioc_value} with VirusTotal: {str(e)}")
            return AnalysisResult(
                whois="Error retrieving data",
                geo_location="Unknown",
                malicious="Unknown",
                blacklist="Unknown"
            )

    def _get_resource_path(self, ioc_value, ioc_type):
        """Determine the appropriate API resource path based on IOC type"""
        if ioc_type == "url":
            # URL needs to be properly identified
            return f"urls/{self._hash_url(ioc_value)}"
        elif ioc_type == "domain":
            return f"domains/{ioc_value}"
        elif ioc_type == "ip":
            return f"ip_addresses/{ioc_value}"
        elif ioc_type == "file_hash":
            return f"files/{ioc_value}"
        else:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")

    def _hash_url(self, url):
        """Hash a URL for VirusTotal API use"""
        return hashlib.sha256(url.encode()).hexdigest()

    async def get_whois_info(self, ioc_value, ioc_type):
        try:
            if ioc_type not in ["domain", "ip"]:
                return "Not available for this IOC type"
                
            async with httpx.AsyncClient() as client:
                resource_path = self._get_resource_path(ioc_value, ioc_type)
                response = await client.get(
                    f"{self.base_url}{resource_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "attributes" in data["data"]:
                        if "whois" in data["data"]["attributes"]:
                            # Return a summary of WHOIS data
                            whois_data = data["data"]["attributes"]["whois"]
                            # Parse the WHOIS text to extract key information
                            if isinstance(whois_data, str):
                                # Extract just the registrar and creation date if possible
                                registrar = None
                                creation_date = None
                                
                                for line in whois_data.split('\n'):
                                    if "Registrar:" in line:
                                        registrar = line.split("Registrar:")[1].strip()
                                    if "Creation Date:" in line:
                                        creation_date = line.split("Creation Date:")[1].strip()
                                
                                summary = {}
                                if registrar:
                                    summary["registrar"] = registrar
                                if creation_date:
                                    summary["creation_date"] = creation_date
                                
                                return json.dumps(summary) if summary else "WHOIS information available but not parsed"
                            return str(whois_data)
                    return "No WHOIS information available"
                else:
                    return f"Error: {response.status_code} - {response.text}"
        except Exception as e:
            logger.error(f"Error retrieving WHOIS info for {ioc_value}: {str(e)}")
            return "Error retrieving WHOIS information"

    async def get_geo_location(self, ioc_value, ioc_type):
        try:
            if ioc_type not in ["ip", "domain", "url"]:
                return "Not available for this IOC type"
                
            resource_path = self._get_resource_path(ioc_value, ioc_type)
            
            # For URLs, extract the domain
            if ioc_type == "url":
                parsed_url = urlparse(ioc_value)
                domain = parsed_url.netloc
                resource_path = f"domains/{domain}"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{resource_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "attributes" in data["data"]:
                        attrs = data["data"]["attributes"]
                        
                        # For IPs
                        if "country" in attrs:
                            return attrs["country"]
                        
                        # For domains with resolution
                        if "last_dns_records" in attrs:
                            for record in attrs["last_dns_records"]:
                                if record.get("type") == "A":
                                    ip = record.get("value")
                                    if ip:
                                        # Get location from the IP
                                        ip_response = await client.get(
                                            f"{self.base_url}ip_addresses/{ip}",
                                            headers=self.headers
                                        )
                                        if ip_response.status_code == 200:
                                            ip_data = ip_response.json()
                                            if "data" in ip_data and "attributes" in ip_data["data"]:
                                                country = ip_data["data"]["attributes"].get("country")
                                                if country:
                                                    return country
                            
                    return "Location information not found"
                else:
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error retrieving geo location for {ioc_value}: {str(e)}")
            return "Unknown"

    async def check_malicious(self, ioc_value, ioc_type):
        try:
            resource_path = self._get_resource_path(ioc_value, ioc_type)
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{resource_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "attributes" in data["data"]:
                        attrs = data["data"]["attributes"]
                        
                        # Check last_analysis_stats
                        if "last_analysis_stats" in attrs:
                            stats = attrs["last_analysis_stats"]
                            malicious_count = stats.get("malicious", 0)
                            suspicious_count = stats.get("suspicious", 0)
                            
                            # Consider it malicious if any engine reports it as malicious or suspicious
                            if malicious_count > 0 or suspicious_count > 0:
                                return "True"
                    
                    return "False"
                else:
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error checking malicious status for {ioc_value}: {str(e)}")
            return "Unknown"

    async def check_blacklist(self, ioc_value, ioc_type):
        try:
            # For VirusTotal, blacklist check is very similar to malicious check
            # but might look at different attributes
            resource_path = self._get_resource_path(ioc_value, ioc_type)
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{resource_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "attributes" in data["data"]:
                        attrs = data["data"]["attributes"]
                        
                        # Check for any category that indicates this is blacklisted
                        if "categories" in attrs:
                            categories = attrs["categories"]
                            blacklist_categories = ["malicious", "phishing", "malware", "spam"]
                            
                            for category in categories.values():
                                if any(bc in category.lower() for bc in blacklist_categories):
                                    return "True"
                        
                        # Also check reputation
                        if "reputation" in attrs:
                            if attrs["reputation"] < 0:  # Negative reputation in VT indicates bad
                                return "True"
                    
                    return "False"
                else:
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error checking blacklist status for {ioc_value}: {str(e)}")
            return "Unknown"
            
    async def check_suspicious(self, ioc_value, ioc_type):
        try:
            resource_path = self._get_resource_path(ioc_value, ioc_type)
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{resource_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "attributes" in data["data"]:
                        attrs = data["data"]["attributes"]
                        
                        # Check last_analysis_stats for suspicious counts
                        if "last_analysis_stats" in attrs:
                            stats = attrs["last_analysis_stats"]
                            suspicious_count = stats.get("suspicious", 0)
                            
                            # Consider it suspicious if any engine reports it as suspicious
                            if suspicious_count > 0:
                                return "True"
                            
                            # Or if it has a borderline reputation score
                            if "reputation" in attrs:
                                rep = attrs["reputation"]
                                if rep < 0 and rep > -20:  # Slightly negative but not strongly negative
                                    return "True"
                    
                    return "False"
                else:
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error checking suspicious status for {ioc_value}: {str(e)}")
            return "Unknown"
            
    async def get_threat_type(self, ioc_value, ioc_type):
        try:
            resource_path = self._get_resource_path(ioc_value, ioc_type)
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{resource_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "attributes" in data["data"]:
                        attrs = data["data"]["attributes"]
                        
                        # Check for any threat categories
                        if "categories" in attrs and attrs["categories"]:
                            # Get the most common category
                            categories = attrs["categories"].values()
                            if categories:
                                return next(iter(categories))  # Return the first category
                                
                        # Check for any popular threat labels
                        if "popular_threat_classification" in attrs:
                            pop_threat = attrs["popular_threat_classification"]
                            if "suggested_threat_label" in pop_threat:
                                return pop_threat["suggested_threat_label"]
                                
                        # Check crowdsourced context
                        if "crowdsourced_context" in attrs and attrs["crowdsourced_context"]:
                            for context in attrs["crowdsourced_context"]:
                                if "details" in context:
                                    return context["details"]
                    
                    return "Unknown"
                else:
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error retrieving threat type for {ioc_value}: {str(e)}")
            return "Unknown"
            
    async def get_malware_family(self, ioc_value, ioc_type):
        try:
            resource_path = self._get_resource_path(ioc_value, ioc_type)
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{resource_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "attributes" in data["data"]:
                        attrs = data["data"]["attributes"]
                        
                        # Check popular threat classification
                        if "popular_threat_classification" in attrs:
                            pop_threat = attrs["popular_threat_classification"]
                            if "popular_threat_category" in pop_threat and pop_threat["popular_threat_category"]:
                                for category in pop_threat["popular_threat_category"]:
                                    if "value" in category:
                                        return category["value"]
                                        
                            # Or check popular threat name
                            if "popular_threat_name" in pop_threat and pop_threat["popular_threat_name"]:
                                for name in pop_threat["popular_threat_name"]:
                                    if "value" in name:
                                        return name["value"]
                    
                    return "Unknown"
                else:
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error retrieving malware family for {ioc_value}: {str(e)}")
            return "Unknown"
            
    async def get_first_seen(self, ioc_value, ioc_type):
        try:
            resource_path = self._get_resource_path(ioc_value, ioc_type)
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{resource_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "attributes" in data["data"]:
                        attrs = data["data"]["attributes"]
                        
                        # Check first submission date
                        if "first_submission_date" in attrs:
                            return str(attrs["first_submission_date"])
                            
                        # Check creation date (if available)
                        if "creation_date" in attrs:
                            return str(attrs["creation_date"])
                            
                        # Check first seen date (if available)
                        if "first_seen_in_the_wild" in attrs:
                            return str(attrs["first_seen_in_the_wild"])
                    
                    return "Unknown"
                else:
                    return "Unknown"
        except Exception as e:
            logger.error(f"Error retrieving first seen date for {ioc_value}: {str(e)}")
            return "Unknown"
            
    async def get_tags(self, ioc_value, ioc_type):
        try:
            resource_path = self._get_resource_path(ioc_value, ioc_type)
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}{resource_path}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "attributes" in data["data"]:
                        attrs = data["data"]["attributes"]
                        tags = []
                        
                        # Check for categories (often used as tags)
                        if "categories" in attrs:
                            tags.extend(attrs["categories"].values())
                            
                        # Check for tags field
                        if "tags" in attrs:
                            tags.extend(attrs["tags"])
                            
                        # Check for type tags
                        if "type_tags" in attrs:
                            tags.extend(attrs["type_tags"])
                            
                        # Return unique tags as JSON string
                        if tags:
                            return json.dumps(list(set(tags)))
                    
                    return "[]"
                else:
                    return "[]"
        except Exception as e:
            logger.error(f"Error retrieving tags for {ioc_value}: {str(e)}")
            return "[]"

