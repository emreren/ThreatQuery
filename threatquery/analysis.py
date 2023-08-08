# threatquery/analysis.py file

import os
import httpx
import re
import asyncio
import xml.etree.ElementTree as ET

from dotenv import load_dotenv
from threatquery.logging_utils import log_info, log_error

load_dotenv()
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLESAFEBROWSING_API_KEY = os.getenv("GOOGLESAFEBROWSING_API_KEY")
WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY", "")

async def ioc_analyzes(ioc_value: str):
    ioc_type = determine_ioc_type(ioc_value)
    tasks = [
        alienvault_analysis(ioc_value, ioc_type),
        virustotal_analysis(ioc_value, ioc_type),
        googlesafebrowsing_analysis(ioc_value, ioc_type),
        whoisxmlapi_analysis(ioc_value, ioc_type),
    ]

    analysis_results = await asyncio.gather(*tasks)
    merged_results = {}

    for result in analysis_results:
        for key, value in result.items():
            if key in merged_results:
                if value is not None:
                    merged_results[key] = value
            else:
                merged_results[key] = value

    merged_results["type"] = ioc_type

    return merged_results


def determine_ioc_type(ioc_value: str) -> str:
    patterns = {
        "ipv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
        "ipv6": r"^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$",
        "domain": r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$",
        "url": r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$",
        "hash": r"^([A-Fa-f\d]{32}|[A-Fa-f\d]{40}|[A-Fa-f\d]{64})$"
    }

    for ioc_type, pattern in patterns.items():
        if re.match(pattern, ioc_value):
            return ioc_type

    return "unknown"


async def alienvault_analysis(ioc_value: str, ioc_type: str):
    analysis_result = {}
    type_mapping = {
        "url": {
            "section": "url_list",
            "alienvault_type": "url"
        },
        "ipv4": {
            "section": "general",
            "alienvault_type": "IPv4"
        },
        "ipv6": {
            "section": "general",
            "alienvault_type": "IPv6"
        }
    }
    dict_mapping = type_mapping.get(ioc_type, {"section": "geo", "alienvault_type": ioc_type})
    section = dict_mapping.get("section")
    alienvault_type = dict_mapping.get("section")

    try:
        base_url = "https://otx.alienvault.com/api/v1/indicators"
        url = f"{base_url}/{alienvault_type}/{ioc_value}/{section}"

        log_info(f"Sending API request to AlienVault: {url}")

        headers = {
            "X-OTX-API-KEY": ALIENVAULT_API_KEY
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            threat_info = response.json()

            location_info = threat_info.get("country_name", None)
            city_info = threat_info.get("city", None)
            if city_info:
                location_info = f"{location_info}, {city_info}"
            analysis_result["geometric_location"] = location_info


    except httpx.RequestError as e:
        log_error(f"AlienVault API request failed: {e}")
    except Exception as e:
        log_error(f"An unexpected error occurred: {e}")

    return analysis_result


async def virustotal_analysis(ioc_value: str, ioc_type: str):
    url = f"https://www.virustotal.com/api/v3/{ioc_type}s/{ioc_value}"
    log_info(f"Sending API request to VirusTotal: {url}")
    analysis_result = {}
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            result = response.json()

            data_attributes = result.get("data", {}).get("attributes", {})
            analysis_result["last_analysis_stats"] = data_attributes.get("last_analysis_stats", {})

    except httpx.RequestError as e:
        log_error(f"VirusTotal API request failed: {e}")
    except Exception as e:
        log_error(f"An unexpected error occurred: {e}")

    return analysis_result


async def googlesafebrowsing_analysis(ioc_value: str, ioc_type: str):
    analysis_result = {}

    # Convert domain or IP to URL format if needed
    if ioc_type == "domain":
        ioc_value = f"http://{ioc_value}"
    elif ioc_type == "ipv4" or ioc_type == "ipv6":
        ioc_value = f"http://{ioc_value}"

    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLESAFEBROWSING_API_KEY}"
    headers = {
        "Content-Type": "application/json"
    }

    threat_info = {
        "client": {
            "clientId": "YourClientId",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["WINDOWS"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": ioc_value}]
        }
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=threat_info)
            response.raise_for_status()
            result = response.json()

            if "matches" in result:
                matches = result["matches"]
                analysis_result["safebrowsing"] = {
                    "matches": matches
                }
            else:
                analysis_result["safebrowsing"] = {
                    "matches": []
                }

            log_info(f"Google Safe Browsing analysis completed for {ioc_value}")
    except httpx.RequestError as e:
        log_error(f"Failed to perform Google Safe Browsing analysis: {e}")
    except Exception as e:
        log_error(f"An unexpected error occurred: {e}")

    return analysis_result


async def whoisxmlapi_analysis(ioc_value: str, ioc_type: str):
    analysis_result = {}

    if ioc_type == "domain":
        domain_name = ioc_value
    else:
        log_error("Only domain type is supported for WHOIS analysis.")
        return analysis_result

    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOISXML_API_KEY}&domainName={domain_name}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            xml_data = response.text

            root = ET.fromstring(xml_data)
            whois_element = root.find(".//whoisServerData/registryData/rawText")
            if whois_element is not None:
                whois_info = whois_element.text
                analysis_result["whois"] = whois_info
                log_info(f"WHOIS information fetched for domain: {domain_name}")
            else:
                log_info(f"WHOIS information not found for domain: {domain_name}")
                analysis_result["whois"] = ""

    except httpx.RequestError as e:
        log_error(f"Failed to fetch WHOIS information for domain {domain_name}: {e}")
    except Exception as e:
        log_error(f"An unexpected error occurred: {e}")

    return analysis_result




