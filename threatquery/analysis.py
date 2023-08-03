# threatquery/analysis.py file

import os
import httpx
import re
import asyncio

from dotenv import load_dotenv
from .logging_utils import log_info, log_error

load_dotenv()


async def analyze_ioc(ioc_value: str):
    ioc_type = determine_ioc_type(ioc_value)
    tasks = [
        alienvault_analysis(ioc_value, ioc_type),
        virustotal_analysis(ioc_value, ioc_type),
    ]

    results = await asyncio.gather(*tasks)
    merged_results = {}
    for result in results:
        merged_results.update(result)
    return merged_results


def determine_ioc_type(ioc_value: str) -> str:
    patterns = {
        "domain": r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$",
        "url": r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$",
        "hash": r"^([A-Fa-f\d]{32}|[A-Fa-f\d]{40}|[A-Fa-f\d]{64})$",
        "ip": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    }

    for ioc_type, pattern in patterns.items():
        if re.match(pattern, ioc_value):
            return ioc_type

    return "unknown"


ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")


async def alienvault_analysis(ioc_value: str, ioc_type: str):
    analysis_result = {}

    # geometric_location
    try:
        api_endpoint = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc_value}/geo"
        log_info(f"Sending API request to: {api_endpoint}")
        headers = {
            "X-OTX-API-KEY": ALIENVAULT_API_KEY
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(api_endpoint, headers=headers)
            response.raise_for_status()
            threat_info = response.json()
            analysis_result["geometric_location"] = threat_info.get("geo", {}).get("country_name", None)
    except httpx.RequestError as e:
        log_error(f"{api_endpoint} isteği başarısız: {e}")
    except Exception as e:
        log_error(f"{api_endpoint} isteği başarısız: {e}")

    # whois, malicious_control, blacklist
    try:
        api_endpoint = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc_value}/general"
        log_info(f"Sending API request to: {api_endpoint}")
        async with httpx.AsyncClient() as client:
            response = await client.get(api_endpoint, headers=headers)
            response.raise_for_status()
            threat_info = response.json()
            analysis_result["malicious_control"] = threat_info.get("malicious_control", None)
            analysis_result["blacklist"] = threat_info.get("blacklist", None)
            analysis_result["whois"] = threat_info.get("whois", None)
            analysis_result["type"] = ioc_type
    except httpx.RequestError as e:
        log_error(f"{api_endpoint} isteği başarısız: {e}")
    except Exception as e:
        log_error(f"{api_endpoint} isteği başarısız: {e}")

    return analysis_result


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


async def virustotal_analysis(ioc_value: str, ioc_type: str):
    url = f"https://www.virustotal.com/api/v3/{ioc_type}s/{ioc_value}"
    log_info(f"Sending API request to: {url}")
    analysis_result = {}
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json"
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()

        data_attributes = result.get("data", {}).get("attributes", {})

        # Type
        analysis_result["type"] = ioc_type

        # Geometric Location
        analysis_result["geometric_location"] = data_attributes.get("geometric_location", None)

        # Malicious Analysis Stats
        malicious_stats = data_attributes.get("last_analysis_stats", {})
        if malicious_stats.get("malicious") > 0:
            analysis_result["malicious_control"] = "positive"
        else:
            analysis_result["malicious_control"] = "negative"

        # Blacklist
        analysis_result["blacklist"] = data_attributes.get("blacklist", None)

        # Whois
        analysis_result["whois"] = data_attributes.get("whois", None)

    return analysis_result
