import os
import httpx
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

ALIENVAULT_API_URL = os.getenv("ALIENVAULT_API_URL")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")

async def analyze_ioc_and_save(ioc_value: str):
    try:
        api_endpoint = f"{ALIENVAULT_API_URL}/indicator/domain/{ioc_value}/general"
        logger.info(f"Sending API request to: {api_endpoint}")

        headers = {
            "X-OTX-API-KEY": ALIENVAULT_API_KEY
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(api_endpoint, headers=headers)
            response.raise_for_status()

            # API yanıtını analiz ederek gerekli bilgileri alın
            threat_info = response.json()

            return {
                "geometric_location": threat_info.get("geometric_location"),
                "malicious_control": threat_info.get("malicious_control"),
                "blacklist": threat_info.get("blacklist"),
                "whois": threat_info.get("whois")
            }

    except httpx.RequestError as e:
        logger.error(f"AlienVault API isteği başarısız: {e}")
        return None
    except Exception as e:
        logger.error(f"Beklenmeyen bir hata oluştu: {e}")
        return None
