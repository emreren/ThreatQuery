# tests/conftest.py

import copy
import os
import tempfile

# Set before anything imports config.env_config: environment variables override .env and
# .env.secret, so tests run on a throwaway SQLite database with fake keys and never touch
# the real database, the real keys or app.log
_tmp = tempfile.mkdtemp(prefix="threatquery-tests-")
os.environ.update({
    "DATABASE_URL": f"sqlite:///{_tmp}/test.db",
    "LOG_FILE": f"{_tmp}/test.log",
    "ALIENVAULT_API_KEY": "test-otx-key",
    "VIRUSTOTAL_API_KEY": "test-vt-key",
    "THREATFOX_API_KEY": "test-threatfox-key",
    "GOOGLESAFEBROWSING_API_KEY": "test-gsb-key",
    "ELEVENLABS_API_KEY": "test-elevenlabs-key",
})

import pytest
import respx

OTX = "https://otx.alienvault.com/api/v1/indicators/"
VT = "https://www.virustotal.com/api/v3/"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
SAFE_BROWSING = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TTS = "https://api.elevenlabs.io/v1/text-to-speech/"

IP = "139.162.5.254"
MP3 = b"ID3 fake mp3"

# Shapes of real responses for 139.162.5.254 (a Mirai C2 on ThreatFox), trimmed
VT_ATTRIBUTES = {
    "country": "SG",
    "last_analysis_stats": {"malicious": 3, "suspicious": 0, "harmless": 50, "undetected": 30},
    "reputation": -1,
    "whois": "netname: ERX-NETBLOCK\ndescr: Early registration addresses\n",
    "crowdsourced_context": [{"title": "ThreatFox IOCs for 2026-10-06",
                              "details": "Mirai botnet C2 server (confidence level: 80%)\nSecond line"}],
}
THREATFOX_HIT = {
    "query_status": "ok",
    "data": [{"ioc": f"{IP}:3778", "threat_type": "botnet_cc", "malware": "elf.mirai",
              "confidence_level": 80, "first_seen": "2026-09-14 08:41:07 UTC", "tags": ["mirai"]}],
}
THREATFOX_MISS = {"query_status": "no_result", "data": "Your search did not yield any results"}


@pytest.fixture
def api():
    """
    Every source answers as for a flagged indicator. Any request without a route fails the test,
    so nothing reaches the real APIs; tests change a route's answer with route.respond(...).
    """
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=rf"^{OTX}.+/geo$", name="otx_geo").respond(json={"country_name": "Singapore"})
        router.get(url__regex=rf"^{OTX}.+/general$", name="otx_general").respond(
            json={"pulse_info": {"count": 2}})
        router.get(url__regex=rf"^{OTX}.+/reputation$", name="otx_reputation").respond(json={"reputation": None})
        router.get(url__startswith=VT, name="vt").respond(json={"data": {"attributes": copy.deepcopy(VT_ATTRIBUTES)}})
        router.post(THREATFOX, name="threatfox").respond(json=copy.deepcopy(THREATFOX_HIT))
        router.post(SAFE_BROWSING, name="safe_browsing").respond(json={})
        router.post(url__startswith=TTS, name="tts").respond(content=MP3, headers={"Content-Type": "audio/mpeg"})
        yield router
