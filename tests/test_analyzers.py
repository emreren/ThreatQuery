# tests/test_analyzers.py

import asyncio
import copy

import pytest

from threatquery.analyzers import IOCAnalyzer
from tests.conftest import IP, THREATFOX_HIT, THREATFOX_MISS, VT_ATTRIBUTES

HASH = "44d88612fea8a8f36de82e1278abb02f"


def analyze(value, ioc_type):
    return asyncio.run(IOCAnalyzer().analyze(value, ioc_type))


def test_ip_lookup_merges_every_source(api):
    results = analyze(IP, "ipv4")

    assert results.malicious == {"AlienVault": "True", "VirusTotal": "True", "ThreatFox": "True",
                                 "GoogleSB": "Not applicable for this IOC type"}
    assert results.blacklist["AlienVault"] == "True"
    assert results.geo_location["AlienVault"] == "Singapore"
    assert results.geo_location["VirusTotal"] == "SG"
    assert results.malware_family["ThreatFox"] == "elf.mirai"
    assert results.threat_type == {"VirusTotal": "Mirai botnet C2 server (confidence level: 80%)",
                                   "ThreatFox": "botnet_cc"}
    assert results.first_seen["ThreatFox"] == "2026-09-14 08:41:07 UTC"


def test_alienvault_blacklist_follows_pulses_without_reputation_call(api):
    # /reputation answered {"reputation": null}, and comparing null with 0 made the blacklist
    # "Unknown" for every indicator
    assert analyze(IP, "ipv4").blacklist["AlienVault"] == "True"
    api["otx_general"].respond(json={"pulse_info": {"count": 0}})
    assert analyze(IP, "ipv4").blacklist["AlienVault"] == "False"
    assert not api["otx_reputation"].called


def test_each_source_is_asked_once_per_lookup(api):
    analyze(IP, "ipv4")
    assert api["vt"].call_count == 1
    assert api["threatfox"].call_count == 1
    assert api["otx_general"].call_count == 1
    assert api["otx_geo"].call_count == 1


def test_ipv6_uses_the_ipv6_alienvault_path(api):
    analyze("2001:db8::1", "ipv6")
    assert "/IPv6/2001:db8::1/geo" in str(api["otx_geo"].calls.last.request.url)


@pytest.mark.parametrize("confidence, suspicious", [(25, "True"), (50, "True"), (75, "False"), (100, "False")])
def test_threatfox_low_confidence_is_suspicious(api, confidence, suspicious):
    hit = copy.deepcopy(THREATFOX_HIT)
    hit["data"][0]["confidence_level"] = confidence
    api["threatfox"].respond(json=hit)
    assert analyze(IP, "ipv4").suspicious["ThreatFox"] == suspicious


def test_threatfox_without_results(api):
    api["threatfox"].respond(json=THREATFOX_MISS)
    results = analyze(IP, "ipv4")
    assert results.malicious["ThreatFox"] == "False"
    assert results.malware_family["ThreatFox"] == "Unknown"


def test_virustotal_ignores_crowdsourced_context_when_engines_are_clean(api):
    attributes = copy.deepcopy(VT_ATTRIBUTES)
    attributes["last_analysis_stats"]["malicious"] = 0
    api["vt"].respond(json={"data": {"attributes": attributes}})
    assert analyze(IP, "ipv4").threat_type["VirusTotal"] == "Unknown"


def test_virustotal_first_seen_is_a_utc_date(api):
    api["vt"].respond(json={"data": {"attributes": {
        "last_analysis_stats": {"malicious": 60}, "first_submission_date": 1148301722}}})
    results = analyze(HASH, "hash")
    assert results.first_seen["VirusTotal"] == "2006-05-22 12:42:02 UTC"
    assert str(api["vt"].calls.last.request.url).endswith(f"/files/{HASH}")


def test_virustotal_url_lookup_lets_virustotal_canonicalise_the_url(api):
    # VirusTotal stores https://host as https://host/; the SHA-256 of the raw URL was a 404, so a URL
    # 11 engines flag came back "Unknown"
    results = analyze("https://google32.m4ntapaset.ink", "url")

    assert results.malicious["VirusTotal"] == "True"
    url_request = next(c.request for c in api["vt"].calls if "/urls/" in str(c.request.url))
    assert str(url_request.url).endswith("/urls/aHR0cHM6Ly9nb29nbGUzMi5tNG50YXBhc2V0Lmluaw")


def test_safe_browsing_key_is_sent_in_a_header(api):
    api["safe_browsing"].respond(json={"matches": [{"threatType": "MALWARE"}]})
    results = analyze("example.com", "domain")

    assert results.malicious["GoogleSB"] == "True"
    request = api["safe_browsing"].calls.last.request
    # in the URL, httpx logged the key to app.log
    assert "key=" not in str(request.url)
    assert request.headers["X-Goog-Api-Key"] == "test-gsb-key"


def test_source_errors_do_not_break_the_lookup(api):
    api["vt"].respond(status_code=429)
    api["threatfox"].mock(side_effect=ConnectionError("network down"))
    results = analyze(IP, "ipv4")
    assert results.malicious["VirusTotal"] == "Unknown"
    assert results.malicious["ThreatFox"] == "Unknown"
    assert results.malicious["AlienVault"] == "True"
