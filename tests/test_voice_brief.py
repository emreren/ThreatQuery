# tests/test_voice_brief.py

from threatquery.modules.voice_brief import build_briefing

NOT_FOR_TYPE = "Not applicable for this IOC type"

FLAGGED_IP = {
    "malicious": {"AlienVault": "True", "VirusTotal": "False", "ThreatFox": "True", "GoogleSB": NOT_FOR_TYPE},
    "blacklist": {"AlienVault": "True", "VirusTotal": "False", "ThreatFox": "True", "GoogleSB": NOT_FOR_TYPE},
    # VirusTotal did not flag it, so its crowdsourced label is left out
    "threat_type": {"VirusTotal": "AsyncRAT botnet C2", "ThreatFox": "botnet_cc"},
    "malware_family": {"VirusTotal": "Unknown", "ThreatFox": "elf.mirai"},
    "geo_location": {"AlienVault": "Singapore", "VirusTotal": "SG",
                     "ThreatFox": "Geolocation data not directly provided by ThreatFox"},
    "first_seen": {"VirusTotal": "Unknown", "ThreatFox": "2026-09-14 08:41:07 UTC"},
}

HASH = "44d88612fea8a8f36de82e1278abb02f"
FLAGGED_HASH = {
    "malicious": {"AlienVault": "False", "VirusTotal": "True", "ThreatFox": "False", "GoogleSB": NOT_FOR_TYPE},
    "blacklist": {"AlienVault": "False", "VirusTotal": "False", "ThreatFox": "False", "GoogleSB": NOT_FOR_TYPE},
    "threat_type": {"VirusTotal": "virus.eicar/test", "ThreatFox": "Unknown"},
    "malware_family": {"VirusTotal": "virus", "ThreatFox": "Unknown"},
    "geo_location": {"AlienVault": "Not available for this IOC type", "VirusTotal": "Not available for this IOC type",
                     "ThreatFox": NOT_FOR_TYPE, "GoogleSB": NOT_FOR_TYPE},
    "first_seen": {"VirusTotal": "2006-05-22 12:42:02 UTC", "ThreatFox": "Unknown"},
}


def test_turkish_briefing_for_flagged_ip():
    assert build_briefing("139.162.5.254", "ipv4", FLAGGED_IP, "tr") == (
        "IP adresi: 139.162.5.254. 3 kaynaktan 2 tanesi bu göstergeyi zararlı olarak işaretliyor: "
        "AlienVault ve ThreatFox. Tehdit türü: botnet komuta kontrol sunucusu. "
        "Zararlı yazılım ailesi: elf.mirai. Konum: Singapore. İlk görülme: 14 Eylül 2026."
    )


def test_english_briefing_for_flagged_ip():
    assert build_briefing("139.162.5.254", "ipv4", FLAGGED_IP, "en") == (
        "IP address: 139.162.5.254. 2 of 3 sources flag this indicator as malicious: AlienVault and ThreatFox. "
        "Threat type: botnet command and control server. Malware family: elf.mirai. Location: Singapore. "
        "First seen: September 14, 2026."
    )


def test_hash_briefing_skips_filler_and_says_dates():
    text = build_briefing(HASH, "hash", FLAGGED_HASH, "tr")
    assert text == (
        "Dosya özeti: 44d88612 ile başlayan 32 karakterlik özet. 3 kaynaktan 1 tanesi bu göstergeyi zararlı "
        "olarak işaretliyor: VirusTotal. Tehdit türü: virus.eicar/test. Zararlı yazılım ailesi: virus. "
        "İlk görülme: 22 Mayıs 2006."
    )


def test_raw_briefing_keeps_hash_and_timestamp():
    text = build_briefing(HASH, "hash", FLAGGED_HASH, "en", normalize=False)
    assert HASH in text
    assert "2006-05-22 12:42:02 UTC" in text


def test_clean_indicator():
    clean = {"malicious": {"AlienVault": "False", "VirusTotal": "False", "ThreatFox": "False", "GoogleSB": "False"},
             "blacklist": {"AlienVault": "False", "VirusTotal": "False", "ThreatFox": "False", "GoogleSB": "False"}}
    assert build_briefing("example.com", "domain", clean, "en") == (
        "Domain: example.com. None of the sources that answered flag this indicator as malicious."
    )


def test_no_source_answered():
    unknown = {"malicious": {"AlienVault": "Unknown", "VirusTotal": "Unknown", "ThreatFox": "Error"}}
    assert build_briefing("example.com", "domain", unknown, "tr") == (
        "Alan adı: example.com. Hiçbir kaynaktan sonuç alınamadı."
    )


def test_silent_sources_are_named():
    partial = {"malicious": {"AlienVault": "Unknown", "VirusTotal": "False", "ThreatFox": "False", "GoogleSB": "Error"},
               "blacklist": {"AlienVault": "Unknown", "VirusTotal": "False", "ThreatFox": "False", "GoogleSB": "Error"}}
    assert build_briefing("example.com", "domain", partial, "en").endswith(
        "AlienVault and Google Safe Browsing returned nothing for this indicator."
    )
