# threatquery/modules/voice_brief.py

"""
Spoken briefings: turns an IOC analysis into a short Turkish or English summary
and renders it as audio with the ElevenLabs text-to-speech API.
"""

import logging
import re

import httpx

from config.env_config import ELEVENLABS_API_KEY, ELEVENLABS_VOICE_ID

logger = logging.getLogger(__name__)

TTS_URL = "https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"
TTS_MODEL = "eleven_multilingual_v2"
SOURCE_NAMES = {"GoogleSB": "Google Safe Browsing"}
# "False" is an answer (not malicious), not missing data
NO_DATA = ("", "unknown", "none")
# Analyzers fill fields they cannot answer with sentences ("Not applicable for this IOC type",
# "Location data not provided by Google Safe Browsing"); a hash briefing said "Konum: Not applicable..."
FILLER = re.compile(r"\bnot\b", re.IGNORECASE)

WORDS = {
    "tr": {
        "kind": {"ipv4": "IP adresi", "ipv6": "IPv6 adresi", "domain": "Alan adı", "url": "Adres",
                 "hash": "Dosya özeti", "unknown": "Gösterge"},
        "and": "ve",
        "opening": "{kind}: {ioc}.",
        "hash_short": "{head} ile başlayan {length} karakterlik özet",
        "hits": "{total} kaynaktan {n} tanesi bu göstergeyi zararlı olarak işaretliyor: {sources}.",
        "clean": "Sonuç veren kaynakların hiçbiri bu göstergeyi zararlı olarak işaretlemiyor.",
        "no_answer": "Hiçbir kaynaktan sonuç alınamadı.",
        "threat_type": "Tehdit türü: {v}.", "malware_family": "Zararlı yazılım ailesi: {v}.",
        "geo_location": "Konum: {v}.", "first_seen": "İlk görülme: {v}.",
        "silent": "{sources} bu gösterge için sonuç döndürmedi.",
        "months": ["Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül",
                   "Ekim", "Kasım", "Aralık"],
        "date": "{d} {m} {y}",
        "terms": {"botnet_cc": "botnet komuta kontrol sunucusu", "payload_delivery": "zararlı yazılım dağıtımı",
                  "payload": "zararlı yazılım"},
    },
    "en": {
        "kind": {"ipv4": "IP address", "ipv6": "IPv6 address", "domain": "Domain", "url": "URL",
                 "hash": "File hash", "unknown": "Indicator"},
        "and": "and",
        "opening": "{kind}: {ioc}.",
        "hash_short": "{length}-character hash starting with {head}",
        "hits": "{n} of {total} sources flag this indicator as malicious: {sources}.",
        "clean": "None of the sources that answered flag this indicator as malicious.",
        "no_answer": "No source returned a verdict for this indicator.",
        "threat_type": "Threat type: {v}.", "malware_family": "Malware family: {v}.",
        "geo_location": "Location: {v}.", "first_seen": "First seen: {v}.",
        "silent": "{sources} returned nothing for this indicator.",
        "months": ["January", "February", "March", "April", "May", "June", "July", "August", "September",
                   "October", "November", "December"],
        "date": "{m} {d}, {y}",
        "terms": {"botnet_cc": "botnet command and control server", "payload_delivery": "payload delivery",
                  "payload": "malware payload"},
    },
}
LANGUAGES = tuple(WORDS)


class VoiceBriefError(Exception):
    pass


def _known(value):
    text = str(value).strip() if value is not None else ""
    return text.lower() not in NO_DATA and not text.startswith("Error") and not FILLER.search(text)


def _join(sources, words):
    names = [SOURCE_NAMES.get(s, s) for s in sources]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + f" {words['and']} " + names[-1]


def _first_known(fields, name, only=None):
    for source, value in (fields.get(name) or {}).items():
        if only is not None and source not in only:
            continue
        if _known(value) and str(value).lower() not in ("true", "false"):
            return str(value)
    return None


def _spoken_dates(text, words):
    """2026-09-14 08:41:07 UTC -> 14 Eylül 2026 / September 14, 2026."""
    def repl(match):
        year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))
        return words["date"].format(d=day, m=words["months"][month - 1], y=year)
    return re.sub(r"(\d{4})-(\d{2})-(\d{2})(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:\s*UTC)?)?", repl, text)


def build_briefing(ioc_value, ioc_type, results, lang="tr", normalize=True):
    """
    Short spoken summary of an analysis. With normalize=True, timestamps and source identifiers such as
    botnet_cc are rewritten as words, and hashes are shortened to their first 8 characters (a full
    SHA-256 takes too long to listen to). Raw IP addresses, domains and English names inside Turkish
    sentences were read correctly by eleven_multilingual_v2 in testing, raw timestamps were not, so
    only those are rewritten.
    """
    words = WORDS[lang]
    fields = results if isinstance(results, dict) else vars(results)
    verdicts = {name: fields.get(name) or {} for name in ("malicious", "blacklist")}
    # Sources that do not handle this indicator type (Safe Browsing for IPs and hashes) are left out
    sources = sorted(s for s, v in verdicts["malicious"].items() if not str(v).lower().startswith("not "))
    flagged = sorted({s for verdict in verdicts.values() for s, v in verdict.items()
                      if s in sources and str(v).lower() == "true"})
    # A source answered only if it gave a verdict; "Unknown", errors and filler text do not count
    answered = {s for verdict in verdicts.values() for s, v in verdict.items()
                if s in sources and str(v).lower() in ("true", "false")}

    spoken_ioc = ioc_value
    if normalize and ioc_type == "hash":
        spoken_ioc = words["hash_short"].format(head=ioc_value[:8].lower(), length=len(ioc_value))
    parts = [words["opening"].format(kind=words["kind"].get(ioc_type, words["kind"]["unknown"]), ioc=spoken_ioc)]
    if flagged:
        parts.append(words["hits"].format(n=len(flagged), total=len(sources), sources=_join(flagged, words)))
    elif answered:
        parts.append(words["clean"])
    else:
        return " ".join(parts + [words["no_answer"]])
    for name in ("threat_type", "malware_family", "geo_location", "first_seen"):
        # Threat type and family only from sources that flagged the indicator: VirusTotal's
        # crowdsourced context names "AsyncRAT botnet C2" for 8.8.8.8, which every source calls clean
        only = flagged if name in ("threat_type", "malware_family") else None
        value = _first_known(fields, name, only)
        if value:
            if normalize:
                value = words["terms"].get(value, value.replace("_", " "))
            parts.append(words[name].format(v=value))
    silent = [s for s in sources if s not in answered and s not in flagged]
    if silent:
        parts.append(words["silent"].format(sources=_join(silent, words)))

    text = " ".join(parts)
    return _spoken_dates(text, words) if normalize else text


async def synthesize(text):
    """Renders text as MP3 with the ElevenLabs text-to-speech API."""
    if not ELEVENLABS_API_KEY:
        raise VoiceBriefError("ELEVENLABS_API_KEY is not set")

    url = TTS_URL.format(voice_id=ELEVENLABS_VOICE_ID)
    logger.info(f"Sending text-to-speech request to ElevenLabs ({len(text)} characters)")

    async with httpx.AsyncClient(timeout=120) as client:
        response = await client.post(url, params={"output_format": "mp3_44100_128"},
                                     headers={"xi-api-key": ELEVENLABS_API_KEY},
                                     json={"text": text, "model_id": TTS_MODEL})
        if response.status_code != 200:
            raise VoiceBriefError(f"ElevenLabs returned {response.status_code}: {response.text[:200]}")
        return response.content
