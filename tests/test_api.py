# tests/test_api.py

import json

import pytest
from fastapi.testclient import TestClient

from threatquery.database.database import SessionLocal
from threatquery.database.models import IoC
from threatquery.main import app
from tests.conftest import IP, MP3

client = TestClient(app)


def saved(value):
    with SessionLocal() as db:
        return db.query(IoC).filter(IoC.value == value).all()


def test_search_returns_and_saves_the_analysis(api):
    response = client.get("/search/", params={"ioc_value": f"  {IP}\n"})

    assert response.status_code == 200
    assert response.json()["malicious"]["AlienVault"] == "True"
    rows = saved(IP)
    assert len(rows) == 1
    assert rows[0].type == "ipv4"
    assert json.loads(rows[0].malware_family)["ThreatFox"] == "elf.mirai"


@pytest.mark.parametrize("value", ["hello world", "999.1.1.1", ""])
def test_unrecognised_input_is_rejected_before_any_lookup(api, value):
    response = client.get("/search/", params={"ioc_value": value})

    assert response.status_code == 400
    assert not api.calls
    assert saved(value) == []


def test_brief_text_only(api):
    response = client.get("/brief/", params={"ioc_value": IP, "lang": "en", "text_only": "true"})

    assert response.status_code == 200
    assert response.json()["text"].startswith(f"IP address: {IP}. 3 of 3 sources flag this indicator")
    assert not api["tts"].called


def test_brief_returns_mp3(api):
    response = client.get("/brief/", params={"ioc_value": IP})

    assert response.status_code == 200
    assert response.headers["content-type"] == "audio/mpeg"
    assert response.content == MP3
    request = api["tts"].calls.last.request
    assert request.headers["xi-api-key"] == "test-elevenlabs-key"
    assert json.loads(request.content)["text"].startswith(f"IP adresi: {IP}.")


def test_brief_reports_text_to_speech_failure(api):
    api["tts"].respond(status_code=401, json={"detail": "invalid api key"})

    response = client.get("/brief/", params={"ioc_value": IP})

    assert response.status_code == 502
    assert "401" in response.json()["detail"]


def test_brief_without_elevenlabs_key(api, monkeypatch):
    monkeypatch.setattr("threatquery.modules.voice_brief.ELEVENLABS_API_KEY", "")

    response = client.get("/brief/", params={"ioc_value": IP})

    assert response.status_code == 502
    assert "ELEVENLABS_API_KEY" in response.json()["detail"]


def test_brief_rejects_unsupported_language(api):
    response = client.get("/brief/", params={"ioc_value": IP, "lang": "de"})

    assert response.status_code == 400
    assert not api.calls
