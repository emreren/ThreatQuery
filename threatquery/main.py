# threatquery/main.py

import logging
import logging.config
import httpx
from fastapi import FastAPI, HTTPException, Response
from threatquery.database.database import SessionLocal
from threatquery.analyzers import IOCAnalyzer
from threatquery.database.crud import save_ioc_to_database
from config.logging_config import get_logging_config
from threatquery.modules.ioc_type_identifier import determine_ioc_type
from threatquery.modules.voice_brief import LANGUAGES, VoiceBriefError, build_briefing, synthesize
app = FastAPI()

logging.config.dictConfig(get_logging_config())
logger = logging.getLogger(__name__)


def _ioc_type(ioc_value):
    """Type of the indicator; anything else used to be sent to every source and saved as "unknown"."""
    ioc_type = determine_ioc_type(ioc_value)
    if ioc_type == "unknown":
        raise HTTPException(status_code=400,
                            detail="ioc_value must be an IP address, domain, URL or MD5/SHA-1/SHA-256 hash")
    return ioc_type


@app.get("/search/")
async def search_ioc(ioc_value: str):
    logger.info(f"Received search request for {ioc_value}")
    ioc_value = ioc_value.strip()
    ioc_type = _ioc_type(ioc_value)
    result = await IOCAnalyzer().analyze(ioc_value, ioc_type)
    with SessionLocal() as db:
        try:
            save_ioc_to_database(db, ioc_value, ioc_type, result)
        except Exception as e:
            logger.error(f"Failed to save analysis result to database: {e}")

    return result


@app.get("/brief/")
async def brief_ioc(ioc_value: str, lang: str = "tr", normalize: bool = True, text_only: bool = False):
    """Spoken summary of the analysis as MP3 (ElevenLabs), or only its text with text_only=true."""
    if lang not in LANGUAGES:
        raise HTTPException(status_code=400, detail=f"lang must be one of: {', '.join(LANGUAGES)}")
    logger.info(f"Received brief request for {ioc_value} ({lang})")
    ioc_value = ioc_value.strip()
    ioc_type = _ioc_type(ioc_value)
    result = await IOCAnalyzer().analyze(ioc_value, ioc_type)
    text = build_briefing(ioc_value, ioc_type, result, lang, normalize)
    if text_only:
        return {"ioc_value": ioc_value, "lang": lang, "text": text}

    try:
        audio = await synthesize(text)
    except (VoiceBriefError, httpx.HTTPError) as e:
        logger.error(f"Text-to-speech failed: {e}")
        raise HTTPException(status_code=502, detail=f"Text-to-speech failed: {e}")

    return Response(content=audio, media_type="audio/mpeg")
