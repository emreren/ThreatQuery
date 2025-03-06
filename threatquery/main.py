# threatquery/main.py

import logging
from fastapi import FastAPI
from threatquery.database.database import SessionLocal
from threatquery.analyzers import IOCAnalyzer
from threatquery.database.crud import save_ioc_to_database
from config.logging_config import get_logging_config
from threatquery.modules.ioc_type_identifier import determine_ioc_type
app = FastAPI()

logging.config.dictConfig(get_logging_config())
logger = logging.getLogger(__name__)


@app.get("/search/")
async def search_ioc(ioc_value: str):
    logger.info(f"Received search request for {ioc_value}")
    ioc_type = determine_ioc_type(ioc_value)
    result = await IOCAnalyzer().analyze(ioc_value, ioc_type)
    with SessionLocal() as db:
        try:
            save_ioc_to_database(db, ioc_value, ioc_type, result)
        except Exception as e:
            logger.error(f"Failed to save analysis result to database: {e}")

    return result
