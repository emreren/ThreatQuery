# threatquery/main.py

import logging

from fastapi import FastAPI
from threatquery.database.database import SessionLocal
from threatquery.analyzes import ioc_analyzes
from threatquery.database.crud import save_ioc_to_database
from config.logging_config import get_logging_config

app = FastAPI()


logging.config.dictConfig(get_logging_config())
logger = logging.getLogger(__name__)


@app.get("/search/")
async def search_ioc(ioc_value: str):
    logger.info(f"Received search request for {ioc_value}")
    merged_results = await ioc_analyzes(ioc_value)
    if merged_results:
        with SessionLocal() as db:
            try:
                save_ioc_to_database(db, ioc_value, merged_results)
            except Exception as e:
                logger.error(f"Failed to save analysis result to database: {e}")

    return merged_results
