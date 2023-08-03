# threatquery/main.py

from fastapi import FastAPI
from .database.database import SessionLocal
from .analysis import analyze_ioc
from .database.crud import save_ioc_to_database
from .logging_utils import log_info, log_error

app = FastAPI()


@app.get("/search/")
async def search_ioc(ioc_value: str):
    log_info(f"Received search request for {ioc_value}")
    analysis_result = await analyze_ioc(ioc_value)
    if analysis_result:
        with SessionLocal() as db:
            try:
                save_ioc_to_database(db, ioc_value, analysis_result)
            except Exception as e:
                log_error(f"Failed to save analysis result to database: {e}")

    return analysis_result
