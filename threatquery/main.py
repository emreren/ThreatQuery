# threatquery/main.py

from fastapi import FastAPI
from threatquery.database.database import SessionLocal
from threatquery.analysis import ioc_analyzes
from threatquery.database.crud import save_ioc_to_database
from threatquery.logging_utils import log_info, log_error

app = FastAPI()


@app.get("/search/")
async def search_ioc(ioc_value: str):
    log_info(f"Received search request for {ioc_value}")
    merged_results = await ioc_analyzes(ioc_value)
    if merged_results:
        with SessionLocal() as db:
            try:
                save_ioc_to_database(db, ioc_value, merged_results)
            except Exception as e:
                log_error(f"Failed to save analysis result to database: {e}")

    return merged_results
