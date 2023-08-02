import logging

from fastapi import FastAPI
from .database.database import SessionLocal
from .analysis import analyze_ioc_and_save
from .database.crud import save_ioc_to_database

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename='app.log', filemode='a')

logger = logging.getLogger(__name__)

app = FastAPI()

@app.get("/search/")
async def search_ioc(ioc_value: str):
    logger.info(f"Received search request for {ioc_value}")
    analysis_result = await analyze_ioc_and_save(ioc_value)
    if analysis_result:
        with SessionLocal() as db:
            save_ioc_to_database(db, ioc_value, analysis_result)

    return {"message": f"Analiz için {ioc_value} değeri sorgusu gönderildi ve analiz ediliyor."}
