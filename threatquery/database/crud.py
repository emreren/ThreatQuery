# threatquery/database/crud.py file

from threatquery.database.models import IoC
from sqlalchemy.orm import Session

import json

def save_ioc_to_database(db: Session, ioc_value: str, analysis_result: dict):

    new_ioc = IoC(
        type=analysis_result.get("type"),
        value=ioc_value,
        geometric_location=analysis_result.get("geometric_location"),
        last_analysis_stats=json.dumps(analysis_result.get("last_analysis_stats")),
        whois=json.dumps(analysis_result.get("whois")),
        safebrowsing=json.dumps(analysis_result.get("safebrowsing")),
    )

    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)

    return new_ioc
