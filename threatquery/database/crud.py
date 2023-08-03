# threatquery/database/crud.py file

from .models import IoC
from sqlalchemy.orm import Session


def save_ioc_to_database(db: Session, ioc_value: str, analysis_result: dict):
    new_ioc = IoC(
        type=analysis_result.get("type"),
        value=ioc_value,
        geometric_location=analysis_result.get("geometric_location"),
        malicious_control=analysis_result.get("malicious_control"),
        blacklist=analysis_result.get("blacklist"),
        whois=analysis_result.get("whois"),
    )

    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)

    return new_ioc
