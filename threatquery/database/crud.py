# threatquery/database/crud.py

from sqlalchemy.orm import Session
from threatquery.database.models import IoC
import json


def save_ioc_to_database(db: Session, ioc_value: str, ioc_type: str, result):
    new_ioc = IoC(
        type=ioc_type,
        value=ioc_value,
        whois=json.dumps(result.whois),
        geo_location=json.dumps(result.geo_location),
        malicious=json.dumps(result.malicious),
        blacklist=json.dumps(result.blacklist),
    )

    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)

    return new_ioc
