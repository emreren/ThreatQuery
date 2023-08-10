# threatquery/database/models.py

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class IoC(Base):
    __tablename__ = 'ioc'

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, index=True)
    value = Column(String, index=True)
    whois = Column(String, index=True)
    geo_location = Column(String, index=True)
    malicious = Column(String, index=True)
    blacklist = Column(String, index=True)
