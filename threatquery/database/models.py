from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class IoC(Base):
    __tablename__ = 'ioc'

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, index=True)
    value = Column(String, index=True)
    geometric_location = Column(String)
    malicious_control = Column(String)
    blacklist = Column(String)
    whois = Column(String)
