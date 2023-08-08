# threatquery/database/database.py file

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from threatquery.database.models import Base
from config.env_config import DATABASE_URL

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)
