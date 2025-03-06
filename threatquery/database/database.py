# threatquery/database/database.py file

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from threatquery.database.models import Base
from config.env_config import DATABASE_URL

# Use environment variable or fallback to the config value
db_url = os.getenv("DATABASE_URL", DATABASE_URL)
engine = create_engine(db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)
