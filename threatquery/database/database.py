# threatquery/database/database.py file

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from threatquery.database.models import Base
from config.env_config import DATABASE_URL

# Use environment variable or fallback to the config value
db_url = os.getenv("DATABASE_URL", DATABASE_URL)
# The project installs psycopg2-binary. SQLAlchemy 2.1 maps plain postgresql:// to psycopg 3,
# so without poetry.lock a fresh install failed with "No module named 'psycopg'".
if db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
engine = create_engine(db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)
