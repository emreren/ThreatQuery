# threatquery/database/database.py file

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from threatquery.database.models import Base
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

