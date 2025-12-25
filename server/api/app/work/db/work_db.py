import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

WORK_DB = os.environ.get("GMF_WORK_DB", "sqlite:///ledger/work/work.sqlite")
engine = create_engine(WORK_DB, connect_args={"check_same_thread": False})
SessionWork = sessionmaker(autocommit=False, autoflush=False, bind=engine)
BaseWork = declarative_base()
