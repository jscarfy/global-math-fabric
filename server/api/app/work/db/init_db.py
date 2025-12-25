from .work_db import engine
from .models import Job, JobLease, WorkResult
from .work_db import BaseWork

def init():
    BaseWork.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init()
