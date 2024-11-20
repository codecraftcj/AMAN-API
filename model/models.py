from sqlalchemy import Column, Integer, String, DateTime, Boolean
from repository.database import Base
import datetime

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True)
    email = Column(String(120), unique=True)

    def __init__(self, name=None, email=None):
        self.name = name
        self.email = email

    def __repr__(self):
        return f'<User {self.name!r}>'

class WaterParameters(Base):
    __tablename__='water_quality_parameters'
    id = Column(Integer, primary_key=True)
    temperature = Column(Integer)
    turbidity = Column(Integer)
    ph_level = Column(Integer)
    hydrogen_sulfide_level = Column(Integer)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)

class JobQueue(Base):
    __tablename__ = 'job_queue'
    id = Column(Integer, primary_key=True)
    job_name = Column(String(100))
    is_completed = Column(Boolean, default=False)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)

    def __init__(self, job_name=None):
        self.job_name = job_name

    def __repr__(self):
        return f'<JobQueue {self.job_name!r}, is_completed={self.is_completed}>'