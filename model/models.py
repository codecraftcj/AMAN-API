from sqlalchemy import Column, Integer, String, DateTime, Boolean
from repository.database import Base
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)  # Stores the hashed password
    
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.set_password(password)  # Hashes the password and stores it
    
    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verifies the password against the stored hash."""
        return check_password_hash(self.password_hash, password)
    
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

class Device(Base):
    __tablename__ = 'devices'
    id = Column(Integer, primary_key=True)
    device_id = Column(String(100), unique=True, nullable=False)
    is_registered = Column(Boolean, default=False)
    last_active = Column(DateTime, default=datetime.datetime.utcnow)

    def __init__(self, device_id, is_registered=False):
        self.device_id = device_id
        self.is_registered = is_registered

    def __repr__(self):
        return f'<Device {self.device_id!r}, is_registered={self.is_registered}, last_active={self.last_active}>'
