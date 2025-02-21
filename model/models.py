from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, ForeignKey, LargeBinary
from sqlalchemy.orm import relationship
from repository.database import Base
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# --- User Model ---
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(10), nullable=False, default='user')  # 'user' or 'admin'
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    def __init__(self, username, email, password, role="user"):
        self.username = username
        self.email = email
        self.set_password(password)
        self.role = role

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, email={self.email}, role={self.role})>"


# --- Device Model ---
class Device(Base):
    __tablename__ = 'devices'

    device_id = Column(String(50), unique=True, nullable=False,primary_key=True)
    
    local_ip = Column(String(50), nullable=True)  # Local network IP address
    status = Column(String(20), nullable=False, default='offline')  # available, offline, busy
    location = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    def __init__(self, device_id, local_ip=None, status="offline", location=None):
        self.device_id = device_id
        self.local_ip = local_ip
        self.status = status
        self.location = location

    def __repr__(self):
        return f"<Device(device_id={self.device_id}, status={self.status})>"


# --- Water Parameters Model ---
class WaterParameter(Base):
    __tablename__ = 'water_parameters'

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(255), ForeignKey('devices.device_id'), nullable=False)

    temperature = Column(Float, nullable=True)
    turbidity = Column(Float, nullable=True)
    ph_level = Column(Float, nullable=True)
    hydrogen_sulfide_level = Column(Float, nullable=True)

    created_date = Column(DateTime, default=datetime.datetime.utcnow)
    db_uploaded_date = Column(DateTime, nullable=True)  # For cleanup later

    device = relationship('Device', backref='water_parameters')

    def __init__(self, device_id, temperature, turbidity, ph_level, hydrogen_sulfide_level, db_uploaded_date=None):
        self.device_id = device_id
        self.temperature = temperature
        self.turbidity = turbidity
        self.ph_level = ph_level
        self.hydrogen_sulfide_level = hydrogen_sulfide_level
        self.db_uploaded_date = db_uploaded_date

    def __repr__(self):
        return f"<WaterParameter(id={self.id}, device_id={self.device_id}, temperature={self.temperature})>"


# --- Fish Pen Images Model ---
class FishPenImage(Base):
    __tablename__ = 'fish_pen_images'

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(255), ForeignKey('devices.device_id'), nullable=False)

    image_data = Column(LargeBinary, nullable=False)  # Stores image as binary data
    created_date = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship('Device', backref='fish_pen_images')

    def __init__(self, device_id, image_data):
        self.device_id = device_id
        self.image_data = image_data

    def __repr__(self):
        return f"<FishPenImage(id={self.id}, device_id={self.device_id})>"


# --- Feeding Schedule Model ---
class FeedingSchedule(Base):
    __tablename__ = 'feeding_schedules'

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(255), ForeignKey('devices.device_id'), nullable=False)

    schedule = Column(String(255), nullable=False)  # JSON-based or String-based schedule
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    device = relationship('Device', backref='feeding_schedule')

    def __init__(self, device_id, schedule):
        self.device_id = device_id
        self.schedule = schedule

    def __repr__(self):
        return f"<FeedingSchedule(id={self.id}, device_id={self.device_id}, schedule={self.schedule})>"


# --- Job Queue Model ---
class JobQueue(Base):
    __tablename__ = 'job_queue'

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(255), ForeignKey('devices.device_id'), nullable=False)

    task_name = Column(String(100), nullable=False)  # Task type
    status = Column(String(50), default='pending')  # pending, in-progress, completed, failed

    issued_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    issued_by = Column(Integer, ForeignKey('users.id'), nullable=True)  # User ID who issued the task
    device = relationship('Device', backref='job_queue')

    def __init__(self, device_id, task_name, status="pending"):
        self.device_id = device_id
        self.task_name = task_name
        self.status = status

    def __repr__(self):
        return f"<JobQueue(id={self.id}, device_id={self.device_id}, task={self.task_name}, status={self.status})>"


# --- Notifications Model ---
class Notification(Base):
    __tablename__ = 'notifications'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    message = Column(String(255), nullable=False)
    status = Column(String(20), default='unread')  # unread, read
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship('User', backref='notifications')

    def __init__(self, user_id, message, status="unread"):
        self.user_id = user_id
        self.message = message
        self.status = status

    def __repr__(self):
        return f"<Notification(id={self.id}, user_id={self.user_id}, status={self.status})>"


# --- System Settings Model ---
class SystemSettings(Base):
    __tablename__ = 'system_settings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    setting_name = Column(String(100), unique=True, nullable=False)
    setting_value = Column(String(255), nullable=False)

    def __init__(self, setting_name, setting_value):
        self.setting_name = setting_name
        self.setting_value = setting_value

    def __repr__(self):
        return f"<SystemSettings(id={self.id}, name={self.setting_name}, value={self.setting_value})>"
