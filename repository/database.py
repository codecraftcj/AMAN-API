from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker, declarative_base
import os

# Environment variables for MySQL configuration

user = "AMAN_INSTANCE" # Default to 'root'
password ="amanpapasa"# Default empty (set password if configured)
host =  "localhost" # Default to localhost
port = "3306"  # MySQL default port
database =  "AMAN"  # Default database (change as needed)
# MySQL Connection String
connection_str = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
print(connection_str)
# SQLAlchemy engine
# SQLAlchemy engine with connection pooling
engine = create_engine(
    connection_str,
    pool_size=10,         # Increase pool size (default is 5)
    max_overflow=20,      # Allow additional connections beyond pool_size
    pool_timeout=30,      # Wait time for a connection before timing out
    pool_recycle=1800,    # Recycle connections every 30 minutes
    pool_pre_ping=True    # Prevent stale connections
)

db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))

Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    """
    Initialize the database by creating all defined tables.
    """
    # Import all models to ensure they are registered
    # Example: from yourapplication.models import SomeModel
    Base.metadata.create_all(bind=engine)
