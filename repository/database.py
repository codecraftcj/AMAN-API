from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker, declarative_base
import os

db_type = "sqlite"  # Change to "postgresql" for PostgreSQL


if db_type == "sqlite":
    database_path = "sqlite_dev.db"  # Change as needed
    connection_str = f"sqlite:///{database_path}"
else:
    user = os.environ["DB_USER"]
    password = os.environ["DB_PASSWORD"]
    host = os.environ["DB_HOST"]
    port = os.environ["DB_PORT"]
    database = os.environ["DB_DB"]
    connection_str = f"postgresql://{user}:{password}@{host}:{port}/{database}"

# SQLAlchemy engine
engine = create_engine(connection_str, connect_args={"check_same_thread": False} if db_type == "sqlite" else {})

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
