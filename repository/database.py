from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker, declarative_base
import os

user = os.environ["DB_USER"]
password = os.environ["DB_PASSWORD"]
host = os.environ["DB_HOST"]
port = os.environ["DB_PORT"]
database = os.environ["DB_DB"]
connection_str = f"postgresql://{user}:{password}@{host}:{port}/{database}"
# SQLAlchemy engine
engine = create_engine(connection_str)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_db()
    # import yourapplication.models
    Base.metadata.create_all(bind=engine)