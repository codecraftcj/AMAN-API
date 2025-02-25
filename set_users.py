from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker, declarative_base
from model.models import User, Base

# MySQL Database Configuration
user = "AMAN_INSTANCE"
password = "amanpapasa"
host = "localhost"
port = "3306"
database = "AMAN"

# MySQL Connection String
connection_str = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"

# SQLAlchemy Engine with Connection Pooling
engine = create_engine(
    connection_str,
    pool_size=10,         # Increase pool size (default is 5)
    max_overflow=20,      # Allow additional connections beyond pool_size
    pool_timeout=30,      # Wait time for a connection before timing out
    pool_recycle=1800,    # Recycle connections every 30 minutes
    pool_pre_ping=True    # Prevent stale connections
)

# Create a session factory
Session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
session = Session()

# Ensure all tables are created
Base.metadata.create_all(engine)

# Define users
user1 = User(username="regular_user", email="user@example.com", password="password123", role="user")
admin1 = User(username="admin_user", email="admin@example.com", password="adminpassword", role="admin")

# Add users to session and commit
session.add(user1)
session.add(admin1)
session.commit()

print("Users created successfully:")
print(f"User: {user1.username}, Email: {user1.email}, Role: {user1.role}")
print(f"Admin: {admin1.username}, Email: {admin1.email}, Role: {admin1.role}")

session.close()
