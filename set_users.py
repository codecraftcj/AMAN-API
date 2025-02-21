from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from model.models import User, Base

# Database connection
DATABASE_URL = "sqlite:///sqlite_dev.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

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