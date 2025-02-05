import requests
from repository.database import init_db, Base, engine, db_session

# Flask app base URL
BASE_URL = "http://localhost:8080"

def reset_database():
    """Drops all tables and reinitializes the database."""
    print("Dropping all tables...")
    Base.metadata.drop_all(engine)
    print("Recreating tables...")
    init_db()
    print("Database reset complete.")

def add_test_users():
    """Adds test users."""
    users = [
        {"name": "John Doe", "email": "john@example.com", "password": "password123"},
        {"name": "Jane Smith", "email": "jane@example.com", "password": "password123"},
    ]
    for user in users:
        response = requests.post(f"{BASE_URL}/register", json=user)
        print(f"Adding user {user['name']}: {response.json()}")

def add_test_water_parameters():
    """Adds test water quality parameters."""
    parameters = [
        {"temperature": 25, "turbidity": 5, "ph_level": 7, "hydrogen_sulfide_level": 0.3},
        {"temperature": 26, "turbidity": 4, "ph_level": 7.2, "hydrogen_sulfide_level": 0.2},
    ]
    for param in parameters:
        response = requests.post(f"{BASE_URL}/set_water_parameters", json=param)
        print(f"Adding water parameters: {response.json()}")

# def add_test_jobs():
#     """Adds test job queue entries."""
#     jobs = [
#         {"job_name": "Feed Fish"},
#         {"job_name": "Monitor Water Quality"},
#     ]
#     for job in jobs:
#         response = requests.post(f"{BASE_URL}/add-job", json=job)
#         print(f"Adding job {job['job_name']}: {response.json()}")

def add_test_devices():
    """Adds test devices."""
    devices = [
        {"device_id": "device_001"},
        {"device_id": "device_002"},
    ]
    for device in devices:
        response = requests.post(f"{BASE_URL}/device/register", json=device)
        print(f"Registering device {device['device_id']}: {response.json()}")

if __name__ == "__main__":
    reset_database()
    add_test_users()
    add_test_water_parameters()
    # add_test_jobs()
    add_test_devices()
    print("Test data setup complete.")