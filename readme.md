### Flask Application

The Flask application is initialized in `main.py`. It sets up the routes, configures JWT for authentication, and initializes video capture for streaming.

## Running the Project

To run the project and generate test data, follow these steps:

### 1. Set Up Environment Variables (if using PostgreSQL)
Ensure the following environment variables are set:

- `DB_USER`
- `DB_PASSWORD`
- `DB_HOST`
- `DB_PORT`
- `DB_DB`

### 2. Install Dependencies
Install the required dependencies using pip:
```sh
pip install -r requirements.txt
```
### 4. Run the Flask Application
Start the Flask application.
```sh
py main.py
```
### 5. Generate Test Data
Run the `set_test_data.py` script to reset the database and add test data. This will drop all existing tables, recreate them, and populate the database with test users, water parameters, and devices.

---

## Models

The models are defined in `/model/models.py` and represent different entities in the database.

### User Model
Represents a system user with fields for ID, name, email, and a securely stored password hash.

### Water Parameters Model
Stores environmental data related to water quality, including temperature, turbidity, pH level, and hydrogen sulfide levels. Each entry includes a timestamp.

### Job Queue Model
Manages scheduled tasks within the system. Each job has a name, a status indicating if it has been completed, and a timestamp for when it was created.

### Device Model
Represents hardware devices in the system. Each device has a unique identifier, a registration status, and a timestamp for the last activity recorded.

---

## Contribution Guidelines
To contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a pull request.


