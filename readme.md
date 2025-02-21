### Flask Application

The Flask application is initialized in `main.py`. It sets up the routes, configures JWT for authentication, and initializes background services for monitoring devices.

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

### 3. Run the Flask Application
Start the Flask application.
```sh
python main.py
```

### 4. Generate Test Data
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
Represents hardware devices in the system. Each device has a unique identifier, status, local IP, and a timestamp for the last activity recorded.

---

## API Endpoints

### General Endpoints
- `GET /` - Returns a welcome message.

### User Endpoints
- `POST /register` - Registers a new user.
  - **Request Body:**
    ```json
    {
      "name": "string",
      "email": "string",
      "password": "string"
    }
    ```
  - **Response:**
    ```json
    {"msg": "User created successfully"}
    ```

- `POST /login` - Authenticates a user and returns a JWT token.
  - **Request Body:**
    ```json
    {
      "email": "string",
      "password": "string"
    }
    ```
  - **Response:**
    ```json
    {"token": "string"}
    ```

### Water Parameters Endpoints
- `POST /get-water-parameters` - Retrieves the latest water quality data.
  - **Request Body:**
    ```json
    {
      "limit": "integer"
    }
    ```
  - **Response:**
    ```json
    [
      {
        "id": 1,
        "temperature": 25,
        "turbidity": 5,
        "ph_level": 7,
        "hydrogen_sulfide_level": 0.2,
        "created_date": "YYYY-MM-DD HH:MM:SS"
      }
    ]
    ```

- `POST /set-water-parameters` - Adds new water parameter data.
  - **Request Body:**
    ```json
    {
      "device_id": "string",
      "temperature": "integer",
      "turbidity": "integer",
      "ph_level": "integer",
      "hydrogen_sulfide_level": "integer"
    }
    ```
  - **Response:**
    ```json
    {"message": "Water parameters added successfully", "id": 1}
    ```

- `GET /get-latest-water-parameters` - Retrieves the latest recorded water quality data.
  - **Response:**
    ```json
    {
      "id": 1,
      "temperature": 25,
      "turbidity": 5,
      "ph_level": 7,
      "hydrogen_sulfide_level": 0.2,
      "created_date": "YYYY-MM-DD HH:MM:SS",
      "device_id": "string"
    }
    ```

### Job Queue Endpoints
- `POST /add-job` - Adds a new job to the queue.
  - **Request Body:**
    ```json
    {"job_name": "string", "device_id": "string"}
    ```
  - **Response:**
    ```json
    {"message": "Job added successfully", "id": 1}
    ```

- `GET /get-jobs` - Retrieves all jobs.
  - **Response:**
    ```json
    [{"id": 1, "job_name": "string", "is_completed": false, "created_date": "YYYY-MM-DD HH:MM:SS"}]
    ```

- `PUT /update-job/<int:job_id>` - Updates job details.
  - **Request Body:**
    ```json
    {"job_name": "string", "is_completed": true}
    ```
  - **Response:**
    ```json
    {"message": "Job updated successfully"}
    ```

- `DELETE /delete-job/<int:job_id>` - Deletes a job.
  - **Response:**
    ```json
    {"message": "Job deleted successfully"}
    ```

### Device Endpoints
- `GET /devices` - Retrieves a list of all registered devices.
  - **Response:**
    ```json
    [{"device_id": "string", "status": "string", "local_ip": "string"}]
    ```

- `POST /device/present` - Updates device presence status.
  - **Request Body:**
    ```json
    {"device_id": "string"}
    ```
  - **Response:**
    ```json
    {"message": "Device presence updated"}
    ```

- `POST /register_device` - Registers a new available device.
  - **Request Body:**
    ```json
    {"device_id": "string", "local_ip": "string"}
    ```
  - **Response:**
    ```json
    {"message": "Device registered as available", "device_id": "string"}
    ```

- `GET /get_available_devices` - Retrieves available devices not registered in the database.
  - **Response:**
    ```json
    {"device_id": {"local_ip": "string", "status": "available"}}
    ```

- `POST /confirm_device` - Confirms and adds a device to the database.
  - **Request Body:**
    ```json
    {"device_id": "string"}
    ```
  - **Response:**
    ```json
    {"message": "Device confirmed and added"}
    ```

- `DELETE /remove_device` - Removes a device from the database.
  - **Request Body:**
    ```json
    {"device_id": "string"}
    ```
  - **Response:**
    ```json
    {"message": "Device removed successfully"}
    ```

---

## Contribution Guidelines
To contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a pull request.
