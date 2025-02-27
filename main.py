from flask import Flask, request, jsonify, Response, render_template, make_response
from repository.database import init_db, db_session
from model.models import User, WaterParameter, JobQueue, Device
import os
import datetime
from datetime import timedelta
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_cors import CORS
import cv2
import threading
import numpy as np
from model.DeviceConnections import DeviceConnection
import requests
import threading
import time
from flask_socketio import SocketIO, emit
import base64
import eventlet
from aiortc import RTCPeerConnection, RTCSessionDescription
from repository.database import db_session
# Initialize Database
init_db()
# Flask App Configuration
app = Flask(__name__)
from flask_cors import CORS

CORS(app, supports_credentials=True, origins="http://192.168.0.42")

app.config['JWT_SECRET_KEY'] = 'your-secure-secret-key'  # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)  # Token validity

# Initialize JWTManager
jwt = JWTManager(app)
available_devices = {}



# ================================#
#       DEVICE MONITORING         #
# ================================#
def ping_devices():
    """Continuously pings all registered devices to check their status."""
    while True:
        try:
            devices = db_session.query(Device).all()
            for device in devices:
                if not device.local_ip:
                    continue  # Skip devices without an IP

                device_url = f"http://{device.local_ip}:8082/device_info"  # Ping the emulator
                try:
                    response = requests.get(device_url, timeout=3)
                    if response.status_code == 200:
                        device_status = response.json().get("status", "unknown")
                        device.status = device_status
                        print(f"✅ Device {device.device_id} is {device_status} at {device.local_ip}")
                    else:
                        print(f"⚠️ Device {device.device_id} did not respond. Status: {response.status_code}")

                except requests.RequestException as e:
                    print(f"❌ Error pinging device {device.device_id}: {e}")

            db_session.commit()  # Save any changes to device statuses

        except Exception as e:
            print(f"❌ Error in device monitoring thread: {e}")
            
        time.sleep(10)  # Ping devices every 10 seconds

# Start the background thread
device_ping_thread = threading.Thread(target=ping_devices, daemon=True)
device_ping_thread.start()


# ================================#
#           GENERAL ROUTES        #
# ================================#
@app.route("/")
def hello_world():
    return jsonify({"message": "You have reached the Terminal Web App!"})


# ================================#
#           USER MODEL            #
# ================================#
@app.route("/get-users", methods=["GET"])
def get_users():
    users = User.query.all()
    serialized_users = [
        {"id": u.id, "username": u.username, "email": u.email, "role": u.role}
        for u in users
    ]
    return jsonify(serialized_users), 200


@app.route("/register-user", methods=["POST"])
def register_user():
    data = request.get_json()
    
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "user")

    if not all([username, email, password]):
        return jsonify({"msg": "Missing required fields"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "User already exists"}), 409

    new_user = User(username=username, email=email, password=password, role=role)
    db_session.add(new_user)
    db_session.commit()

    return jsonify({"msg": "User registered successfully"}), 201

@app.route("/update-user/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    data = request.get_json()
    user = db_session.query(User).filter_by(id=user_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    user.username = data.get("username", user.username)
    user.email = data.get("email", user.email)
    user.role = data.get("role", user.role)
    
    db_session.commit()
    return jsonify({"msg": "User updated successfully"}), 200

@app.route("/delete-user/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    user = db_session.query(User).filter_by(id=user_id).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404

    db_session.delete(user)
    db_session.commit()
    return jsonify({"msg": "User deleted successfully"}), 200
@app.route('/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({"msg": "Missing parameters"}), 400  # Bad Request

    user = db_session.query(User).filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({"msg": "Bad email or password"}), 401  # Unauthorized

    token = create_access_token(identity=str(user.id))

    response = jsonify({"token": token, "role": user.role})
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response, 200  # ✅ Ensure 'role' is returned
    
     # ✅ Ensure the role is included in the response
    return jsonify(token=token, role=user.role), 200  # ✅ 'role' must be returned

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logs out the user by revoking their JWT token"""
    response = jsonify({"message": "User logged out successfully"})
    
    # Remove JWT from frontend by setting an empty token with an immediate expiry
    response.set_cookie('access_token_cookie', '', expires=0, httponly=True)
    
    return response, 200

@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    """JWT protected route"""
    current_user_id = get_jwt_identity()
    
    user = db_session.query(User).get(current_user_id)  
    if not user:
        return jsonify({"msg": "User not found"}), 404  # Not Found
    
    return jsonify(logged_in_as=user.name), 200


# ================================#
#     WATER PARAMETERS MODEL      #
# ================================#
@app.route("/get-water-parameters", methods=["GET"])
def get_water_parameters():
    """Retrieve water parameters"""
    try:
        limit = request.args.get("limit", default=10, type=int)  # Get query parameter

        data = db_session.query(WaterParameter).order_by(WaterParameter.created_date.desc()).limit(limit).all()

        serialized_data = [
            {
                "id": param.id,
                "temperature": param.temperature,
                "turbidity": param.turbidity,
                "ph_level": param.ph_level,
                "hydrogen_sulfide_level": param.hydrogen_sulfide_level,
                "created_date": param.created_date.strftime('%Y-%m-%d %H:%M:%S')
            }
            for param in data
        ]
        return jsonify(serialized_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/set-water-parameters', methods=['POST'])
def set_water_parameters():
    """Store new water parameters"""
    try:
        data = request.get_json()
        required_fields = ['device_id', 'temperature', 'turbidity', 'ph_level', 'hydrogen_sulfide_level']
        
        for field in required_fields:
            if field not in data or data[field] is None:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        new_parameters = WaterParameter(**data)
        db_session.add(new_parameters)
        db_session.commit()

        return jsonify({'message': 'Water parameters added successfully', 'id': new_parameters.id}), 201
    except Exception as e:
        db_session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db_session.close()

@app.route("/get-latest-water-parameters", methods=["GET"])
def get_latest_water_parameters():
    try:
        latest_param = db_session.query(WaterParameter).order_by(WaterParameter.created_date.desc()).limit(1).first()
        if latest_param is None:
            return jsonify({"message": "No data available"}), 404

        serialized_data = {
            "id": latest_param.id,
            "temperature": latest_param.temperature,
            "turbidity": latest_param.turbidity,
            "ph_level": latest_param.ph_level,
            "hydrogen_sulfide_level": latest_param.hydrogen_sulfide_level,
            "created_date": latest_param.created_date.strftime('%Y-%m-%d %H:%M:%S'),
            "device_id": latest_param.device_id
        }

        return jsonify(serialized_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# ================================#
#         JOB QUEUE MODEL         #
# ================================#
@app.route("/add-job", methods=["POST"])
def add_job():
    """Add a new job to the queue"""
    try:
        data = request.get_json()
        required_fields = ["job_name", "device_id"]
        
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        new_job = JobQueue(**data)
        db_session.add(new_job)
        db_session.commit()

        return jsonify({'message': 'Job added successfully', 'id': new_job.id}), 201
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()
        
@app.route("/get-jobs", methods=["GET"])
def get_jobs():
    try:
        jobs = db_session.query(JobQueue).all()
        serialized_jobs = [
            {
                "id": job.id,
                "job_name": job.job_name,
                "is_completed": job.is_completed,
                "created_date": job.created_date.strftime('%Y-%m-%d %H:%M:%S')
            }
            for job in jobs
        ]
        return jsonify(serialized_jobs), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/update-job/<int:job_id>", methods=["PUT"])
def update_job(job_id):
    try:
        data = request.get_json()
        job = db_session.query(JobQueue).filter(JobQueue.id == job_id).first()

        if job is None:
            return jsonify({"message": "Job not found"}), 404

        if "job_name" in data:
            job.job_name = data['job_name']
        if "is_completed" in data:
            job.is_completed = data['is_completed']

        db_session.commit()
        return jsonify({"message": "Job updated successfully"}), 200
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()

@app.route("/delete-job/<int:job_id>", methods=["DELETE"])
def delete_job(job_id):
    try:
        job = db_session.query(JobQueue).filter(JobQueue.id == job_id).first()

        if job is None:
            return jsonify({"message": "Job not found"}), 404

        db_session.delete(job)
        db_session.commit()
        return jsonify({"message": "Job deleted successfully"}), 200
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()

# ================================#
#         DEVICE MODEL            #
# ================================#
@app.route("/devices", methods=["GET"])
def get_devices():
    """Retrieve all registered devices"""
    try:
        devices = db_session.query(Device).all()
        serialized_devices = [
            {
                "device_id": device.device_id,
                "status":device.status,
                "local_ip": device.local_ip,
            }
            for device in devices
        ]
        return jsonify(serialized_devices), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

        
@app.route('/register_device', methods=['POST'])
def register_device():
    """Receives device announcements and stores them as available devices, 
    but only if the device is not already registered in the database."""
    try:
        data = request.get_json()
        device_id = data.get("device_id")
        local_ip = data.get("local_ip")

        if not device_id or not local_ip:
            return jsonify({"error": "Missing device ID or IP"}), 400

        # Check if the device already exists in the database
        existing_device = db_session.query(Device).filter_by(device_id=device_id).first()
        if existing_device:
            return jsonify({"message": "Device is already registered in the system"}), 200  # Conflict
        else:
            # If the device is not in the database, add it to available devices
            available_devices[device_id] = {"local_ip": local_ip, "status": "available"}
            return jsonify({"message": "Device registered as available", "device_id": device_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get_available_devices', methods=['GET'])
def get_available_devices():
    """Returns a list of available devices that are not already in the database."""
    try:
        # Get all registered device IDs from the database
        registered_devices = {device.device_id for device in db_session.query(Device.device_id).all()}

        # Filter available devices to exclude already registered ones
        filtered_devices = {
            device_id: info for device_id, info in available_devices.items() if device_id not in registered_devices
        }

        return jsonify(filtered_devices), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/confirm_device', methods=['POST'])
def confirm_device():
    """Confirms a device and adds it to the database."""
    try:
        data = request.get_json()
        device_id = data.get("device_id")
        if device_id not in available_devices:
            return jsonify({"error": "Device not found"}), 404

        device_info = available_devices.pop(device_id)
        new_device = Device(device_id=device_id, local_ip=device_info["local_ip"])
        db_session.add(new_device)
        db_session.commit()

        return jsonify({"message": f"Device {device_id} confirmed and added"}), 200
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/remove_device', methods=['DELETE'])
def remove_device():
    """Disconnects a device by removing it from the database."""
    try:
        data = request.get_json()
        device_id = data.get("device_id")

        if not device_id:
            return jsonify({"error": "Missing device ID"}), 400

        # Check if the device exists in the database
        device = db_session.query(Device).filter_by(device_id=device_id).first()

        if not device:
            return jsonify({"message": "Device not found in the database"}), 404

        # Remove the device from the database
        db_session.delete(device)
        db_session.commit()

        return jsonify({"message": f"Device {device_id} has been disconnected and removed"}), 200
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()

# Start Flask App
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
