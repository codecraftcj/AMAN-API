from flask import Flask, request, jsonify, Response, render_template
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

# Initialize Database
init_db()

# Flask App Configuration
app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = 'your-secure-secret-key'  # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)  # Token validity

# Initialize JWTManager
jwt = JWTManager(app)

# Video Streaming Variables
video_capture = cv2.VideoCapture(0)
frame_lock = threading.Lock()
latest_frame = None  # Stores the latest frame received
available_devices = {}
device_connections = {}

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
                        print(f"✅ Device {device.device_id} is {device_status}")
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
@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    
    if not all([name, email, password]):
        return jsonify({"msg": "Missing parameters"}), 400  # Bad Request
    
    if db_session.query(User).filter_by(email=email).first():
        return jsonify({"msg": "User already exists"}), 409  # Conflict
    
    new_user = User(name=name, email=email, password=password)
    db_session.add(new_user)
    db_session.commit()
    
    return jsonify({"msg": "User created successfully"}), 201  # Created

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
    return jsonify(token=token), 200

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
        limit = request.args.get("limit", default=10, type=int)  
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
        latest_param = db_session.query(WaterParameter).order_by(WaterParameter.created_date.desc()).first()
        if latest_param is None:
            return jsonify({"message": "No data available"}), 404

        serialized_data = {
            "id": latest_param.id,
            "temperature": latest_param.temperature,
            "turbidity": latest_param.turbidity,
            "ph_level": latest_param.ph_level,
            "hydrogen_sulfide_level": latest_param.hydrogen_sulfide_level,
            "created_date": latest_param.created_date.strftime('%Y-%m-%d %H:%M:%S'),
            "device_id":latest_param.device_id
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
                "id": device.id,
                "device_id": device.device_id,
                "is_registered": device.is_registered,
                "last_active": device.last_active.strftime('%Y-%m-%d %H:%M:%S')
            }
            for device in devices
        ]
        return jsonify(serialized_devices), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/device/present", methods=["POST"])
def device_present():
    """Update the last active status of a device"""
    try:
        data = request.get_json()
        device = db_session.query(Device).filter_by(device_id=data["device_id"]).first()

        if not device:
            return jsonify({"message": "Device not found"}), 404

        device.last_active = datetime.datetime.utcnow()
        db_session.commit()

        return jsonify({"message": "Device presence updated"}), 200
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()
@app.route('/register_device', methods=['POST'])
def register_device():
    """Receives device announcements and stores them as available devices."""
    try:
        data = request.get_json()
        device_id = data.get("device_id")
        local_ip = data.get("local_ip")

        if not device_id or not local_ip:
            return jsonify({"error": "Missing device ID or IP"}), 400

        available_devices[device_id] = {"local_ip": local_ip, "status": "available"}

        return jsonify({"message": "Device registered as available", "device_id": device_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_available_devices', methods=['GET'])
def get_available_devices():
    """Returns a list of available devices that can be registered."""
    return jsonify(available_devices), 200

@app.route('/confirm_device', methods=['POST'])
def confirm_device():
    """Confirms a device and adds it to the database."""
    try:
        data = request.get_json()
        device_id = data.get("device_id")
        if device_id not in available_devices:
            return jsonify({"error": "Device not found"}), 404

        device_info = available_devices.pop(device_id)
        print(device_info)
        new_device = Device(device_id=device_id, local_ip=device_info["local_ip"])
        db_session.add(new_device)
        db_session.commit()

        return jsonify({"message": f"Device {device_id} confirmed and added"}), 200
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()
        
# Start Flask App
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
