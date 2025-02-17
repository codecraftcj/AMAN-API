from flask import Flask, request, jsonify, Response, render_template
from repository.database import init_db, db_session
from model.models import User, WaterParameters, JobQueue,Device
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
init_db()

app = Flask(__name__)
CORS(app)
# Configure application with a secret key and JWT settings
app.config['JWT_SECRET_KEY'] = 'your-secure-secret-key'  # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)  # Token validity

# Initialize JWTManager
jwt = JWTManager(app)

# Initialize video capture (0 for default webcam)
video_capture = cv2.VideoCapture(0)
frame_lock = threading.Lock()
latest_frame = None  # Stores the latest frame received
available_devices = {}
device_connections = {}

def generate_frames():
    """ Continuously stream the latest received frame """
    global latest_frame

    while True:
        with frame_lock:
            if latest_frame is None:
                continue  # No frame available yet

            # Encode frame as JPEG
            _, buffer = cv2.imencode('.jpg', latest_frame)
            frame_bytes = buffer.tobytes()

        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')


@app.route("/")
def hello_world():
    return jsonify({"message": "You have reached the Terminal Web App!"})

@app.route("/adduser/<user>")
def add_user(user):
    u = User(user, f'{user}@localhost')
    db_session.add(u)
    db_session.commit()
    return "success"

@app.route("/get-water-parameters", methods=["GET"])
def get_water_parameters():
    try:

        limit = request.args.get("limit", default=10, type=int)  # Default to latest 10 records
        
        data = (
            db_session.query(WaterParameters)
            .order_by(WaterParameters.created_date.desc())  # Get the latest first
            .limit(limit)
            .all()
        )

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
    try:
        data = request.get_json()
        required_fields = ['device_id', 'temperature', 'turbidity', 'ph_level', 'hydrogen_sulfide_level']
        
        # Validate required fields
        for field in required_fields:
            if field not in data or data[field] is None:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create new water parameter entry
        new_parameters = WaterParameters(
            device_id=data['device_id'],  # Store device ID
            temperature=data['temperature'],
            turbidity=data['turbidity'],
            ph_level=data['ph_level'],
            hydrogen_sulfide_level=data['hydrogen_sulfide_level']
        )
        
        # Save to database
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
        latest_param = db_session.query(WaterParameters).order_by(WaterParameters.created_date.desc()).first()
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

# CRUD routes for JobQueue

@app.route("/add-job", methods=["POST"])
def add_job():
    try:
        data = request.get_json()
        required_fields = ["job_name", "device_id"]
        
        # Ensure required fields exist
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        new_job = JobQueue(job_name=data['job_name'], device_id=data['device_id'])
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

@app.route('/register', methods=['POST'])
def register():
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
    current_user_id = get_jwt_identity()
    print(f"Current User ID: {current_user_id}")
    
    # Ensure `current_user_id` is used as a string
    user = db_session.query(User).get(current_user_id)  
    
    if not user:
        return jsonify({"msg": "User not found"}), 404  # Not Found
    
    return jsonify(logged_in_as=user.name), 200



# Get all devices
@app.route("/devices", methods=["GET"])
def get_devices():
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

# Device ping route (to update last active timestamp)
@app.route("/device/present", methods=["POST"])
def device_present():
    try:
        data = request.get_json()
        if "device_id" not in data:
            return jsonify({"error": "Missing required field: device_id"}), 400

        device = db_session.query(Device).filter_by(device_id=data["device_id"]).first()

        if not device:
            return jsonify({"message": "Device not found"}), 404

        device.last_active = datetime.datetime.utcnow()
        db_session.commit()

        return jsonify({"message": "Device presence updated", "device_id": device.device_id}), 200
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()
        
@app.route('/receive-video-feed', methods=['POST'])
def receive_video_feed():
    global latest_frame

    if 'frame' not in request.files:
        return "No frame received", 400

    # Read the uploaded frame (JPEG format)
    file = request.files['frame'].read()
    np_img = np.frombuffer(file, np.uint8)
    frame = cv2.imdecode(np_img, cv2.IMREAD_COLOR)

    with frame_lock:
        latest_frame = frame  # Update the latest frame

    return "Frame received", 200


@app.route('/video-feed')
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route("/device/set-registered/<device_id>", methods=["PUT"])
def set_device_registered(device_id):
    try:
        device = db_session.query(Device).filter_by(device_id=device_id).first()

        if not device:
            return jsonify({"message": "Device not found"}), 404

        # Assuming the device IP is stored in the database or can be derived
        device_ip = f"192.168.1.{device.id}"  # Example; Replace with actual method to get device IP

        # Create a new device connection
        device_conn = DeviceConnection(device_id, device_ip)
        if device_conn.connect():
            device_connections[device_id] = device_conn
        else:
            return jsonify({"error": "Failed to connect to device"}), 500

        device.is_registered = True
        db_session.commit()

        return jsonify({"message": "Device successfully registered and connected", "device_id": device.device_id}), 200
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

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
