from flask import Flask, request, jsonify, Response, render_template, make_response,stream_with_context, send_file
from repository.database import init_db, db_session
from model.models import User, WaterParameter, JobQueue, Device, Notification,UserNotification,AvailableDevice
import os
import datetime
from datetime import timedelta
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,unset_jwt_cookies
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
import json
from ultralytics import YOLO
from io import BytesIO

def create_app():
    # Flask App Configuration
    app = Flask(__name__)
    CORS(app,supports_credentials=True)
    TESTING = False # get from config
    print(f"IS TESTING? {TESTING}" )
    app.config['JWT_SECRET_KEY'] = 'your-secure-secret-key'  # Change this!
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)  # Token validity

    # Initialize Database
    init_db()

    # Cleanup sessions after requests
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db_session.remove()


    # Initialize JWTManager
    jwt = JWTManager(app)
    available_devices = {}


    def get_unread_notifications(user_id):
        """Fetch all unread notifications for a given user."""
        return db_session.query(Notification).join(UserNotification).filter(
            UserNotification.user_id == user_id,
            UserNotification.seen == False
        ).all()

    def mark_notification_as_seen(user_id, notification_id):
        """Mark a specific notification as read for a user."""
        user_notification = db_session.query(UserNotification).filter_by(
            user_id=user_id,
            notification_id=notification_id
        ).first()

        if user_notification and not user_notification.seen:
            user_notification.seen = True
            user_notification.seen_at = datetime.datetime.utcnow()
            db_session.commit()
            print(f"✅ Notification {notification_id} marked as read by User {user_id}")
            
    def send_notification(user_id, message, details):
        """Create a new notification and associate it with a user."""
        new_notification = Notification(
            message=message,
            details=details,
            created_at=datetime.datetime.utcnow(),
            system_wide=False
        )
        db_session.add(new_notification)
        db_session.commit()

        user_notification = UserNotification(
            user_id=user_id,
            notification_id=new_notification.id,
            seen=False
        )
        db_session.add(user_notification)
        db_session.commit()
        print(f"📩 Notification sent to User {user_id}")

    # Load YOLO model (optimized for Raspberry Pi)
    MODEL_PATH = "models/yolov8l.pt"
    model = YOLO(MODEL_PATH)

    def capture_single_frame(camera_url):
        """Fetch a single frame from the MJPEG stream of the device camera."""
        try:
            # Request the stream and read a single frame
            response = requests.get(camera_url, stream=True, timeout=5)

            if response.status_code != 200:
                print(f"Failed to fetch camera stream, status code: {response.status_code}")
                return None

            # Read the stream to extract a frame
            bytes_data = bytes()
            for chunk in response.iter_content(chunk_size=1024):
                bytes_data += chunk
                a = bytes_data.find(b'\xff\xd8')  # JPEG start
                b = bytes_data.find(b'\xff\xd9')  # JPEG end
                if a != -1 and b != -1:
                    jpg = bytes_data[a:b+2]
                    bytes_data = bytes_data[b+2:]
                    frame = cv2.imdecode(np.frombuffer(jpg, dtype=np.uint8), cv2.IMREAD_COLOR)
                    return frame  # Return the extracted frame

            print("No valid frame found in stream.")
            return None
        except requests.RequestException as e:
            print(f"Error connecting to camera: {e}")
            return None


    def process_frame(frame):
        """Detect lesions and disfigurations on fish using YOLOv8l."""
        results = model(frame, verbose=False)  # Run YOLO inference

        for result in results:
            for box in result.boxes:
                x1, y1, x2, y2 = map(int, box.xyxy[0])  # Bounding box coordinates
                confidence = box.conf[0].item()  # Confidence score
                class_id = int(box.cls[0])  # Class index
                label = f"{model.names[class_id]} {confidence:.2f}"  # Class label

                # Define bounding box color: Red for lesions, Green for healthy fish
                color = (0, 0, 255) if class_id == 1 else (0, 255, 0)  # Red for lesion, Green for healthy

                # Draw bounding box
                cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
                
                # Draw label text
                cv2.putText(frame, label, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)

        return frame

    def monitor_water_parameters():
        """Continuously monitors water quality trends over the last 5 minutes and sends alerts if necessary."""
        THRESHOLDS = {
            "temperature": {"min": 10, "max": 35},
            "ph_level": {"min": 4.5, "max": 9.5},
            "turbidity": {"max": 100},  # NTU
            "hydrogen_sulfide_level": {"max": 0.01},  # mg/L
            "salinity": {"min": 0.5, "max": 35, "fluctuation_threshold": 5}  # ppt
        }

        while True:
            try:
                # Fetch the last 60 readings (5 minutes of data)
                latest_params = db_session.query(WaterParameter).order_by(WaterParameter.created_date.desc()).limit(60).all()

                if len(latest_params) < 60:
                    print("⚠️ Not enough water quality data to assess trends. Skipping check.")
                    time.sleep(30)
                    continue

                alert_message = []

                # Track persistent threshold violations
                violations = {
                    "temperature": sum(
                        1 for p in latest_params if p.temperature < THRESHOLDS["temperature"]["min"] or p.temperature > THRESHOLDS["temperature"]["max"]
                    ),
                    "ph_level": sum(
                        1 for p in latest_params if p.ph_level < THRESHOLDS["ph_level"]["min"] or p.ph_level > THRESHOLDS["ph_level"]["max"]
                    ),
                    "turbidity": sum(
                        1 for p in latest_params if p.turbidity > THRESHOLDS["turbidity"]["max"]
                    ),
                    "hydrogen_sulfide_level": sum(
                        1 for p in latest_params if p.hydrogen_sulfide_level > THRESHOLDS["hydrogen_sulfide_level"]["max"]
                    )
                }

                # If more than 30 readings (50%) exceed limits, trigger an alert
                for key, count in violations.items():
                    if count >= 30:
                        alert_message.append(f"{key.replace('_', ' ').title()} persistently unsafe for the last 5 minutes.")

                if alert_message:
                    notification_text = " ".join(alert_message)
                    print(f"📢 ALERT: {notification_text}")

                    # **Send notification to all users**
                    all_users = db_session.query(User).all()

                    # Create a system-wide notification
                    new_notification = Notification(
                        message="⚠️ Persistent water quality issue detected!",
                        details=notification_text,
                        created_at=datetime.datetime.utcnow(),
                        system_wide=True
                    )
                    db_session.add(new_notification)
                    db_session.commit()

                    # Associate notification with all users as unread
                    user_notifications = [
                        UserNotification(user_id=user.id, notification_id=new_notification.id, seen=False)
                        for user in all_users
                    ]
                    db_session.bulk_save_objects(user_notifications)
                    db_session.commit()

                    print("📩 System-wide notification sent to all users!")

            except Exception as e:
                print(f"❌ Error in monitoring task: {e}")

            time.sleep(30)  # Check every 30 seconds 
    # ================================#
    #       DEVICE MONITORING         #
    # ================================#
    # Constants
    PING_INTERVAL = 30  # Time between pings in seconds
    DISCONNECTION_TIME_MINUTES = 1  # Time in minutes before a device is considered offline
    DISCONNECTION_THRESHOLD = (DISCONNECTION_TIME_MINUTES * 60) // PING_INTERVAL  # Calculate threshold

    def ping_devices():
        """Continuously pings all registered devices to check their status and alerts on disconnections."""
        disconnection_counters = {}  # Store failed attempts per device

        while True:
            try:
                devices = db_session.query(Device).all()
                for device in devices:
                    
                    if(TESTING):
                        device.hostname = "127.0.0.1"
                    else:
                        if("local" not in device.hostname):
                            device.hostname = f"{device.hostname}.local"
                    if not device.hostname:
                        continue  # Skip devices without a hostname
                    
                    device_url = f"http://{device.hostname}:8082/register"  # Ping the emulator
                    try:
                        response = requests.post(device_url)
                        if response.status_code == 200:
                            # Reset the disconnection counter upon success
                            disconnection_counters[device.device_id] = 0
                            
                            # Update device status in the database
                            if device.status != "online":
                                print(f"✅ Device {device.device_id} is back online at {device.hostname}")
                                
                                # Send recovery notification
                                new_notification = Notification(
                                    message="✅ Device Reconnected",
                                    details=f"Device {device.device_id} is back online.",
                                    created_at=datetime.datetime.utcnow(),
                                    system_wide=True
                                )
                                db_session.add(new_notification)

                            device.status = "online"
                        else:
                            print(f"⚠️ Device {device.device_id} did not respond. Status: {response.status_code}")
                            handle_device_disconnection(device, disconnection_counters)
                    
                    except requests.RequestException as e:
                        print(f"❌ Error pinging device {device.device_id}: {e}")
                        handle_device_disconnection(device, disconnection_counters)

                db_session.commit()  # Save changes to device statuses
            
            except Exception as e:
                print(f"❌ Error in device monitoring thread: {e}")

            time.sleep(PING_INTERVAL)  # Ping devices every defined interval

    def handle_device_disconnection(device, disconnection_counters):
        """Handles a device disconnection by updating status and sending an alert."""
        device_id = device.device_id
        
        # Initialize counter if not present
        if device_id not in disconnection_counters:
            disconnection_counters[device_id] = 0
        
        # Increment the failed attempt counter
        disconnection_counters[device_id] += 1
        
        # Only mark as offline if the threshold is reached
        if disconnection_counters[device_id] >= DISCONNECTION_THRESHOLD:
            if device.status != "offline":  # Only notify if the status just changed
                print(f"🚨 ALERT: Device {device.device_id} is offline!")
                existing_device = db_session.query(Device).filter_by(device_id=device_id).first()
                if(TESTING):
                    device.hostname = "127.0.0.1"
                else:
                    if("local" not in device.hostname):
                        device.hostname = f"{device.hostname}.local"
                db_session.delete(existing_device)
                # Send disconnection notification
                new_notification = Notification(
                    message="🚨 Device Disconnected",
                    details=f"Device {device.device_id} at {device.hostname} is unreachable.",
                    created_at=datetime.datetime.utcnow(),
                    system_wide=True
                )
                db_session.add(new_notification)
            device.status = "offline"


    # Start the background thread
    device_ping_thread = threading.Thread(target=ping_devices, daemon=True)
    device_ping_thread.start()

    monitor_thread = threading.Thread(target=monitor_water_parameters, daemon=True)
    monitor_thread.start()
    # ================================#
    #           GENERAL ROUTES        #
    # ================================#
    @app.route("/")
    def hello_world():
        return jsonify({"message": "You have reached the Terminal Web App!"})


    # ================================#
    #           USER MODEL            #
    # ================================#

    @app.route("/register-user", methods=["POST"])
    def register_user():
        data = request.get_json()

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        role = data.get("role", "user")

        if not all([username, email, password]):
            return jsonify({"msg": "Missing required fields"}), 400
        if db_session.query(User).query.filter_by(email=email).first():
            return jsonify({"msg": "User already exists"}), 409
        new_user = User(username=username, email=email, password=password, role=role)
        db_session.add(new_user)
        db_session.commit()
        return jsonify({"msg": "User registered successfully"}), 201
    


    @app.route("/delete-user/<int:user_id>", methods=["DELETE"])
    @jwt_required()
    def delete_user(user_id):
        user = db_session.query(User).filter_by(id=user_id).first()

        if not user:
            return jsonify({"msg": "User not found"}), 404

        db_session.delete(user)
        db_session.commit()
        return jsonify({"msg": "User deleted successfully"}), 200

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


    @app.route('/login', methods=['POST'])
    def login():
        """User login"""
        data = request.get_json()

        email = data.get('email')
        password = data.get('password')

        if not all([email, password]):
            return jsonify({"msg": "Missing parameters"}), 400  # Bad Request

        user = db_session.query(User).filter_by(email=email).first()
        print("DEBUG USER")
        print(email)
        print(password)
        if not user or not user.check_password(password):
            return jsonify({"msg": "Bad email or password"}), 401  # Unauthorized

        token = create_access_token(identity=str(user.id))

        response = jsonify({"token": token, "role": user.role})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response, 200  # ✅ Ensure 'role' is returned
        
        # ✅ Ensure the role is included in the response
        return jsonify(token=token, role=user.role), 200  # ✅ 'role' must be returned


    @app.route('/get-users', methods=['GET'])
    @jwt_required()
    def get_users():
        """Retrieve all users (Admin only)"""
        current_user_id = get_jwt_identity()
        print("GET USERS")
        print(current_user_id)
        current_user = db_session.query(User).get(current_user_id)  
        if not current_user or current_user.role != "admin":
            return jsonify({"msg": "Unauthorized"}), 403
        
        users = db_session.query(User).all()
        return jsonify([{
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at.isoformat()
        } for user in users]), 200
    
    @app.route('/users/<int:user_id>', methods=['GET'])
    @jwt_required()
    def get_user(user_id):
        """Retrieve a single user by ID (Admin only)"""
        current_user_id = get_jwt_identity()
        current_user = db_session.query(User).get(current_user_id)
        if not current_user or current_user.role != "admin":
            return jsonify({"msg": "Unauthorized"}), 403
        
        user = db_session.query(User).get(user_id)
        if not user:
            return jsonify({"msg": "User not found"}), 404
        
        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at.isoformat()
        }), 200

    @app.route('/users', methods=['POST'])
    @jwt_required()
    def create_user():
        """Create a new user (Admin only)"""
        current_user_id = get_jwt_identity()
        current_user = db_session.query(User).get(current_user_id)
        if not current_user or current_user.role != "admin":
            return jsonify({"msg": "Unauthorized"}), 403
        
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'user')
        
        if not all([username, email, password]):
            return jsonify({"msg": "Missing parameters"}), 400
        
        if db_session.query(User).filter_by(email=email).first():
            return jsonify({"msg": "User already exists"}), 409
        
        new_user = User(username=username, email=email, password=password, role=role)
        db_session.add(new_user)
        db_session.commit()
        
        return jsonify({"msg": "User created successfully", "id": new_user.id}), 201



    # ================================#
    #          AUTHENTICATION         #
    # ================================#


    @app.route('/auth/me', methods=['GET'])
    @jwt_required()
    def fetch_user():
        """Fetch authenticated user"""
        current_user_id = get_jwt_identity()
        user = db_session.query(User).get(current_user_id)
        if not user:
            return jsonify({"msg": "User not found"}), 404
        
        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }), 200

    @app.route('/auth/logout', methods=['POST'])
    @jwt_required()
    def logout_user():
        """User logout"""
        response = jsonify({"msg": "Logout successful"})
        unset_jwt_cookies(response)
        return response, 200

    # ================================#
    #     WATER PARAMETERS MODEL      #
    # ================================#

    @app.route("/get-water-parameters", methods=["POST"])
    def get_water_parameters():
        """Retrieve water parameters"""
        try:
            data = request.get_json()
            limit = data.get("limit", 10)  
            data = db_session.query(WaterParameter).order_by(WaterParameter.created_date.desc()).limit(limit).all()

            serialized_data = [
                {
                    "id": param.id,
                    "temperature": param.temperature,
                    "turbidity": param.turbidity,
                    "ph_level": param.ph_level,
                    "hydrogen_sulfide_level": param.hydrogen_sulfide_level,
                    "created_date": param.created_date.strftime('%Y-%m-%d %H:%M:%S'),
                    "device_id": param.device_id
                    
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

    @app.route("/water-parameters/latest", methods=["GET"])
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
            if(TESTING):
                    serialized_devices = [
                        {
                            "device_id": device.device_id,
                            "status":device.status,
                            "hostname": f"127.0.0.1",
                        }
                        for device in devices
                    ]
            else:
                serialized_devices = []
                for device in devices:
                    if("local" not in device.hostname):
                        serialized_devices.append(
                            {
                        "device_id": device.device_id,
                        "status":device.status,
                        "hostname": f"{device.hostname}.local",
                            }
                        )
                    else: 
                        serialized_devices.append(
                            {
                        "device_id": device.device_id,
                        "status":device.status,
                        "hostname": f"{device.hostname}",
                            }
                        )
            
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
        """Receives device announcements and stores them as available devices, 
        but only if the device is not already registered in the database."""
        try:
            data = request.get_json()
            device_id = data.get("device_id")
            hostname = data.get("device_hostname")

            if not device_id or not hostname:
                return jsonify({"error": "Missing device ID or IP"}), 400

            # Check if the device already exists in the database
            existing_device = db_session.query(Device).filter_by(device_id=device_id).first()

            # Check if the device is already in available devices and remove it
            available_device = db_session.query(AvailableDevice).filter_by(device_id=device_id).first()
            if available_device and existing_device:
                db_session.delete(available_device)
            else:
                # If the device is not in the database, add it to available devices
                new_available_device = AvailableDevice(device_id=device_id, hostname=hostname)
                db_session.add(new_available_device)
            if existing_device:
                return jsonify({"message": "Device is already registered in the system"}), 200
            
            
        
            db_session.commit()
            return jsonify({"message": "Device registered as available", "device_id": device_id}), 201
        except Exception as e:
            print(f"ERROR AT {str(e)}")
            if ("Duplicate entry" in str(e)):
                return jsonify({"error": "DUPLICATE FOUND"}), 200
            return jsonify({"error": str(e)}), 500



    @app.route('/get_available_devices', methods=['GET'])
    def get_available_devices():
        """Returns a list of available devices that are not already in the database."""
        try:
            # Get all registered device IDs from the database
            registered_devices = {device.device_id for device in db_session.query(Device.device_id).all()}

            # Remove registered devices from available devices
            available_devices = db_session.query(AvailableDevice).all()
            print(available_devices)
            if(TESTING):
                filtered_devices = {device.device_id: {"hostname": "127.0.0.1"} for device in available_devices if device.device_id not in registered_devices}
            
            else:
                filtered_devices = {device.device_id: {"hostname": device.hostname} for device in available_devices if device.device_id not in registered_devices}
            
            return jsonify(filtered_devices), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500


    @app.route('/confirm_device', methods=['POST'])
    def confirm_device():
        """Confirms a device and adds it to the database."""
        try:
            data = request.get_json()
            device_id = data.get("device_id")

            # Check if the device exists in available devices and remove it
            available_device = db_session.query(AvailableDevice).filter_by(device_id=device_id).first()
            if not available_device:
                return jsonify({"error": "Device not found"}), 404
            
            db_session.delete(available_device)
            db_session.commit()
            if(TESTING):
                available_device.hostname = "127.0.0.1"
                # Send request to confirm the device
            else:
                if("local" not in available_device.hostname):
                    available_device.hostname = f"{available_device.hostname}.local"
            # Send request to confirm the device
            response = requests.post(f"http://{available_device.hostname}:8082/register")
            if response.status_code == 200:
                new_device = Device(device_id=device_id, hostname=available_device.hostname)
                db_session.add(new_device)
                db_session.commit()
                return jsonify({"message": f"Device {device_id} confirmed and added"}), 200
            else:
                return jsonify({"error": f"Error confirming device: {response.text}"}), 500
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

            if(TESTING):
                device.hostname = "127.0.0.1"
            else:
                if("local" not in device.hostname):
                    device.hostname = f"{device.hostname}.local"
            response = requests.post(f"http://{device.hostname}:8082/unregister")
            if response.status_code == 200:
                # Remove the device from the database
                available_device = AvailableDevice(device_id=device.device_id, hostname=device.hostname)
                db_session.add(available_device)
                db_session.delete(device)
                db_session.commit()
                return jsonify({"message": f"Device {device_id} has been disconnected and removed"}), 200
            else:
                return jsonify({"error": f"Error removing device: {response.text}"}), 500
        except Exception as e:
            db_session.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            db_session.close()
            
    @app.route("/device/<string:device_id>/jobs", methods=["GET"])
    def get_device_jobs(device_id):
        """Retrieve jobs associated with a specific device with pagination."""
        try:
            # Parse optional query params
            nth = request.args.get("nth", type=int)  # Get a single Nth row
            start = request.args.get("start", type=int, default=0)  # Pagination start index
            limit = request.args.get("limit", type=int, default=10)  # Number of rows to fetch

            # Fetch device from the database
            device = db_session.query(Device).filter_by(device_id=device_id).first()
            if not device:
                return jsonify({"message": "Device not found in the database"}), 404

            # Apply .local domain correction if needed
            if TESTING:
                device.hostname = "127.0.0.1"
            elif "local" not in device.hostname:
                device.hostname = f"{device.hostname}.local"

            # Fetch jobs from the device API
            response = requests.get(f"http://{device.hostname}:8082/get-jobs")
            jobs = json.loads(response.content)
            jobs.reverse()
            if not jobs:
                return jsonify({"message": "No jobs found for this device"}), 404

            # Handle nth row retrieval
            if nth is not None:
                if nth < 0 or nth >= len(jobs):
                    return jsonify({"message": "Nth row out of range"}), 400
                return jsonify(jobs[nth]), 200

            # Handle pagination
            paginated_jobs = jobs[start : start + limit]
            return jsonify(paginated_jobs), 200

        except Exception as e:
            print(e)
            return jsonify({"error": str(e)}), 500


    @app.route("/device/<string:device_id>/jobs", methods=["POST"])
    def create_device_job(device_id):
        """Send a job command to a specific device."""
        try:
            data = request.json

            if not data or "command" not in data:
                return jsonify({"error": "Invalid request, 'command' is required"}), 400

            command = data["command"].lower()

            # Validate the command
            valid_commands = {"small open", "half open", "full open"}
            if command not in valid_commands:
                return jsonify({"error": "Invalid command"}), 400

            # Fetch device information
            device = db_session.query(Device).filter_by(device_id=device_id).first()
            if(TESTING):
                device.hostname = "127.0.0.1"
            else:
                if("local" not in device.hostname):
                    device.hostname = f"{device.hostname}.local"
            if not device:
                return jsonify({"message": "Device not found in the database"}), 404

            # Send the command to the emulator
            response = requests.post(
                f"http://{device.hostname}:8082/send_command",
                json={"job_name": command}
            )

            if response.status_code != 200:
                return jsonify({"error": "Failed to send command to the device"}), response.status_code

            return jsonify({"message": "Command sent successfully", "response": response.json()}), 200

        except Exception as e:
            print(e)
            return jsonify({"error": str(e)}), 500

    @app.route("/device/<string:device_id>/camera", methods=["GET"])
    def get_device_camera_url(device_id):
        """Proxy the camera feed from the device without lag."""
        try:
            # Fetch device from database
            device = db_session.query(Device).filter_by(device_id=device_id).first()
            if(TESTING):
                device.hostname = "127.0.0.1"
            else:
                if("local" not in device.hostname):
                    device.hostname = f"{device.hostname}.local"
            if not device:
                return jsonify({"message": "Device not found in the database"}), 404

            camera_url = f"http://{device.hostname}:8082/camera"
            print(f"Proxying camera stream from: {camera_url}")

            # Stream camera feed directly as a proxy
            response = requests.get(camera_url, stream=True, timeout=5)

            if response.status_code != 200:
                return jsonify({"error": f"Failed to fetch camera stream, status code: {response.status_code}"}), response.status_code

            return Response(
                stream_with_context(response.iter_content(chunk_size=4096)), 
                content_type=response.headers.get("Content-Type", "multipart/x-mixed-replace; boundary=frame")
            )
            
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            return jsonify({"error": "Failed to connect to camera"}), 500
        except Exception as e:
            print(f"Server error: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/device/model-inference", methods=["POST"])
    def capture_and_process():
        """Process an uploaded image using YOLO and return the processed image."""
        try:
            if "image" not in request.files:
                return jsonify({"error": "No image file provided"}), 400

            # Read the uploaded image
            file = request.files["image"].read()
            np_arr = np.frombuffer(file, np.uint8)
            frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

            if frame is None:
                return jsonify({"error": "Failed to process image"}), 500

            # Process the frame with YOLO
            processed_frame = process_frame(frame)

            # Convert to JPEG format
            _, buffer = cv2.imencode('.jpg', processed_frame)
            image_io = BytesIO(buffer)

            # Send the processed image as response
            return send_file(image_io, mimetype='image/jpeg')

        except Exception as e:
            print(f"Error processing frame: {e}")
            return jsonify({"error": str(e)}), 500

    # ================================#
    #       NOTIFICATIONS API         #
    # ================================#

    @app.route("/notifications/unread", methods=["GET"])
    @jwt_required()
    def get_unread_notifications_api():
        """Retrieve unread notifications for the authenticated user with pagination."""
        user_id = get_jwt_identity()
        
        start = request.args.get("start", default=0, type=int)  # Start index for pagination
        limit = request.args.get("limit", default=10, type=int)  # Number of records per page

        unread_notifications = (
            db_session.query(Notification)
            .join(UserNotification)
            .filter(UserNotification.user_id == user_id, UserNotification.seen == False)
            .order_by(Notification.created_at.desc())
            .offset(start)
            .limit(limit)
            .all()
        )

        total_count = (
            db_session.query(Notification)
            .join(UserNotification)
            .filter(UserNotification.user_id == user_id, UserNotification.seen == False)
            .count()
        )

        return jsonify({
            "notifications": [
                {
                    "id": notif.id,
                    "message": notif.message,
                    "details": notif.details,
                    "created_at": notif.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    "system_wide": notif.system_wide
                }
                for notif in unread_notifications
            ],
            "total_count": total_count
        }), 200



    @app.route("/notifications/mark-seen", methods=["POST"])
    @jwt_required()
    def mark_notification_as_seen_api():
        """Mark a specific notification as read."""
        user_id = get_jwt_identity()
        data = request.get_json()
        notification_id = data.get("notification_id")

        if not notification_id:
            return jsonify({"error": "Missing notification_id"}), 400

        user_notification = db_session.query(UserNotification).filter_by(
            user_id=user_id,
            notification_id=notification_id
        ).first()

        if not user_notification:
            return jsonify({"error": "Notification not found"}), 404

        if not user_notification.seen:
            user_notification.seen = True
            user_notification.seen_at = datetime.datetime.utcnow()
            db_session.commit()
            return jsonify({"message": f"Notification {notification_id} marked as read"}), 200

        return jsonify({"message": "Notification already marked as read"}), 200


    @app.route("/notifications/send", methods=["POST"])
    @jwt_required()
    def send_notification_api():
        """Send a new notification to a user."""
        data = request.get_json()
        user_id = data.get("user_id")
        message = data.get("message")
        details = data.get("details")

        if not all([user_id, message, details]):
            return jsonify({"error": "Missing parameters"}), 400

        new_notification = Notification(
            message=message,
            details=details,
            created_at=datetime.datetime.utcnow(),
            system_wide=False
        )
        db_session.add(new_notification)
        db_session.commit()

        user_notification = UserNotification(
            user_id=user_id,
            notification_id=new_notification.id,
            seen=False
        )
        db_session.add(user_notification)
        db_session.commit()

        return jsonify({"message": f"Notification sent to user {user_id}"}), 201
    return app
# Gunicorn WSGI Entry Point
app = create_app()

# Start Flask App
if __name__ == "__main__":
    # app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
    
    app.run(host="0.0.0.0", port=8080, debug=False)
   
