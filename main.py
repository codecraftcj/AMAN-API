from flask import Flask, request, jsonify
from repository.database import init_db, db_session
from model.models import User, WaterParameters, JobQueue
import os
import datetime
from datetime import timedelta
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_cors import CORS
from flask import Flask, jsonify


init_db()

app = Flask(__name__)
CORS(app)
# Configure application with a secret key and JWT settings
app.config['JWT_SECRET_KEY'] = 'your-secure-secret-key'  # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)  # Token validity

# Initialize JWTManager
jwt = JWTManager(app)

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
        data = db_session.query(WaterParameters).all()
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

@app.route('/set_water_parameters', methods=['POST'])
def set_water_parameters():
    try:
        data = request.get_json()
        required_fields = ['temperature', 'turbidity', 'ph_level', 'hydrogen_sulfide_level']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        new_parameters = WaterParameters(
            temperature=data['temperature'],
            turbidity=data['turbidity'],
            ph_level=data['ph_level'],
            hydrogen_sulfide_level=data['hydrogen_sulfide_level']
        )
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
            "created_date": latest_param.created_date.strftime('%Y-%m-%d %H:%M:%S')
        }

        return jsonify(serialized_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# CRUD routes for JobQueue

@app.route("/add-job", methods=["POST"])
def add_job():
    try:
        data = request.get_json()
        if "job_name" not in data:
            return jsonify({'error': 'Missing required field: job_name'}), 400

        new_job = JobQueue(job_name=data['job_name'])
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

# @TODO: connect to GUI 
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
