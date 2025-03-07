import os
import cv2
import numpy as np
from flask import Flask, Response, request, jsonify, send_file
from ultralytics import YOLO

app = Flask(__name__)

# Function to check if /dev/video0 is available
def is_video_device_available(device_path="/dev/video0"):
    return os.path.exists(device_path)

# Function to list available cameras
def list_available_cameras(max_test=5):
    available_cameras = []
    for index in range(max_test):
        cap = cv2.VideoCapture(index)
        if cap.isOpened():
            available_cameras.append(index)
            cap.release()
    return available_cameras

# Check if /dev/video0 is available, otherwise list available cameras
if is_video_device_available("/dev/video0"):
    camera_index = 0
    print("Using /dev/video0 as the default camera.")
else:
    cameras = list_available_cameras()
    if not cameras:
        print("No cameras found. Please check your connections.")
        exit()
    camera_index = cameras[0]  # Use the first available camera
    print(f"/dev/video0 not found. Using camera {camera_index}")

# Load YOLO model
model_path = "models/best.pt"
if not os.path.exists(model_path):
    print(f"Error: Model file '{model_path}' not found.")
    exit()

print(f"Using {model_path}")
model = YOLO(model_path)  # Load trained YOLO model

# Define class labels
class_names = [
    "Bacterial diseases - Aeromoniasis", "Bacterial gill disease", "Bacterial Red disease",
    "Fungal diseases Saprolegniasis", "Healthy Fish", "Parasitic diseases",
    "Viral diseases White tail disease"
]

# Open the selected camera
cap = cv2.VideoCapture(camera_index)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

if not cap.isOpened():
    print(f"Error: Could not open camera {camera_index}.")
    exit()


def generate_raw_frames():
    """ Continuously capture frames and yield them as a raw video stream """
    while True:
        success, frame = cap.read()
        if not success:
            print("Error: Failed to capture frame.")
            break

        # Encode frame as JPEG
        _, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()

        # Yield as MJPEG stream
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')


@app.route('/')
def index():
    """ Route to test if the server is running """
    return "Flask Video Streaming & Image Processing API is running!"


@app.route('/video_feed')
def video_feed():
    """ Video streaming route (Raw camera feed) """
    return Response(generate_raw_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/detect', methods=['POST'])
def detect():
    """ Process an uploaded image and return the detected image """
    if 'image' not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Read image from request
    image_np = np.frombuffer(file.read(), np.uint8)
    img = cv2.imdecode(image_np, cv2.IMREAD_COLOR)

    if img is None:
        return jsonify({"error": "Invalid image format"}), 400

    # Run YOLO detection
    results = model(img)

    # Process detections
    for result in results:
        if result.boxes is not None and len(result.boxes.xyxy) > 0:
            for box in result.boxes.data:
                x1, y1, x2, y2, conf, cls = map(float, box[:6])

                # Convert to integer for OpenCV drawing
                x1, y1, x2, y2 = int(x1), int(y1), int(x2), int(y2)
                conf = round(conf, 2)
                cls = int(cls)

                # Get class label
                class_label = class_names[cls] if cls < len(class_names) else f"Unknown ({cls})"

                # Draw bounding box
                cv2.rectangle(img, (x1, y1), (x2, y2), (0, 255, 0), 2)

                # Display label
                label = f"{class_label}: {conf:.2f}"
                text_size = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 2)[0]
                text_x = x1
                text_y = max(y1 - 10, 20)  # Ensure text is within frame

                # Draw label background
                cv2.rectangle(img, (text_x - 2, text_y - text_size[1] - 2),
                              (text_x + text_size[0] + 2, text_y + 2), (0, 255, 0), -1)
                
                # Draw text
                cv2.putText(img, label, (text_x, text_y),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 2)

    # Save processed image
    output_path = "static/detected_image.jpg"
    cv2.imwrite(output_path, img)

    return send_file(output_path, mimetype='image/jpeg')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8084, debug=False)
