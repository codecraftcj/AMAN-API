import cv2
from ultralytics import YOLO
import os

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

model = YOLO(model_path)  # Load trained YOLO model

# Define class labels
class_names = [
    "Bacterial diseases - Aeromoniasis", "Bacterial gill disease", "Bacterial Red disease",
    "Fungal diseases Saprolegniasis", "Healthy Fish", "Parasitic diseases",
    "Viral diseases White tail disease"
]

# Open the selected camera
cap = cv2.VideoCapture(camera_index)

if not cap.isOpened():
    print(f"Error: Could not open camera {camera_index}.")
    exit()

# Set video capture properties
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        print("Failed to grab frame.")
        break

    # Run YOLOv8 detection
    results = model(frame)

    # Process each detection
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
                cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)

                # Display label
                label = f"{class_label}: {conf:.2f}"
                text_size = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 2)[0]
                text_x = x1
                text_y = max(y1 - 10, 20)  # Ensure text is within frame

                # Draw label background
                cv2.rectangle(frame, (text_x - 2, text_y - text_size[1] - 2),
                              (text_x + text_size[0] + 2, text_y + 2), (0, 255, 0), -1)
                
                # Draw text
                cv2.putText(frame, label, (text_x, text_y),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 2)

    # Show webcam feed
    cv2.imshow("YOLOv8 Real-Time Detection", frame)

    # Exit with 'Q'
    if cv2.waitKey(1) & 0xFF == ord("q"):
        break

cap.release()
cv2.destroyAllWindows()
