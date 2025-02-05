import cv2
import requests
import threading

URL = "http://localhost:8080/receive-video-feed"

cap = cv2.VideoCapture(0)  # Use webcam

# Create a requests session for connection persistence
session = requests.Session()

def send_frame(frame):
    """ Send the frame asynchronously using a separate thread """
    _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 60])  # Reduce JPEG quality
    files = {'frame': buffer.tobytes()}
    
    # Use threading to avoid blocking frame capture
    thread = threading.Thread(target=session.post, args=(URL,), kwargs={"files": files})
    thread.start()

while True:
    ret, frame = cap.read()
    if not ret:
        break

    # Resize frame for speed optimization (optional)
    frame = cv2.resize(frame, (640, 480))

    # Send frame asynchronously
    send_frame(frame)

cap.release()
