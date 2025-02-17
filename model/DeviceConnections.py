import requests
import threading
import time

class DeviceConnection:
    def __init__(self, device_id, device_ip):
        self.device_id = device_id
        self.device_ip = device_ip
        self.connected = False
        self.keep_alive_thread = threading.Thread(target=self.keep_alive, daemon=True)
    
    def connect(self):
        """Attempt to establish a connection with the device."""
        try:
            response = requests.get(f"http://{self.device_ip}/ping", timeout=5)
            if response.status_code == 200:
                self.connected = True
                print(f"Device {self.device_id} connected successfully.")
                self.keep_alive_thread.start()
                return True
        except requests.RequestException:
            print(f"Failed to connect to device {self.device_id}")
        return False
    
    def send_data(self, data):
        """Send data to the device."""
        if not self.connected:
            print(f"Device {self.device_id} is not connected.")
            return False
        
        try:
            response = requests.post(f"http://{self.device_ip}/data", json=data, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            print(f"Failed to send data to device {self.device_id}")
            return False
    
    def keep_alive(self):
        """Ping the device to keep the connection alive."""
        while self.connected:
            try:
                response = requests.get(f"http://{self.device_ip}/ping", timeout=5)
                if response.status_code != 200:
                    self.connected = False
                    print(f"Device {self.device_id} lost connection.")
                    break
            except requests.RequestException:
                self.connected = False
                print(f"Device {self.device_id} lost connection.")
                break
            time.sleep(30)  # Ping every 30 seconds
