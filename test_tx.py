import meshtastic.serial_interface
from meshtastic import mesh_pb2
import time

try:
    interface = meshtastic.serial_interface.SerialInterface()
    print("Connected to radio.")
    
    print("Sending test message to ^all...")
    interface.sendText("Bridge TX Test", destinationId="^all")
    print("Test message sent.")
    
    interface.close()
except Exception as e:
    print(f"Error: {e}")
