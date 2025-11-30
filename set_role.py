import meshtastic.serial_interface
from meshtastic import mesh_pb2

try:
    interface = meshtastic.serial_interface.SerialInterface()
    print("Connected to radio.")
    
    print(f"Current Role: {interface.localNode.localConfig.device.role}")
    
    # Set Role to REPEATER
    # REPEATER = 3 (based on protobuf definition usually, let's check or use enum)
    # mesh_pb2.Config.DeviceConfig.Role.REPEATER
    
    interface.localNode.localConfig.device.role = mesh_pb2.Config.DeviceConfig.Role.REPEATER
    interface.writeConfig("device")
    
    print("Role set to REPEATER.")
    print("Please restart the radio (or it might reboot automatically).")
    
    interface.close()
except Exception as e:
    print(f"Error: {e}")
