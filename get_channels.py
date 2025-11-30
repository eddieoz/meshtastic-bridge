import meshtastic.serial_interface
from meshtastic import mesh_pb2

try:
    interface = meshtastic.serial_interface.SerialInterface()
    print("Connected to radio.")
    
    if interface.nodes:
        print(f"My Node ID: {interface.myInfo.my_node_num}")
        
    print("\nChannels:")
    for channel in interface.localNode.channels:
        print(f"Channel Object: {channel}")
        # Try accessing fields safely if possible, or just rely on the print above
        try:
            name = channel.settings.name
            index = channel.index
            role = channel.role
            print(f"Index: {index}, Name: '{name}', Role: {role}")
        except Exception as e:
            print(f"Error accessing fields: {e}")
            
    interface.close()
except Exception as e:
    print(f"Error: {e}")
