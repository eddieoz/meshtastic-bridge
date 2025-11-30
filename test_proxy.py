import meshtastic.serial_interface
from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2
import time
import base64

def main():
    try:
        interface = meshtastic.serial_interface.SerialInterface()
        print("Connected to radio.")
        
        # 1. Create a MeshPacket (Text Message)
        mesh_packet = mesh_pb2.MeshPacket()
        mesh_packet.to = 4294967295  # Broadcast
        mesh_packet.decoded.payload = b"Proxy Test"
        mesh_packet.decoded.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
        mesh_packet.id = 123456789
        mesh_packet.hop_limit = 3
        
        # 2. Wrap in ServiceEnvelope (standard MQTT format)
        envelope = mqtt_pb2.ServiceEnvelope()
        envelope.packet.CopyFrom(mesh_packet)
        envelope.channel_id = "LongFast"
        envelope.gateway_id = "!12345678"
        
        payload_bytes = envelope.SerializeToString()
        
        # 3. Create MqttClientProxyMessage
        proxy_msg = mesh_pb2.MqttClientProxyMessage()
        proxy_msg.topic = "mc/2/e/MiHome" # Testing Primary Channel
        proxy_msg.data = payload_bytes
        proxy_msg.retained = False
        
        # 4. Wrap in ToRadio
        to_radio = mesh_pb2.ToRadio()
        to_radio.mqttClientProxyMessage.CopyFrom(proxy_msg)
        
        print(f"Sending MqttClientProxyMessage to radio...")
        print(f"Topic: {proxy_msg.topic}")
        print(f"Payload len: {len(proxy_msg.data)}")
        
        interface._sendToRadio(to_radio)
        print("Sent. Check if radio transmits.")
        
        interface.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
