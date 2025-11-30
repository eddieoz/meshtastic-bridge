from meshtastic import mesh_pb2
print("MqttClientProxyMessage fields:")
for field in mesh_pb2.MqttClientProxyMessage.DESCRIPTOR.fields:
    print(f"{field.name}: {field.type}")
