from meshtastic import mesh_pb2
print("Data fields:")
for field in mesh_pb2.Data.DESCRIPTOR.fields:
    print(f"{field.name}: {field.type}")
