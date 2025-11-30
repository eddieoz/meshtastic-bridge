try:
    from meshtastic import portnums_pb2
    print("PortNum found in portnums_pb2")
    print(f"TEXT_MESSAGE_APP: {portnums_pb2.PortNum.TEXT_MESSAGE_APP}")
except ImportError:
    print("portnums_pb2 not found")
