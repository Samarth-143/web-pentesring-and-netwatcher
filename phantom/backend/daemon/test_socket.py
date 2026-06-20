import socket
import os
import tempfile

IPC_SOCKET_PATH = os.path.join(tempfile.gettempdir(), 'phantom_scapy_bridge.sock')

try:
    if os.path.exists(IPC_SOCKET_PATH):
        os.remove(IPC_SOCKET_PATH)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(IPC_SOCKET_PATH)
    print("Bind successful")
    os.chmod(IPC_SOCKET_PATH, 0o600)
    print("Chmod successful")
except Exception as e:
    print(f"Error: {e}")
