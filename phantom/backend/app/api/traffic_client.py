import os
import tempfile
import socket
import json

IPC_SOCKET_PATH = os.path.join(tempfile.gettempdir(), 'phantom_scapy_bridge.sock')
IPC_HOST = '127.0.0.1'
IPC_PORT = 19999

def get_traffic_snapshot(interface: str = "eth0") -> dict:
    req = json.dumps({"command": "get_snapshot", "interface": interface})

    try:
        if hasattr(socket, 'AF_UNIX'):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(IPC_SOCKET_PATH)
        else:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((IPC_HOST, IPC_PORT))

        client.settimeout(2.0)
        client.sendall(req.encode())
        client.shutdown(socket.SHUT_WR)  # Signal end of send

        # Chunked receive — snapshot can be large with per_ip data
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        client.close()

        data = b''.join(chunks)
        if data:
            return json.loads(data.decode())
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to connect to IPC Traffic Daemon: {str(e)}",
            "interface": interface,
            "per_ip": [],
            "packets": []
        }

    return {"status": "empty", "per_ip": []}

