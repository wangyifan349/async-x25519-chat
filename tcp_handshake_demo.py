import socket
import threading
# 服务器套接字
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_sock.bind(("127.0.0.1", 50000))
server_sock.listen(1)
print("Server: listening on 127.0.0.1:50000")

def handle_client(conn, addr):
    print("Server: accepted connection from", addr)
    data = conn.recv(4096)
    print("Server: recv returned", len(data), "bytes")
    if data:
        print("Server: received payload:", data.decode())
        response = b"ACK: " + data
        print("Server: sending response:", response.decode())
        conn.sendall(response)
    print("Server: closing connection")
    conn.close()

def server_thread():
    print("Server thread: waiting for accept")
    conn, addr = server_sock.accept()
    print("Server thread: accept returned")
    handle_client(conn, addr)
    print("Server thread: closing listening socket")
    server_sock.close()
    print("Server thread: stopped")

t = threading.Thread(target=server_thread, daemon=True)
print("Main: starting server thread")
t.start()

# 客户端套接字
client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Client: connecting to server 127.0.0.1:50000")
client_sock.connect(("127.0.0.1", 50000))
print("Client: connected")

message = b"Hello from client"
print("Client: sending message:", message.decode())
client_sock.sendall(message)
resp = client_sock.recv(4096)
print("Client: received", len(resp), "bytes")
print("Client: response payload:", resp.decode())
print("Client: closing socket")
client_sock.close()

print("Main: waiting for server thread to finish")
t.join()
print("Main: done")
