"""
secure_chat.py

This script provides a secure peer-to-peer chat and file transfer channel with optional proxy support for clients.
It uses secp256k1 ECDH for session key exchange (hashed via SHA256), then encrypts all traffic (including file data) with ChaCha20-Poly1305 AEAD.
Both peers exchange public keys at session start, derive a shared session key, and use independent threads for sending and receiving. All protocol messages are JSON objects (length-prefixed with 4 bytes) and fall into distinct types: text messages, file transfer (fileinfo, filedata, fileend).
File transfer includes an integrity check via SHA256; the receiver verifies the received file hash. The client can optionally connect through SOCKS5, SOCKS4, or HTTP proxies using the PySocks library.
The script runs as server or client based on command-line arguments, defaulting to server if run without arguments.

"""

import socket
import threading
import json
import os
import struct
import base64
import sys
from hashlib import sha256                            # For session key and file hash integrity
from coincurve import PrivateKey, PublicKey           # For secp256k1 key exchange
from Crypto.Cipher import ChaCha20_Poly1305           # AEAD encryption for all messages

try:
    import socks                                      # For optional proxy support in client
except ImportError:
    socks = None

PORT = 65432                                          # Default TCP port

def generate_ecdh_key_pair():
    # Generate a secp256k1 ECDH private and public key pair.
    private_key = PrivateKey()
    public_key = private_key.public_key
    return private_key, public_key

def perform_ecdh_shared_secret(own_private_key, remote_public_bytes):
    # Derive a shared session key from local private key and peer's public key bytes.
    remote_public_key = PublicKey(remote_public_bytes)
    shared_secret = own_private_key.ecdh(remote_public_key)
    return sha256(shared_secret).digest()

def sha256_file_digest(filename):
    # Return SHA256 hash digest (hex) of the specified file.
    h = sha256()
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def recvn(sock, size):
    # Read exactly 'size' bytes from a socket.
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            return None
        data += part
    return data

def encrypt_and_send(sock, session_key, message_dict):
    # Encrypt and send a message dict over the socket.
    plaintext = json.dumps(message_dict).encode("utf-8")
    nonce = os.urandom(12)                            # 96-bit unique nonce per message
    cipher = ChaCha20_Poly1305.new(key=session_key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    packet = nonce + ciphertext + tag
    sock.sendall(struct.pack(">I", len(packet)) + packet)  # Send 4-byte length + encrypted payload

def recv_and_decrypt(sock, session_key):
    # Receive and decrypt a message from the socket.
    header = recvn(sock, 4)
    if not header:
        return None
    packet_length = struct.unpack(">I", header)[0]
    packet = recvn(sock, packet_length)
    if not packet or len(packet) != packet_length:
        return None
    nonce, ciphertext, tag = packet[:12], packet[12:-16], packet[-16:]
    cipher = ChaCha20_Poly1305.new(key=session_key, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        print("#! Decryption or authentication error:", e)
        return None

def send_loop(sock, session_key):
    # Interactive loop for sending text messages or files.
    print('Type a message or "/sendfile path" to send file.')  # User instructions
    while True:
        try:
            user_input = input("> ")
            if user_input.startswith("/sendfile "):                 # Start file transfer if command detected
                filepath = user_input[len("/sendfile "):].strip()
                if not os.path.isfile(filepath):
                    print("File not found.")
                    continue
                filename = os.path.basename(filepath)
                filesize = os.path.getsize(filepath)
                file_hash = sha256_file_digest(filepath)
                encrypt_and_send(sock, session_key, {
                    "type": "fileinfo",
                    "filename": filename,
                    "filesize": filesize,
                    "sha256": file_hash
                })
                with open(filepath, "rb") as file_object:
                    chunk_index = 0
                    while True:
                        chunk = file_object.read(4096)
                        if not chunk:
                            break
                        encrypt_and_send(sock, session_key, {
                            "type": "filedata",
                            "filename": filename,
                            "index": chunk_index,
                            "data": base64.b64encode(chunk).decode("ascii")
                        })
                        chunk_index += 1
                encrypt_and_send(sock, session_key, {
                    "type": "fileend",
                    "filename": filename
                })
                print(f"File '{filename}' sent.")
            else:
                encrypt_and_send(sock, session_key, {"type": "text", "data": user_input}) # Regular message
        except Exception as exc:
            print("Send Error:", exc)
            break

def recv_loop(sock, session_key):
    # Continuously receive and process incoming text and file messages.
    file_receivers = {}  # filename -> dict with file object, expected size, written bytes, sha256
    while True:
        msg = recv_and_decrypt(sock, session_key)
        if msg is None:
            print("\nPeer disconnected.")
            os._exit(0)
        if msg["type"] == "text":
            print("\nPeer:", msg["data"])
        elif msg["type"] == "fileinfo":
            recv_filename = "recv_" + msg["filename"]
            print(f"Receiving file '{msg['filename']}' ({msg['filesize']} bytes)...")
            fileobj = open(recv_filename, "wb")
            file_receivers[msg["filename"]] = {
                "file": fileobj,
                "expected_size": msg["filesize"],
                "written_bytes": 0,
                "sha256": msg["sha256"]
            }
        elif msg["type"] == "filedata":
            file_entry = file_receivers.get(msg["filename"])
            if file_entry and not file_entry["file"].closed:
                chunk = base64.b64decode(msg["data"])
                file_entry["file"].write(chunk)
                file_entry["written_bytes"] += len(chunk)
        elif msg["type"] == "fileend":
            file_entry = file_receivers.get(msg["filename"])
            if file_entry:
                file_entry["file"].close()
                recv_filename = "recv_" + msg["filename"]
                computed_hash = sha256_file_digest(recv_filename)
                if computed_hash == file_entry["sha256"]:
                    print(f"File '{msg['filename']}' received OK (SHA256 verified).")
                else:
                    print(f"WARNING: File '{msg['filename']}' integrity check FAILED!")
                del file_receivers[msg["filename"]]

def do_server():
    # Run as a server: listen, perform key exchange, start chat.
    local_private_key, local_public_key = generate_ecdh_key_pair()
    print(f"[Chat Secure Server] Listening on 0.0.0.0:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # Allow quick restart
        server_sock.bind(("0.0.0.0", PORT))
        server_sock.listen(1)
        conn, client_addr = server_sock.accept()
        print("[Connected] From", client_addr)
        conn.sendall(local_public_key.format(compressed=True))               # Send public key to client
        remote_public_bytes = recvn(conn, 33)                               # Receive client's public key
        session_key = perform_ecdh_shared_secret(local_private_key, remote_public_bytes)
        print("[Key Exchanged] Secure session started.")
        threading.Thread(target=send_loop, args=(conn, session_key), daemon=True).start()
        threading.Thread(target=recv_loop, args=(conn, session_key), daemon=True).start()
        threading.Event().wait()

def do_client(dest_ip, proxy=None):
    # Run as a client: connect (with or without proxy), perform key exchange, start chat.
    local_private_key, local_public_key = generate_ecdh_key_pair()
    if proxy:
        if not socks:
            print("PySocks module is required for proxy support. Run: pip install pysocks")
            sys.exit(1)
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_type, proxy_addr, proxy_port = proxy
        sock.set_proxy(proxy_type, proxy_addr, proxy_port)
        print(f"[Proxy] Connecting via proxy ({proxy_addr}:{proxy_port}) ...")
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with sock:
        sock.connect((dest_ip, PORT))
        remote_public_bytes = recvn(sock, 33)                                  # Server sends pubkey first
        sock.sendall(local_public_key.format(compressed=True))                 # Then we send ours
        session_key = perform_ecdh_shared_secret(local_private_key, remote_public_bytes)
        print(f"[Key Exchanged] Connected securely to {dest_ip}:{PORT}")
        threading.Thread(target=send_loop, args=(sock, session_key), daemon=True).start()
        threading.Thread(target=recv_loop, args=(sock, session_key), daemon=True).start()
        threading.Event().wait()

if __name__ == "__main__":
    # Choose mode based on command-line arguments, default to server.
    if len(sys.argv) == 1:
        print("[Default] No arguments given, starting as server.")
        do_server()
    elif sys.argv[1].lower() == "server":
        do_server()
    elif sys.argv[1].lower() == "client":
        if len(sys.argv) < 3:
            print("Usage: python secure_chat.py client SERVER_IP [--proxy socks5|socks4|http PROXY_IP PROXY_PORT]")
            sys.exit(1)
        dest_ip = sys.argv[2]
        proxy = None
        if len(sys.argv) > 6 and sys.argv[3] == "--proxy":
            if not socks:
                print("PySocks module is required for proxy support. Run: pip install pysocks")
                sys.exit(1)
            type_map = {"socks5": socks.SOCKS5, "socks4": socks.SOCKS4, "http": socks.HTTP}
            ptype = sys.argv[4].lower()
            if ptype not in type_map:
                print("Proxy type must be one of: socks5, socks4, http")
                sys.exit(1)
            proxy_addr = sys.argv[5]
            proxy_port = int(sys.argv[6])
            proxy = (type_map[ptype], proxy_addr, proxy_port)
        do_client(dest_ip, proxy)
    else:
        print("Usage:")
        print("  python secure_chat.py server")
        print("  python secure_chat.py client SERVER_IP [--proxy socks5|socks4|http PROXY_IP PROXY_PORT]")
        sys.exit(1)
