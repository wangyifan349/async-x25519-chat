import socket
import threading
import json
import os
import struct
import base64
from hashlib import sha256                       # For key derivation and file integrity
from coincurve import PrivateKey, PublicKey      # secp256k1 ECDH/BIP32 compatible curve
from Crypto.Cipher import ChaCha20_Poly1305      # Secure AEAD cipher for payloads

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432

def generate_ecdh_key_pair():
    """
    Generate a secp256k1 ECDH private/public key pair.
    """
    private_key = PrivateKey()                                                            # Random secp256k1 private key   
    public_key = private_key.public_key                                                   # Corresponding public key
    return private_key, public_key

def perform_ecdh_shared_secret(local_private_key, remote_public_bytes):
    """
    Perform ECDH with secp256k1: local private scalar * peer's public point.
    Output is 32-byte shared secret (not directly suitable for encryption).
    """
    remote_public_key = PublicKey(remote_public_bytes)                                    # PublicKey object from bytes
    shared_secret = local_private_key.ecdh(remote_public_key)                             # ECDH step, result is bytes
    # It is best practice to process ECDH output with KDF, e.g., SHA256, for uniform key
    return sha256(shared_secret).digest()                                                 # Secure symmetric session key

def sha256_file_digest(filename):
    """
    Compute SHA256 digest of a file, used for file integrity.
    """
    hasher = sha256()
    with open(filename, "rb") as file_object:
        while True:
            data_chunk = file_object.read(4096)
            if not data_chunk: break
            hasher.update(data_chunk)
    return hasher.hexdigest()

def recv_exact(sock, size):
    """
    Robustly receive 'size' bytes from a socket.
    """
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part: return None
        data += part
    return data

def encrypt_and_send(sock, session_key, message_dict):
    """
    Encrypt a JSON message with ChaCha20-Poly1305.
    """
    plaintext = json.dumps(message_dict).encode("utf-8")                                  # Standard UTF-8 encoding
    nonce = os.urandom(12)                                                               # 96-bit unique nonce per message
    cipher = ChaCha20_Poly1305.new(key=session_key, nonce=nonce)                         # AEAD setup
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    packet = nonce + ciphertext + tag                                                    # nonce||ciphertext||tag
    sock.sendall(struct.pack(">I", len(packet)) + packet)                                # Framed: length + message

def recv_and_decrypt(sock, session_key):
    """
    Decrypt an incoming framed message.
    """
    header = recv_exact(sock, 4)                                                         # 4-byte length prefix
    if not header: return None
    packet_length = struct.unpack(">I", header)[0]
    packet = recv_exact(sock, packet_length)
    if not packet or len(packet) != packet_length: return None
    nonce, ciphertext, tag = packet[:12], packet[12:-16], packet[-16:]
    cipher = ChaCha20_Poly1305.new(key=session_key, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext.decode("utf-8"))                                     # Standard utf-8
    except Exception as e:
        print("#! Decrypt/verify failure:", e)                                           # On authentication failure
        return None

def send_loop(sock, session_key):
    """
    Input loop: send either plain text or file transfer requests/files.
    """
    print('Type a message or "/sendfile PATH" to send a file:')
    while True:
        try:
            user_input = input("> ")                                                     # Non-blocking with respect to recv
            if user_input.startswith("/sendfile "):
                filepath = user_input[len("/sendfile "):].strip()
                if not os.path.isfile(filepath):
                    print("File not found.")
                    continue
                filename = os.path.basename(filepath)
                filesize = os.path.getsize(filepath)
                file_hash = sha256_file_digest(filepath)
                # 1. Send fileinfo
                encrypt_and_send(sock, session_key, {
                    "type": "fileinfo",
                    "filename": filename,
                    "filesize": filesize,
                    "sha256": file_hash
                })      # Describe file, so peer prepares for chunks
                # 2. Send all filedata chunks
                with open(filepath, "rb") as file_object:
                    chunk_index = 0
                    while True:
                        chunk = file_object.read(4096)
                        if not chunk: break
                        encrypt_and_send(sock, session_key, {
                            "type": "filedata",
                            "filename": filename,
                            "index": chunk_index,
                            "data": base64.b64encode(chunk).decode("ascii")
                        })  # Each chunk base64 for JSON safety
                        chunk_index += 1
                # 3. Explicitly notify file end
                encrypt_and_send(sock, session_key, {
                    "type": "fileend",
                    "filename": filename
                })
                print(f"File '{filename}' sent.")
            else:
                encrypt_and_send(sock, session_key, {"type": "text", "data": user_input})
        except Exception as exc:
            print("Send Error:", exc)
            break

def recv_loop(sock, session_key):
    """
    Receive loop: handles both text and file reception, totally independent of send.
    """
    active_file_receivers = {}  # filename -> dict {file, expected_size, written, sha256}
    while True:
        msg = recv_and_decrypt(sock, session_key)
        if msg is None:
            print("\nPeer disconnected.")
            os._exit(0)
        if msg["type"] == "text":
            print("\nPeer:", msg["data"])
        elif msg["type"] == "fileinfo":
            recv_filename = "recv_" + msg["filename"]
            print(f"Receiving file: '{msg['filename']}' ({msg['filesize']} bytes)...")
            fileobj = open(recv_filename, "wb")
            active_file_receivers[msg["filename"]] = {
                "file": fileobj,
                "expected_size": msg["filesize"],
                "written_bytes": 0,
                "sha256": msg["sha256"]
            }
        elif msg["type"] == "filedata":
            file_entry = active_file_receivers.get(msg["filename"])
            if file_entry and not file_entry["file"].closed:
                chunk = base64.b64decode(msg["data"])
                file_entry["file"].write(chunk)
                file_entry["written_bytes"] += len(chunk)
        elif msg["type"] == "fileend":
            file_entry = active_file_receivers.get(msg["filename"])
            if file_entry:
                file_entry["file"].close()
                recv_filename = "recv_" + msg["filename"]
                computed_hash = sha256_file_digest(recv_filename)
                if computed_hash == file_entry["sha256"]:
                    print(f"File '{msg['filename']}' received OK.")
                else:
                    print(f"WARNING: File '{msg['filename']}' integrity check FAILED!")
                del active_file_receivers[msg["filename"]]
        else:
            continue

def main():
    # 1. Generate ECDH key pair
    local_private_key, local_public_key = generate_ecdh_key_pair()          # Our static keypair
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))
        # 2. Exchange compressed public keys
        remote_public_bytes = recv_exact(sock, 33)                          # Get server public key first
        sock.sendall(local_public_key.format(compressed=True))              # Then send our key
        # 3. Derive the shared session key ("intermediate exchange seedling")
        session_key = perform_ecdh_shared_secret(local_private_key, remote_public_bytes)
        print("Secure session key established.")                            # ECDH-derived, post-hash
        threading.Thread(target=send_loop, args=(sock, session_key), daemon=True).start()
        threading.Thread(target=recv_loop, args=(sock, session_key), daemon=True).start()
        threading.Event().wait()

if __name__ == "__main__":
    main()
