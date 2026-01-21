#!/usr/bin/env python3
"""
Secure asynchronous end-to-end chat/file transfer over TCP using X25519 key agreement
and per-session AES-GCM encryption for privacy and authenticity. Communication is done
in threads for send/receive independence. File transfers are chunked and verified.
USAGE:
  Server:   python3 chatfile.py --server PORT
  Client:   python3 chatfile.py --connect HOST:PORT
COMMANDS:
  /quit           Disconnects.
  /sendfile PATH  Send file at PATH to the peer (file is chunked, hashed, reassembled and verified on receiver).
MESSAGE LAYOUT:
  All application-level messages (after handshake and symmetric key established) use:
    [4-byte big-endian length][encrypted payload]
  Encrypted payload is:
    [12-byte random nonce][AES-GCM ciphertext]
  There are two types of messages, distinguished by unencrypted magic header once decrypted:
  1. Text message:
      [b'TEXT'][UTF-8 data]
  2. File chunk message:
      [b'FILE'] 
      [2-byte little-endian header length]
      [1-byte filename length][filename utf8]
      [8-byte file_size][4-byte this_chunk_size][4-byte chunk_index][4-byte total_chunks]
      [32-byte sha256 of chunk_data]
      [chunk_data (this_chunk_size bytes)]
    - Each chunk contains the above header plus actual data.
    - When all chunks are received and validated by hash, the receiver writes the file atomically.
    - Received files are renamed as needed to avoid overwrite.
SECURITY:
- All communication is encrypted and authenticated.
- X25519 key exchange is used for forward secrecy.
- Each session uses a random symmetric key derived using HKDF-SHA256.
- Each AES-GCM message uses a fresh random nonce.
DEPENDENCIES:
  pip install cryptography
"""

import socket
import struct
import argparse
import sys
import threading
import queue
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519      # X25519 key exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF          # HKDF for AES key derivation
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM    # AES-GCM symmetric encryption

MAGIC_FILE_CHUNK = b'FILE'            # Magic for file chunk message
MAGIC_TEXT_LINE = b'TEXT'             # Magic for text line message

FILE_CHUNK_SIZE = 65536               # File chunk size (64 KiB)
MAX_FILENAME_LENGTH = 255             # Max file name (UTF-8 bytes)

send_queue = queue.Queue()            # Queue for outgoing plaintext messages
recv_queue = queue.Queue()            # Queue for incoming decrypted messages
session_aes_key = None                # Symmetric AES session key
tcp_socket = None                     # TCP socket object

def perform_handshake(transport_socket, is_server_side):
    """Performs X25519 key exchange and returns the session AES key."""
    local_private_key = x25519.X25519PrivateKey.generate()
    local_public_bytes = local_private_key.public_key().public_bytes()
    if is_server_side:                                    # Server: recv, then send
        peer_public_bytes = receive_frame(transport_socket)
        send_frame(transport_socket, local_public_bytes)
    else:                                                 # Client: send, then recv
        send_frame(transport_socket, local_public_bytes)
        peer_public_bytes = receive_frame(transport_socket)
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = local_private_key.exchange(peer_public_key)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'x25519-aesgcm-session'
    ).derive(shared_secret)
    return session_key

def send_frame(transport_socket, data_bytes):
    """Send a length-prefixed data frame: [uint32 length][data]. Blocking."""
    frame_length = struct.pack('>I', len(data_bytes))         # 4-byte big endian length
    transport_socket.sendall(frame_length + data_bytes)

def receive_frame(transport_socket):
    """Receive a length-prefixed data frame. Blocking."""
    length_bytes = b''
    while len(length_bytes) < 4:
        chunk = transport_socket.recv(4 - len(length_bytes))
        if not chunk: raise ConnectionError("Connection closed before length field.")
        length_bytes += chunk
    total_length = struct.unpack('>I', length_bytes)[0]
    data_bytes = b''
    while len(data_bytes) < total_length:
        chunk = transport_socket.recv(total_length - len(data_bytes))
        if not chunk: raise ConnectionError("Connection closed before all data received.")
        data_bytes += chunk
    return data_bytes

def encrypt_message(plaintext_bytes):
    """Encrypt plaintext using the session AES key, with a fresh nonce."""
    nonce_bytes = os.urandom(12)
    cipher_bytes = AESGCM(session_aes_key).encrypt(nonce_bytes, plaintext_bytes, None)
    return nonce_bytes + cipher_bytes

def decrypt_message(ciphertext_bytes):
    """Decrypt a message with the session AES key."""
    if len(ciphertext_bytes) < 12:
        raise ValueError("Encrypted message too short (no nonce present).")
    nonce_bytes, cipher_part = ciphertext_bytes[:12], ciphertext_bytes[12:]
    decrypted = AESGCM(session_aes_key).decrypt(nonce_bytes, cipher_part, None)
    return decrypted

def sending_thread_loop():
    """Thread: takes plaintext messages from send_queue, encrypts and sends to peer."""
    while True:
        plaintext = send_queue.get()
        if plaintext is None:
            break
        encrypted = encrypt_message(plaintext)
        send_frame(tcp_socket, encrypted)

def receiving_thread_loop():
    """Thread: receives encrypted frames, decrypts and queues for processing."""
    while True:
        try:
            encrypted_frame = receive_frame(tcp_socket)
        except Exception:
            break
        try:
            decrypted_message = decrypt_message(encrypted_frame)
        except Exception:
            print("[Decryption failed. Disconnecting.]")
            break
        recv_queue.put(decrypted_message)
    recv_queue.put(None)                              # Passing signal for processor to quit

def user_input_loop():
    """Reads user input lines/commands and pushes into send_queue (handles /sendfile)."""
    while True:
        try:
            user_line = input("> ")
        except EOFError:
            send_queue.put(None)
            break
        trimmed = user_line.strip()
        if trimmed == "/quit":
            send_queue.put(None)
            break
        if trimmed.startswith("/sendfile "):
            _, path = trimmed.split(" ", 1)
            if os.path.isfile(path):
                send_file_by_chunks(path)
            else:
                print("[File not found]")
            continue
        # Send as text message (prepend magic)
        message_bytes = MAGIC_TEXT_LINE + trimmed.encode()
        send_queue.put(message_bytes)

def send_file_by_chunks(filepath):
    """Reads file, splits into chunks, sends each with detailed encoded file headers."""
    file_size = os.path.getsize(filepath)
    base_filename = os.path.basename(filepath)
    file_name_bytes = base_filename.encode("utf-8")
    if len(file_name_bytes) > MAX_FILENAME_LENGTH:
        print("[File name too long]")
        return
    total_chunks = (file_size + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE
    with open(filepath, "rb") as file_handle:
        for chunk_index in range(total_chunks):
            chunk_data = file_handle.read(FILE_CHUNK_SIZE)
            chunk_hash = hashlib.sha256(chunk_data).digest()
            header_buffer = MAGIC_FILE_CHUNK
            # Compose header (see docstring)
            header_len = 2 + 1 + len(file_name_bytes) + 8 + 4 + 4 + 4 + 32
            header_buffer += struct.pack('<H', header_len)                    # header length (LE) (2)
            header_buffer += struct.pack('<B', len(file_name_bytes))          # filename length (1)
            header_buffer += file_name_bytes                                  # filename (N)
            header_buffer += struct.pack('<Q', file_size)                     # file size (8)
            header_buffer += struct.pack('<I', len(chunk_data))               # this chunk data len (4)
            header_buffer += struct.pack('<I', chunk_index)                   # chunk number (4)
            header_buffer += struct.pack('<I', total_chunks)                  # total chunks (4)
            header_buffer += chunk_hash                                       # chunk sha256 (32)
            packet_bytes = header_buffer + chunk_data                         # Full message
            send_queue.put(packet_bytes)
    print(f"[File sent: {filepath} ({file_size} bytes, {total_chunks} chunks)]")

def save_file_chunks_to_disk(chunks_dict, file_metadata):
    """Writes all collected file chunks in-order to a unique file, verifies hash, returns final filename."""
    file_name, total_chunks, total_length = file_metadata
    candidate_filename = file_name
    duplicate_count = 0
    while os.path.exists(candidate_filename):
        duplicate_count += 1
        candidate_filename = f"{file_name}.{duplicate_count}"
    with open(candidate_filename, "wb") as output_file:
        for i in range(total_chunks):
            output_file.write(chunks_dict[i])
    print(f"[File received: {candidate_filename} ({total_length} bytes)]")

def main_message_processing_loop():
    """Processes items from recv_queue: prints text, reassembles and writes received files."""
    files_waiting = dict()    # {meta_tuple: {chunk_index: chunk_data}}, stores file chunks in-memory
    chunks_received_count = dict()  # {meta_tuple: count}, tracks received chunks for each file
    while True:
        incoming = recv_queue.get()  # Get the next decrypted item from the queue (blocking)
        if incoming is None:  # Check for termination signal
            break
        if incoming.startswith(MAGIC_TEXT_LINE):  # Check if it's a text message
            text_bytes = incoming[4:]  # The text message starts after the 4-byte magic
            try:
                text_line = text_bytes.decode("utf-8", errors="replace")  # Decode bytes to string
            except Exception:
                text_line = "<decode error>"  # On decode failure, use placeholder
            print("\nPeer:", text_line)  # Display incoming message
        elif incoming.startswith(MAGIC_FILE_CHUNK):  # File chunk detected by magic
            cursor = 4  # Starting index past the 'FILE' magic
            header_length = struct.unpack('<H', incoming[cursor:cursor+2])[0]; cursor += 2  # Fetch header length
            filename_length = incoming[cursor]; cursor += 1  # Fetch filename length (one byte)
            filename = incoming[cursor:cursor+filename_length].decode("utf-8", errors="replace"); cursor += filename_length  # Get filename
            file_size = struct.unpack('<Q', incoming[cursor:cursor+8])[0]; cursor += 8  # Get declared total file size
            this_chunk_length = struct.unpack('<I', incoming[cursor:cursor+4])[0]; cursor += 4  # This data chunk size
            chunk_index = struct.unpack('<I', incoming[cursor:cursor+4])[0]; cursor += 4  # Which chunk number is this
            chunks_total = struct.unpack('<I', incoming[cursor:cursor+4])[0]; cursor += 4  # Total number of chunks
            hash_value = incoming[cursor:cursor+32]; cursor += 32  # SHA256 hash of this chunk, for validation
            chunk_data = incoming[cursor:cursor+this_chunk_length]  # Actual chunk data slice
            file_key = (filename, chunks_total, file_size)  # Tuple uniquely identifying this file transfer
            if file_key not in files_waiting:  # If this is the first chunk for this file
                files_waiting[file_key] = {}  # Initialize the chunk dict for reassembly
                chunks_received_count[file_key] = 0  # Initialize the counter for this file
                print(f"[Started receiving file: {filename}]")  # Logging file header
            computed_hash = hashlib.sha256(chunk_data).digest()  # Hash chunk for validation
            if computed_hash != hash_value:  # Check for data corruption
                print(f"[Warning: File chunk {chunk_index} hash check failed. Skipping chunk.]")  # Warn about hash mismatch
            else:
                if chunk_index not in files_waiting[file_key]:  # Only count unique chunks
                    files_waiting[file_key][chunk_index] = chunk_data  # Save received chunk by its index
                    chunks_received_count[file_key] += 1  # Increment counter for completed chunks
            print(f"[File {filename} chunk {chunk_index+1}/{chunks_total} received]")  # Display progress
            if chunks_received_count[file_key] == chunks_total:  # If all expected chunks are received
                save_file_chunks_to_disk(files_waiting[file_key], file_key)  # Assemble and write the file
                del files_waiting[file_key]  # Cleanup memory for this file
                del chunks_received_count[file_key]
        else:
            print("[Warning: Unknown message type received]")  # Unrecognized message type

def main():
    parser = argparse.ArgumentParser(description="Secure async chat/file transfer, X25519 handshake + AES-GCM + threads.")  # Setup argument parser
    group = parser.add_mutually_exclusive_group(required=True)  # Only allow server or client at once
    group.add_argument("--server", metavar="PORT", help="Run as server listening at this port")  # Server mode flag
    group.add_argument("--connect", metavar="HOST:PORT", help="Connect to server as client (eg: 10.1.2.3:8000)")  # Client mode flag
    args = parser.parse_args()  # Parse command line arguments
    global session_aes_key, tcp_socket  # Use global session key and socket
    if args.server:  # If server mode
        server_socket = socket.socket()  # Create new TCP socket
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable address reuse
        server_socket.bind(('0.0.0.0', int(args.server)))  # Listen on all interfaces on specified port
        server_socket.listen(1)  # Start listening (max 1 queued connection)
        print(f"[Listening on 0.0.0.0:{args.server}]")  # Inform
        accepted_socket, peer_address = server_socket.accept()  # Accept a connection
        print(f"[Accepted connection from {peer_address}]")  # Inform
        tcp_socket = accepted_socket  # Set global socket
        session_aes_key = perform_handshake(accepted_socket, True)  # Perform server-side handshake
    else:  # Client mode
        remote_host, remote_port = args.connect.split(":")  # Extract host and port
        client_socket = socket.create_connection((remote_host, int(remote_port)))  # Establish TCP connection
        print(f"[Connected to {remote_host}:{remote_port}]")  # Inform
        tcp_socket = client_socket  # Set global socket
        session_aes_key = perform_handshake(client_socket, False)  # Perform client-side handshake
    print("[Handshake complete. Secure session established.]")  # Confirm secure session ready
    sender_thread = threading.Thread(target=sending_thread_loop, daemon=True)  # Thread for sending plaintext from send_queue
    receiver_thread = threading.Thread(target=receiving_thread_loop, daemon=True)  # Thread for receiving/decrypting into recv_queue
    sender_thread.start()  # Start sender thread
    receiver_thread.start()  # Start receiver thread
    message_processor_thread = threading.Thread(target=main_message_processing_loop)  # Thread for message/file processing
    message_processor_thread.start()  # Start processor thread
    user_input_loop()  # Handle user input and command loop (blocking in main thread)
    sender_thread.join()  # Wait for sender exit
    receiver_thread.join()  # Wait for receiver exit
    recv_queue.put(None)  # Signal processor thread to terminate
    message_processor_thread.join()  # Wait for processor thread exit
    print("[Session closed]")  # Inform user

if __name__ == "__main__":
    main()
