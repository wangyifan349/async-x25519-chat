#!/usr/bin/env python3
"""
Asyncio TCP chat with x25519 handshake and AES-GCM encryption.
- Descriptive variable names, no nested blocks where avoidable, line-end comments.
- Usage:
    # server
    python3 async_tcp_x25519_readable.py --role server --bind 0.0.0.0 --port 12345

    # client
    python3 async_tcp_x25519_readable.py --role client --host 127.0.0.1 --port 12345

Requires:
    pip install cryptography
"""  # file docstring

import argparse  # argument parsing
import asyncio  # asyncio primitives
import struct  # binary packing/unpacking
import os  # random bytes for nonce
import sys  # stdin access

from cryptography.hazmat.primitives.asymmetric import x25519  # X25519 keys
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # HKDF for key derivation
from cryptography.hazmat.primitives import hashes  # hash algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-GCM AEAD

# ---------------------
# Framing helpers
# ---------------------
async def read_exact_bytes(stream_reader: asyncio.StreamReader, total_bytes: int) -> bytes:
    """
    Read exactly total_bytes from stream_reader or raise ConnectionError if closed.
    """  # docstring
    buffer = b""  # accumulator for received bytes
    while len(buffer) < total_bytes:  # loop until we have requested amount
        chunk = await stream_reader.read(total_bytes - len(buffer))  # read remaining bytes
        if not chunk:
            raise ConnectionError("stream closed while reading exact bytes")  # unexpected EOF
        buffer += chunk  # append chunk
    return buffer  # return collected bytes

async def receive_framed_message(stream_reader: asyncio.StreamReader) -> bytes:
    """
    Read a 4-byte big-endian length prefix then that many bytes payload.
    """
    header_bytes = await read_exact_bytes(stream_reader, 4)  # read length prefix
    (payload_length,) = struct.unpack(">I", header_bytes)  # unpack as unsigned int BE
    payload_bytes = await read_exact_bytes(stream_reader, payload_length)  # read payload
    return payload_bytes  # return framed payload

async def send_framed_message(stream_writer: asyncio.StreamWriter, payload_bytes: bytes) -> None:
    """
    Send a 4-byte big-endian length prefix followed by payload_bytes, then drain.
    """
    length_prefix = struct.pack(">I", len(payload_bytes))  # pack length
    stream_writer.write(length_prefix + payload_bytes)  # write prefix + payload
    await stream_writer.drain()  # ensure data sent

# ---------------------
# Handshake helpers
# ---------------------
async def perform_handshake_initiator(stream_reader: asyncio.StreamReader,
                                      stream_writer: asyncio.StreamWriter) -> bytes:
    """
    Initiator: send public key first, then receive peer public key, return shared secret.
    """
    private_key = x25519.X25519PrivateKey.generate()  # generate private key
    public_key_bytes = private_key.public_key().public_bytes()  # get public key bytes
    await send_framed_message(stream_writer, public_key_bytes)  # send our public key
    peer_public_key_bytes = await receive_framed_message(stream_reader)  # receive peer pubkey
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)  # parse
    shared_secret = private_key.exchange(peer_public_key)  # compute shared secret
    return shared_secret  # return raw shared secret

async def perform_handshake_responder(stream_reader: asyncio.StreamReader,
                                      stream_writer: asyncio.StreamWriter) -> bytes:
    """
    Responder: receive peer public key first, then send our public key, return shared secret.
    """
    peer_public_key_bytes = await receive_framed_message(stream_reader)  # get peer pubkey
    private_key = x25519.X25519PrivateKey.generate()  # generate private key
    public_key_bytes = private_key.public_key().public_bytes()  # get public key bytes
    await send_framed_message(stream_writer, public_key_bytes)  # send our public key
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)  # parse
    shared_secret = private_key.exchange(peer_public_key)  # compute shared secret
    return shared_secret  # return raw shared secret

def derive_aes_key_from_shared_secret(shared_secret: bytes) -> bytes:
    """
    Derive a 32-byte AES key from shared_secret using HKDF-SHA256.
    """
    hkdf_instance = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x25519-aesgcm-v1")  # HKDF setup
    derived_key = hkdf_instance.derive(shared_secret)  # derive 32 bytes
    return derived_key  # return AES-256 key

# ---------------------
# Encryption helpers
# ---------------------
def encrypt_with_aes_gcm(aes_key: bytes, plaintext_bytes: bytes) -> bytes:
    """
    Encrypt plaintext_bytes with AES-GCM using a random 12-byte nonce.
    Returns nonce || ciphertext_with_tag.
    """
    aead_cipher = AESGCM(aes_key)  # AESGCM object
    nonce_bytes = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext_with_tag = aead_cipher.encrypt(nonce_bytes, plaintext_bytes, associated_data=None)  # encrypt
    return nonce_bytes + ciphertext_with_tag  # prepend nonce

def decrypt_with_aes_gcm(aes_key: bytes, payload_bytes: bytes) -> bytes:
    """
    Decrypt payload_bytes (nonce || ciphertext||tag) with AES-GCM, return plaintext.
    """
    if len(payload_bytes) < 12 + 16:
        raise ValueError("payload too short for AES-GCM")  # basic length check
    nonce_bytes = payload_bytes[:12]  # extract nonce
    ciphertext_with_tag = payload_bytes[12:]  # remaining is ciphertext+tag
    aead_cipher = AESGCM(aes_key)  # AESGCM object
    plaintext_bytes = aead_cipher.decrypt(nonce_bytes, ciphertext_with_tag, associated_data=None)  # decrypt
    return plaintext_bytes  # return plaintext

# ---------------------
# Stdin reader (non-blocking for asyncio)
# ---------------------
async def stdin_line_reader_to_queue(output_queue: asyncio.Queue) -> None:
    """
    Read lines from stdin using a thread executor and push to output_queue.
    Puts None into queue when EOF reached.
    """
    event_loop = asyncio.get_running_loop()  # current event loop

    def blocking_readline() -> bytes:
        return sys.stdin.buffer.readline()  # blocking call to read stdin

    while True:
        line_bytes = await event_loop.run_in_executor(None, blocking_readline)  # run blocking IO in executor
        if not line_bytes:
            await output_queue.put(None)  # signal EOF
            return
        stripped_line = line_bytes.rstrip(b"\n")  # remove trailing newline
        await output_queue.put(stripped_line)  # push to queue
        if stripped_line == b"/quit":  # allow /quit to stop
            return

# ---------------------
# Send and receive loops
# ---------------------
async def send_loop_from_queue(stream_writer: asyncio.StreamWriter,
                               aes_key: bytes,
                               send_queue: asyncio.Queue) -> None:
    """
    Consume bytes from send_queue, encrypt and send framed messages over stream_writer.
    Exits when queue yields None or '/quit'.
    """
    try:
        while True:
            item = await send_queue.get()  # get next item
            if item is None:
                break  # EOF signal
            if item == b"/quit":
                break  # user requested quit
            encrypted_payload = encrypt_with_aes_gcm(aes_key, item)  # encrypt plaintext
            await send_framed_message(stream_writer, encrypted_payload)  # send framed encrypted payload
    finally:
        try:
            stream_writer.write_eof()  # signal EOF to peer if supported
        except Exception:
            pass
        try:
            await stream_writer.drain()  # flush pending writes
        except Exception:
            pass

async def receive_loop_to_stdout(stream_reader: asyncio.StreamReader, aes_key: bytes) -> None:
    """
    Receive framed encrypted messages, decrypt and print to stdout.
    """
    while True:
        try:
            framed_payload = await receive_framed_message(stream_reader)  # get framed encrypted payload
        except ConnectionError:
            return  # stream closed
        if not framed_payload:
            return  # no data => exit
        try:
            plaintext_bytes = decrypt_with_aes_gcm(aes_key, framed_payload)  # decrypt
            try:
                plaintext_text = plaintext_bytes.decode("utf-8", errors="replace")  # decode for display
            except Exception:
                plaintext_text = "<binary data>"  # fallback label
            # print peer message and reprint prompt
            print("\nPeer:", plaintext_text)  # show peer message
            print("> ", end="", flush=True)  # prompt
        except Exception as decrypt_error:
            print("Decrypt error:", decrypt_error)  # show decrypt error and continue

# ---------------------
# Server and client runners
# ---------------------
async def handle_single_client_connection(client_reader: asyncio.StreamReader,
                                          client_writer: asyncio.StreamWriter) -> None:
    """
    Handle an accepted client connection: perform handshake, then start send/recv tasks.
    This function is intentionally flat (no deep nesting) for clarity.
    """
    peer_address = client_writer.get_extra_info("peername")  # get peer address
    print("Accepted connection from", peer_address)  # log connection
    try:
        shared_secret = await perform_handshake_responder(client_reader, client_writer)  # responder handshake
    except Exception as handshake_error:
        print("Handshake failed:", handshake_error)  # log and return
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass
        return
    aes_key = derive_aes_key_from_shared_secret(shared_secret)  # derive AES key
    print("Handshake complete. AES key derived.")  # notify ready
    send_queue = asyncio.Queue()  # queue for lines to send
    stdin_task = asyncio.create_task(stdin_line_reader_to_queue(send_queue))  # task reading stdin
    send_task = asyncio.create_task(send_loop_from_queue(client_writer, aes_key, send_queue))  # sending task
    receive_task = asyncio.create_task(receive_loop_to_stdout(client_reader, aes_key))  # receiving task

    done_tasks, pending_tasks = await asyncio.wait(
        {stdin_task, send_task},
        return_when=asyncio.FIRST_COMPLETED
    )  # wait until stdin or send finishes

    # signal send loop to exit if not already
    await send_queue.put(None)  # ensure send loop will terminate
    await send_task  # wait send loop finished

    try:
        client_writer.close()  # close connection writer
        await client_writer.wait_closed()
    except Exception:
        pass

    await receive_task  # wait receive loop finished
    return

async def run_server(bind_address: str, bind_port: int) -> None:
    """
    Start TCP server and accept a single connection, handling it with handle_single_client_connection.
    """
    server = await asyncio.start_server(handle_single_client_connection, bind_address, bind_port)  # start server
    socket_names = []
    for server_socket in server.sockets:
        socket_names.append(str(server_socket.getsockname()))  # collect listening addresses
    listening_addresses = ", ".join(socket_names)  # join for display
    print("Listening on", listening_addresses)  # show listening addrs
    async with server:
        await server.serve_forever()  # serve forever

async def run_client(remote_host: str, remote_port: int) -> None:
    """
    Connect to remote_host:remote_port, perform initiator handshake, then start send/recv tasks.
    """
    reader, writer = await asyncio.open_connection(remote_host, remote_port)  # open connection
    print("Connected to", (remote_host, remote_port))  # log
    try:
        shared_secret = await perform_handshake_initiator(reader, writer)  # initiator handshake
    except Exception as handshake_error:
        print("Handshake failed:", handshake_error)  # log
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return
    aes_key = derive_aes_key_from_shared_secret(shared_secret)  # derive AES key
    print("Handshake complete. AES key derived.")  # notify ready
    send_queue = asyncio.Queue()  # create queue for stdin lines
    stdin_task = asyncio.create_task(stdin_line_reader_to_queue(send_queue))  # task reading stdin
    send_task = asyncio.create_task(send_loop_from_queue(writer, aes_key, send_queue))  # sending task
    receive_task = asyncio.create_task(receive_loop_to_stdout(reader, aes_key))  # receiving task

    done_tasks, pending_tasks = await asyncio.wait(
        {stdin_task, send_task},
        return_when=asyncio.FIRST_COMPLETED
    )  # wait until stdin or send finishes

    await send_queue.put(None)  # ensure send loop stops
    await send_task  # wait for send completion

    try:
        writer.close()  # close writer
        await writer.wait_closed()
    except Exception:
        pass

    await receive_task  # wait for receive loop to finish
    return

# ---------------------
# Argument parsing and entrypoint
# ---------------------
def parse_command_line_arguments():
    """
    Parse and return command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Asyncio TCP chat with x25519 + AES-GCM, readable variable names")  # set up parser
    parser.add_argument("--role", choices=("server", "client"), required=True)  # role flag
    parser.add_argument("--bind", default="0.0.0.0")  # bind address for server
    parser.add_argument("--host", default="127.0.0.1")  # host for client
    parser.add_argument("--port", type=int, default=12345)  # port for both
    return parser.parse_args()  # return parsed args

def main():
    """
    Entry point: parse args and run server or client accordingly.
    """
    args = parse_command_line_arguments()  # get args
    try:
        if args.role == "server":  # server role
            asyncio.run(run_server(args.bind, args.port))  # run server
        else:  # client role
            asyncio.run(run_client(args.host, args.port))  # run client
    except KeyboardInterrupt:
        print("Interrupted. Exiting.")  # Ctrl+C handled

if __name__ == "__main__":
    main()  # call main
