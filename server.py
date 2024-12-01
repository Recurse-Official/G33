import socket
import pickle
import sys
from crypto_utils import SecureComm


def send_data(conn, data):
    # Serialize the data
    serialized_data = pickle.dumps(data)

    # Send the length of the data first
    conn.sendall(len(serialized_data).to_bytes(4, byteorder='big'))

    # Send the actual data
    conn.sendall(serialized_data)


def receive_data(conn):
    # Receive the length of the data
    data_length = int.from_bytes(conn.recv(4), byteorder='big')

    # Receive the actual data
    data = b''
    while len(data) < data_length:
        chunk = conn.recv(min(data_length - len(data), 1024))
        if not chunk:
            raise RuntimeError("Socket connection broken")
        data += chunk

    # Deserialize and return the data
    return pickle.loads(data)


def run_server():
    # Server configuration
    HOST = '127.0.0.1'
    PORT = 65432

    # Generate server's key pairs
    server_keys = SecureComm.generate_keypair()

    # Create socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")

        # Accept client connection
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            # 1. Send server's public encryption key
            send_data(conn, server_keys['encrypt_public'])
            print("Sent server's public encryption key")

            # 2. Receive client's public encryption key
            client_encrypt_public = receive_data(conn)
            print("Received client's public encryption key")

            # 3. Encapsulate shared secret for client
            server_shared_secret, encapsulated_key = SecureComm.encapsulate_key(client_encrypt_public)
            send_data(conn, encapsulated_key)
            print("Sent encapsulated shared secret")

            # 4. Send server's public signature key
            send_data(conn, server_keys['sign_public'])
            print("Sent server's public signature key")

            # Communication loop
            while True:
                # Receive encrypted message
                try:
                    encrypted_msg = receive_data(conn)
                    signature = receive_data(conn)
                    client_sign_public = receive_data(conn)

                    # Decrypt message
                    decrypted_msg = SecureComm.decrypt_message(encrypted_msg, server_shared_secret)

                    # Verify signature
                    is_valid = SecureComm.verify_signature(decrypted_msg.decode('utf-8'), signature, client_sign_public)

                    print(f"Received (Signature Valid: {is_valid}): {decrypted_msg.decode('utf-8')}")

                    # Prepare response
                    response = input("Enter response (or 'quit' to exit): ")

                    if response.lower() == 'quit':
                        break

                    # Sign and encrypt response
                    response_signature = SecureComm.sign_message(response, server_keys['sign_private'])
                    encrypted_response = SecureComm.encrypt_message(response.encode('utf-8'), server_shared_secret)

                    # Send encrypted response, signature, and server's signature public key
                    send_data(conn, encrypted_response)
                    send_data(conn, response_signature)
                    send_data(conn, server_keys['sign_public'])

                except Exception as e:
                    print(f"Error in communication: {e}")
                    break


if __name__ == "__main__":
    run_server()