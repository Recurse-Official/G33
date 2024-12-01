import socket
import pickle
import sys
from crypto_utils import SecureComm


def send_data(s, data):
    # Serialize the data
    serialized_data = pickle.dumps(data)

    # Send the length of the data first
    s.sendall(len(serialized_data).to_bytes(4, byteorder='big'))

    # Send the actual data
    s.sendall(serialized_data)


def receive_data(s):
    # Receive the length of the data
    data_length = int.from_bytes(s.recv(4), byteorder='big')

    # Receive the actual data
    data = b''
    while len(data) < data_length:
        chunk = s.recv(min(data_length - len(data), 1024))
        if not chunk:
            raise RuntimeError("Socket connection broken")
        data += chunk

    # Deserialize and return the data
    return pickle.loads(data)


def run_client():
    # Server configuration
    HOST = '127.0.0.1'
    PORT = 65432

    # Generate client's key pairs
    client_keys = SecureComm.generate_keypair()

    # Create socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Connected to {HOST}:{PORT}")

        # 1. Receive server's public encryption key
        server_encrypt_public = receive_data(s)
        print("Received server's public encryption key")

        # 2. Send client's public encryption key
        send_data(s, client_keys['encrypt_public'])
        print("Sent client's public encryption key")

        # 3. Receive encapsulated shared secret
        encapsulated_key = receive_data(s)

        # Decapsulate shared secret
        client_shared_secret = SecureComm.decapsulate_key(client_keys['encrypt_private'], encapsulated_key)
        print("Derived shared secret")

        # 4. Receive server's public signature key
        server_sign_public = receive_data(s)
        print("Received server's public signature key")

        # Communication loop
        while True:
            # Prepare message
            message = input("Enter message (or 'quit' to exit): ")

            if message.lower() == 'quit':
                break

            # Sign message
            signature = SecureComm.sign_message(message, client_keys['sign_private'])

            # Encrypt message
            encrypted_msg = SecureComm.encrypt_message(message.encode('utf-8'), client_shared_secret)

            # Send encrypted message, signature, and client's signature public key
            send_data(s, encrypted_msg)
            send_data(s, signature)
            send_data(s, client_keys['sign_public'])

            # Receive response
            try:
                encrypted_response = receive_data(s)
                response_signature = receive_data(s)
                server_sign_public_received = receive_data(s)

                # Decrypt response
                decrypted_response = SecureComm.decrypt_message(encrypted_response, client_shared_secret)

                # Verify signature
                is_valid = SecureComm.verify_signature(decrypted_response.decode('utf-8'), response_signature,
                                                       server_sign_public_received)

                print(f"Received (Signature Valid: {is_valid}): {decrypted_response.decode('utf-8')}")

            except Exception as e:
                print(f"Error in communication: {e}")
                break


if __name__ == "__main__":
    run_client()