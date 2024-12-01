from kyber_py.kyber import Kyber512
from dilithium_py.dilithium import Dilithium2



class SecureComm:
    @staticmethod
    def generate_keypair():
        # Kyber key for encryption
        pk_encrypt, sk_encrypt = Kyber512.keygen()

        # Dilithium key for signatures
        pk_sign, sk_sign = Dilithium2.keygen()

        return {
            'encrypt_public': pk_encrypt,
            'encrypt_private': sk_encrypt,
            'sign_public': pk_sign,
            'sign_private': sk_sign
        }

    @staticmethod
    def encapsulate_key(recipient_public_key):
        # Generate shared secret and its encapsulation
        shared_secret, encapsulated_key = Kyber512.encaps(recipient_public_key)
        return shared_secret, encapsulated_key

    @staticmethod
    def decapsulate_key(private_key, encapsulated_key):
        # Decrypt the shared secret
        decapsulated_secret = Kyber512.decaps(private_key, encapsulated_key)
        return decapsulated_secret

    @staticmethod
    def sign_message(message, sign_private_key):
        # Sign the message
        signature = Dilithium2.sign(sign_private_key, message.encode('utf-8'))
        return signature

    @staticmethod
    def verify_signature(message, signature, sign_public_key):
        # Verify the signature
        return Dilithium2.verify(sign_public_key, message.encode('utf-8'), signature)

    @staticmethod
    def encrypt_message(message, shared_secret):
        # Simple XOR encryption (for demonstration)
        # In a real-world scenario, use a proper symmetric encryption method
        encrypted = bytes([message[i] ^ shared_secret[i % len(shared_secret)] for i in range(len(message))])
        return encrypted

    @staticmethod
    def decrypt_message(encrypted_message, shared_secret):
        # Decrypt using the same XOR method
        decrypted = bytes(
            [encrypted_message[i] ^ shared_secret[i % len(shared_secret)] for i in range(len(encrypted_message))])
        return decrypted