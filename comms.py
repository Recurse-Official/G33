from kyber_py.kyber import Kyber512
from dilithium_py.dilithium import Dilithium2


# Helper functions for communication
def person_a_send_key():
    # Generate Kyber keypair
    pk_a, sk_a = Kyber512.keygen()

    # Generate Dilithium keypair
    pk_a_sig, sk_a_sig = Dilithium2.keygen()

    return pk_a, sk_a, pk_a_sig, sk_a_sig


def person_b_send_key():
    # Generate Kyber keypair
    pk_b, sk_b = Kyber512.keygen()

    # Generate Dilithium keypair
    pk_b_sig, sk_b_sig = Dilithium2.keygen()

    return pk_b, sk_b, pk_b_sig, sk_b_sig


def generate_shared_key(pk_a, pk_b, sk_a, sk_b):
    print("\n--- Key Exchange Process ---")
    # A generates shared key and challenge using B's public key
    key_a, c_a = Kyber512.encaps(pk_b)

    print("Person A generates challenge:")
    print("Challenge:", c_a)
    print("Generated Key (A's side):", key_a)

    # B decapsulates the key sent by A
    key_b = Kyber512.decaps(sk_b, c_a)

    print("\nPerson B decapsulates the challenge:")
    print("Decapsulated Key (B's side):", key_b)

    # Check if the keys match
    assert key_a == key_b, "Keys do not match!"
    print("\nKey exchange successful! Shared key verified.")

    return key_a


def sign_message(sender, msg, sk_sig):
    print(f"\n--- {sender} Signing Message ---")
    print("Original Message:", msg)

    sig = Dilithium2.sign(sk_sig, msg.encode('utf-8'))

    print("Signature Generated:", sig)
    return sig


def verify_signature(receiver, msg, sig, pk_sig):
    print(f"\n--- {receiver} Verifying Signature ---")
    print("Received Message:", msg)
    print("Received Signature:", sig)

    verification = Dilithium2.verify(pk_sig, msg.encode('utf-8'), sig)

    print("Signature Verification Result:", verification)
    return verification


# Main logic
def main():
    print("=== Secure Communication Protocol Simulation ===")

    # Generate keypairs for both parties
    pk_a, sk_a, pk_a_sig, sk_a_sig = person_a_send_key()
    pk_b, sk_b, pk_b_sig, sk_b_sig = person_b_send_key()

    # Generate and verify shared key
    shared_key = generate_shared_key(pk_a, pk_b, sk_a, sk_b)
    print("\nShared Symmetric Key:", shared_key)

    # Person A sends a signed message to Person B
    message_a = "Hello, Person B. This is a secure message from A."
    signature_a = sign_message("Person A", message_a, sk_a_sig)

    is_valid_a = verify_signature("Person B", message_a, signature_a, pk_a_sig)
    print("\nSignature Verification Status (A's message):",
          "VALID" if is_valid_a else "INVALID")

    # Person B sends a signed message to Person A
    message_b = "Hi there, Person A. This is a secure response from B."
    signature_b = sign_message("Person B", message_b, sk_b_sig)

    is_valid_b = verify_signature("Person A", message_b, signature_b, pk_b_sig)
    print("\nSignature Verification Status (B's message):",
          "VALID" if is_valid_b else "INVALID")


if __name__ == "__main__":
    main()