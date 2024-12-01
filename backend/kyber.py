import random
import numpy as np

# Kyber Parameters for Kyber512
N = 256  # Degree of polynomial
Q = 3329  # Modulus
ETA = 2  # Error distribution parameter
POLY_SIZE = N

# Helper function to generate random polynomials
def gen_poly():
    return np.random.randint(-ETA, ETA, POLY_SIZE)

# Polynomial multiplication (mod Q)
def poly_mult(a, b):
    result = np.zeros(2 * POLY_SIZE - 1, dtype=int)
    for i in range(POLY_SIZE):
        for j in range(POLY_SIZE):
            result[i + j] += a[i] * b[j]
            result[i + j] %= Q
    return result[:POLY_SIZE]

# Polynomial addition (mod Q)
def poly_add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]

# Polynomial scaling (mod Q)
def poly_scale(a, scalar):
    return [(x * scalar) % Q for x in a]

# Key Generation (Alice)
def generate_keypair():
    s = gen_poly()  # Secret key polynomial s
    e = gen_poly()  # Error polynomial e
    A = [gen_poly() for _ in range(POLY_SIZE)]  # Random public matrix A
    b = [poly_add(poly_mult(A[i], s), e) for i in range(POLY_SIZE)]  # b = A * s + e
    return (b, s)  # Public key b and private key s

# Encryption (Bob)
def encrypt(message, public_key):
    b = public_key  # Public key is a list of polynomials
    r1 = gen_poly()  # Random polynomial r1
    r2 = gen_poly()  # Random polynomial r2
    c1 = [poly_mult(r1, b_i) for b_i in b]
    c2 = poly_add(poly_add(r2, message), c1[0])  # Take the first result from c1
    return (c1, c2)

# Decryption (Alice)
def decrypt(ciphertext, private_key):
    c1, c2 = ciphertext
    s = private_key
    c1_s = poly_mult(c1[0], s)  # Use the first polynomial from c1
    m = poly_add(c2, [-x for x in c1_s])
    return m

# Key Encapsulation (KEM) - Alice generates a shared secret
def kem_encapsulation(public_key):
    b = public_key
    r = gen_poly()
    c = [poly_add(poly_mult(r, b_i), gen_poly()) for b_i in b]
    shared_secret = sum(c[0]) % Q  # Simplified shared secret derivation using the first ciphertext result
    return c, shared_secret

# Key Decapsulation (KEM) - Bob recovers the shared secret
def kem_decapsulation(ciphertext, private_key):
    c = ciphertext
    s = private_key
    c_s = poly_mult(c[0], s)  # Use the first polynomial from c
    shared_secret = sum(c_s) % Q
    return shared_secret

# Function to convert user message (string) to a polynomial representation
def message_to_poly(message):
    return [ord(c) for c in message] + [0] * (POLY_SIZE - len(message))

# Function to convert polynomial back to message (for decryption)
def poly_to_message(poly):
    return ''.join(chr(x) for x in poly[:POLY_SIZE] if 0 <= x <= 127)

# Key Generation
alice_public_key, alice_private_key = generate_keypair()
bob_public_key, bob_private_key = generate_keypair()

# Accept user input for message to be encrypted
print("Please enter a message to encrypt:")
user_message = input()

if user_message.strip() == "":
    print("No message entered! Please try again.")
else:
    message_poly = message_to_poly(user_message)

    # Debugging: Print the message polynomial
    print("Message Polynomial:", message_poly[:10])

    # Encryption: Bob encrypts the message using Alice's public key
    ciphertext = encrypt(message_poly, alice_public_key)

    # Decryption: Alice decrypts the ciphertext using her private key
    decrypted_message_poly = decrypt(ciphertext, alice_private_key)

    # Convert the decrypted polynomial back to a string message
    decrypted_message = poly_to_message(decrypted_message_poly)

    # Print Results
    print("Original Message:", user_message)
    print("Decrypted Message:", decrypted_message)

    # KEM: Key Encapsulation and Decapsulation
    ciphertext_kem, shared_secret_enc = kem_encapsulation(alice_public_key)
    shared_secret_dec = kem_decapsulation(ciphertext_kem, bob_private_key)

    print("Shared Secret Encapsulation:", shared_secret_enc)
    print("Shared Secret Decapsulation:", shared_secret_dec)