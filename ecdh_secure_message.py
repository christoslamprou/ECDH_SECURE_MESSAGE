from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

print("ECDH PROTOCOL – ALICE SENDS MESSAGE TO BOB\n")

# Bob creates a static key pair
bob_private_key = ec.generate_private_key(ec.SECP256R1())
bob_public_key = bob_private_key.public_key()

# Alice creates an ephemeral key pair
alice_private_key = ec.generate_private_key(ec.SECP256R1())
alice_public_key = alice_private_key.public_key()

# Alice creates a shared secret (prA + puB)
shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)

# Derive a 128-bit symmetric key using HKDF
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=16,
    salt=None,
    info=b'handshake data'
).derive(shared_secret)

# Alice encrypts the message using AES-GCM
plaintext = b"Hello Bob! This is Alice."
nonce = os.urandom(12)  # 12-byte nonce for AES-GCM
aesgcm = AESGCM(derived_key)
ciphertext = aesgcm.encrypt(nonce, plaintext, None)

# Alice sends ciphertext, nonce, and her public key
message_to_send = {
    "ciphertext": ciphertext,
    "nonce": nonce,
    "alice_public_bytes": alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
}

# Bob receives and loads Alice's public key
alice_public_key_received = serialization.load_pem_public_key(
    message_to_send["alice_public_bytes"]
)

# Bob creates the same shared secret (prB + puA)
shared_secret_bob = bob_private_key.exchange(ec.ECDH(), alice_public_key_received)

# Bob derives the same symmetric key using HKDF
derived_key_bob = HKDF(
    algorithm=hashes.SHA256(),
    length=16,
    salt=None,
    info=b'handshake data'
).derive(shared_secret_bob)

# Bob decrypts the message using AES-GCM
aesgcm_bob = AESGCM(derived_key_bob)
decrypted_message = aesgcm_bob.decrypt(
    message_to_send["nonce"],
    message_to_send["ciphertext"],
    None
)

print(f"Message received by Bob: {decrypted_message.decode()}")