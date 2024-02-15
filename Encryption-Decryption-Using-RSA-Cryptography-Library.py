from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def load_private_key_from_file(private_key_file):
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_public_key_from_file(public_key_file):
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def encrypt_message(public_key_file, message):
    # Load public key from file
    public_key = load_public_key_from_file(public_key_file)
    
    # Encrypt the message
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted

def decrypt_message(private_key_file, encrypted):
    # Load private key from file
    private_key = load_private_key_from_file(private_key_file)
    
    # Decrypt the message
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted.decode()

if __name__ == "__main__":
    # File paths for private key and public key
    private_key_file = "private_key.pem"
    public_key_file = "public_key.pem"

    # Encrypt and decrypt a message
    message = "kdsjfdfhksjdksfhdskfhhfffffffffffffffffffffffffffffffffffffffffffff';'fffffffffffffffffffffffffffffffffffffffffff"
    print("Original message:", message)

    encrypted_message = encrypt_message(public_key_file, message)
    print("Encrypted message:", encrypted_message)

    decrypted_message = decrypt_message(private_key_file, encrypted_message)
    print("Decrypted message:", decrypted_message)
