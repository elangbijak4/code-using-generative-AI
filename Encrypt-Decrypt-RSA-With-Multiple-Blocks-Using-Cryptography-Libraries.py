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
    
    # Define the maximum length of each block
    max_block_length = 200
    
    # Encrypt the message in blocks
    encrypted_blocks = []
    for i in range(0, len(message), max_block_length):
        block = message[i:i+max_block_length]
        encrypted_block = public_key.encrypt(
            block.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_blocks.append(encrypted_block)
    
    return b''.join(encrypted_blocks)

def decrypt_message(private_key_file, encrypted):
    # Load private key from file
    private_key = load_private_key_from_file(private_key_file)
    
    # Decrypt the message
    decrypted_blocks = []
    block_size = private_key.key_size // 8
    for i in range(0, len(encrypted), block_size):
        encrypted_block = encrypted[i:i+block_size]
        decrypted_block = private_key.decrypt(
            encrypted_block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_blocks.append(decrypted_block)
    
    return b''.join(decrypted_blocks).decode()

if __name__ == "__main__":
    # File paths for private key and public key
    private_key_file = "private_key.pem"
    public_key_file = "public_key.pem"

    # Encrypt and decrypt a message
    message = "hfksdhfsdkjhf"
    print("Original message:", message)

    encrypted_message = encrypt_message(public_key_file, message)
    print("Encrypted message:", encrypted_message)

    decrypted_message = decrypt_message(private_key_file, encrypted_message)
    print("Decrypted message:", decrypted_message)
