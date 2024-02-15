from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    return private_key, public_key

def write_private_key_to_file(private_key, filename):
    # Serialize private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Write private key to file
    with open(filename, "wb") as key_file:
        key_file.write(private_key_pem)

def write_public_key_to_file(public_key, filename):
    # Serialize public key
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write public key to file
    with open(filename, "wb") as key_file:
        key_file.write(public_key_pem)

if __name__ == "__main__":
    private_key, public_key = generate_rsa_key_pair()
    
    # Write private key to file
    write_private_key_to_file(private_key, "private_key.pem")
    print("Private key has been written to private_key.pem")
    
    # Write public key to file
    write_public_key_to_file(public_key, "public_key.pem")
    print("Public key has been written to public_key.pem")

# Serialize private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    print("Private key:")
    print(private_key_pem.decode())
    print("\nPublic key:")
    print(public_key_pem.decode())
