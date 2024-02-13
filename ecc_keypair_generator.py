from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Generate ECC key pair
private_key = ec.generate_private_key(ec.SECP256R1())

# Extract public key
public_key = private_key.public_key()

# Serialize private key to PEM format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to PEM format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Print private and public keys
print("Private Key (PEM format):")
print(private_key_pem.decode('utf-8'))

print("\nPublic Key (PEM format):")
print(public_key_pem.decode('utf-8'))
