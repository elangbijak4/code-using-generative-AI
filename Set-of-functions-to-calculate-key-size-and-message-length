from cryptography.hazmat.primitives import serialization

def get_key_size_from_file(key_file, key_type):
    with open(key_file, "rb") as f:
        key_data = f.read()
        if key_type == 'private':
            key = serialization.load_pem_private_key(key_data, password=None)
        elif key_type == 'public':
            key = serialization.load_pem_public_key(key_data)
        key_size = key.key_size
    return key_size

# Function to calculate the maximum number of characters
def calculate_max_characters(key_size):
    # Subtracting overhead padding and converting bits to bytes
    max_encryption_length = (key_size - 42) // 8
    return max_encryption_length

# Function to calculate the key_size from a given message
def calculate_key_size_for_message(message, overhead_padding=42, margin=16):
    # Calculate the number of characters in the message
    character_count = len(message)

    # Calculate the total size needed for encryption
    total_size_needed = character_count + overhead_padding

    # Converting the total size needed to bits
    total_size_bits = total_size_needed * 8

    # Adding the margin
    required_key_size = total_size_bits + margin

    return character_count, required_key_size

# Function to calculate key_size from the given number of characters
def calculate_key_size_for_character_count(character_count, overhead_padding=42, margin=16):
    # Calculate the total size needed for encryption
    total_size_needed = character_count + overhead_padding

    # Converting the total size needed to bits
    total_size_bits = total_size_needed * 8

    # Adding the margin
    required_key_size = total_size_bits + margin

    return required_key_size

if __name__ == "__main__":
    # File paths for private key and public key
    private_key_file = "private_key.pem"
    public_key_file = "public_key.pem"

    # Get key sizes
    private_key_size = get_key_size_from_file(private_key_file, 'private')
    public_key_size = get_key_size_from_file(public_key_file, 'public')

    print("Private key size:", private_key_size, "bits")
    print("Public key size:", public_key_size, "bits")

    max_encryption_length = (private_key_size - 42) // 8
    print("max_encryption_length:", max_encryption_length, "bits")

    # Calculate maximum number of characters
    max_characters = calculate_max_characters(private_key_size)

    print("Key size:", private_key_size, "bits")
    print("Max encryption length:", max_characters, "bytes")
    print("Max number of ASCII characters:", max_characters)

    # Calculates the required key_size of a given message
    message = "This is a sample message."

    character_count, required_key_size = calculate_key_size_for_message(message)
    print("Message:", message)
    print("Character count:", character_count)
    print("Required key size for encrypting the message:", required_key_size, "bits")

    # Calculates the required key_size of a given number of characters
    character_count = 100  # Example character count

    required_key_size = calculate_key_size_for_character_count(character_count)
    print("Required key size for encrypting a message with", character_count, "characters:", required_key_size, "bits")
