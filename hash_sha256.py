# Meng-import pustaka hashlib
import hashlib

# Membuat string yang ingin di-hash
string_to_hash = "Hello, world!"

# Membuat objek hash SHA256
hash_object = hashlib.sha256()

# Menambahkan data string ke objek hash
hash_object.update(string_to_hash.encode())

# Mendapatkan nilai hash dalam format heksadesimal
hex_digest = hash_object.hexdigest()

# Mencetak nilai hash
print("Nilai hash dari string adalah:", hex_digest)
