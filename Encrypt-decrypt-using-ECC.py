# Import library yang dibutuhkan
from tinyec import registry
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os, secrets

# Fungsi untuk menghasilkan kunci publik dan privat ECC
def generate_ecc_keys():
  # Pilih kurva eliptik yang diinginkan, misalnya brainpoolP256r1
  curve = registry.get_curve('brainpoolP256r1')
  # Buat kunci privat ECC secara acak
  private_key = secrets.randbelow(curve.field.n)
  # Buat kunci publik ECC dengan mengalikan kunci privat dengan generator point
  public_key = private_key * curve.g
  # Kembalikan kunci publik dan privat ECC
  return public_key, private_key

# Fungsi untuk mengenkripsi pesan dengan kunci publik ECC
def encrypt_ecc(message, public_key):
  # Pilih kurva eliptik yang sama dengan kunci publik
  curve = registry.get_curve(public_key.curve.name)
  # Buat kunci privat sementara (ephemeral) secara acak
  ephemeral_private_key = secrets.randbelow(curve.field.n)
  # Buat kunci publik sementara dengan mengalikan kunci privat sementara dengan generator point
  ephemeral_public_key = ephemeral_private_key * curve.g
  # Hitung kunci ECC yang dibagi dengan mengalikan kunci publik ECC dengan kunci privat sementara
  shared_ecc_key = ephemeral_private_key * public_key
  # Ubah kunci ECC yang dibagi menjadi kunci AES dengan menggunakan fungsi hash SHA256
  shared_aes_key = SHA256.new(shared_ecc_key.x.to_bytes(32, 'big')).digest()
  # Buat objek AES dengan mode GCM (Galois Counter Mode) yang mendukung autentikasi
  aes = AES.new(shared_aes_key, AES.MODE_GCM)
  # Enkripsi pesan dengan AES dan dapatkan ciphertext dan tag autentikasi
  ciphertext, tag = aes.encrypt_and_digest(message.encode('utf-8'))
  # Kembalikan ciphertext, tag, nonce, dan kunci publik sementara
  return ciphertext, tag, aes.nonce, ephemeral_public_key

# Fungsi untuk mendekripsi pesan dengan kunci privat ECC
def decrypt_ecc(ciphertext, tag, nonce, ephemeral_public_key, private_key):
  # Hitung kunci ECC yang dibagi dengan mengalikan kunci publik sementara dengan kunci privat ECC
  shared_ecc_key = private_key * ephemeral_public_key
  # Ubah kunci ECC yang dibagi menjadi kunci AES dengan menggunakan fungsi hash SHA256
  shared_aes_key = SHA256.new(shared_ecc_key.x.to_bytes(32, 'big')).digest()
  # Buat objek AES dengan mode GCM dan nonce yang diberikan
  aes = AES.new(shared_aes_key, AES.MODE_GCM, nonce=nonce)
  # Dekripsi ciphertext dengan AES dan verifikasi tag autentikasi
  message = aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')
  # Kembalikan pesan yang didekripsi
  return message

# Contoh penggunaan fungsi-fungsi di atas
# Buat kunci publik dan privat ECC untuk penerima pesan
receiver_public_key, receiver_private_key = generate_ecc_keys()
# Buat pesan yang ingin dikirim
message = "Halo, ini adalah pesan rahasia"
# Enkripsi pesan dengan kunci publik ECC penerima
ciphertext, tag, nonce, ephemeral_public_key = encrypt_ecc(message, receiver_public_key)
# Cetak ciphertext dan kunci publik sementara dalam bentuk heksadesimal
print("Ciphertext:", ciphertext.hex())
print("Ephemeral public key:", ephemeral_public_key.x.to_bytes(32, 'big').hex() + ephemeral_public_key.y.to_bytes(32, 'big').hex())
# Dekripsi pesan dengan kunci privat ECC penerima
decrypted_message = decrypt_ecc(ciphertext, tag, nonce, ephemeral_public_key, receiver_private_key)
# Cetak pesan yang didekripsi
print("Decrypted message:", decrypted_message)
