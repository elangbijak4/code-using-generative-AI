# Import library tinyec dan pycryptodome
from tinyec import registry
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import secrets
from tinyec import ec

# Fungsi untuk mengubah string menjadi objek point
def string_to_point(string, curve_name):
  # Pisahkan string menjadi dua bagian yang sama panjang
  half = len(string) // 2
  x_string = string[:half]
  y_string = string[half:]
  # Ubah x dan y dari heksadesimal menjadi integer
  x = int(x_string, 16)
  y = int(y_string, 16)
  # Dapatkan objek kurva eliptik dari registry
  curve = registry.get_curve(curve_name)
  # Buat objek point dengan kurva, x, dan y
  point = ec.Point(curve, x, y)
  # Kembalikan objek point
  return point

# Fungsi untuk mengubah string menjadi integer
def string_to_integer(string):
  # Ubah string dari heksadesimal menjadi integer
  integer = int(string, 16)
  # Kembalikan integer
  return integer

# Fungsi untuk mengubah string public key, string private key, dan curve name menjadi kunci publik dan kunci privat ECC
def get_ecc_private_key(private_key_string, curve_name):
  # Ubah string private key menjadi integer
  private_key = string_to_integer(private_key_string)
  # Kembalikan kunci publik dan privat ECC
  return private_key

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
# Berikan string public key, nama kurva eliptik yang Anda gunakan
private_key_string = "0fa1e98f25425693110756477ae706bc19c5d7a3d27dc2618da8b5eb8e7f5e40"
curve_name = "brainpoolP256r1"
# Ubah string menjadi kunci publik dan kunci privat ECC
private_key = get_ecc_private_key(private_key_string, curve_name)
# Baris ini memerlukan informasi tag, nonce dan ephemeral_public_key pada proses enkripsi sebelumnya, yang tersimpan di memori, yaitu ecc_encrypt_data.py
decrypted_message = "15f41509b72eaad2d1cb350794198d26e6fa777bea6a8c742621b1137b886a3e3200cd2957248d4faf038cced1148a92b2657c8ade5dcb3f2c8c1107c311c5ab"
# Dekripsi pesan dengan kunci privat ECC
decrypted_message = decrypt_ecc(ciphertext, tag, nonce, ephemeral_public_key, private_key)
# Cetak pesan yang didekripsi
print("Decrypted message:", decrypted_message)
