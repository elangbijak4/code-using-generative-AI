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

# Tambahan
# Fungsi untuk mengubah string public key, string private key, dan curve name menjadi kunci publik dan kunci privat ECC
def get_ecc_public_key(public_key_string,curve_name):
  # Ubah string public key menjadi objek point
  public_key = string_to_point(public_key_string, curve_name)
  # Kembalikan kunci publik ECC
  return public_key

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

# Berikan string public key, string private key, dan nama kurva eliptik yang Anda gunakan
public_key_string = "2a40d80e739f163bde8f2bd471a637f9ec6f17cf0e78fe497c7ea40d90e84b62955ce37843a0c7a5e10a630c4d2e1e8199c9c15d208cfa4d4692298818510e68"
curve_name = "brainpoolP256r1"
# Ubah string menjadi kunci publik dan kunci privat ECC
public_key = get_ecc_public_key(public_key_string, curve_name)
# Buat pesan yang ingin dikirim
message = "0c961e7140b8187130d340a19845f0ea16a2df13c6fdf2753240062682b859f8"
# Enkripsi pesan dengan kunci publik ECC
ciphertext, tag, nonce, ephemeral_public_key = encrypt_ecc(message, public_key)
# Cetak ciphertext dan kunci publik sementara dalam bentuk heksadesimal
print("Ciphertext:", ciphertext.hex())
print("Ephemeral public key:", ephemeral_public_key.x.to_bytes(32, 'big').hex() + ephemeral_public_key.y.to_bytes(32, 'big').hex())
