# contoh_qrcode.py
import qrcode

# Membuat objek qrcode
qr = qrcode.QRCode()

# Menambahkan data ke objek qrcode
qr.add_data("Hello, World")

# Membuat qrcode
img = qr.make_image()

# Menyimpan qrcode sebagai gambar PNG
img.save("hello_world.png")

# Menampilkan gambar qrcode
img
