# Import library tinyec
from tinyec import registry

# Fungsi untuk menampilkan list nama kurva eliptik
def show_curve_names():
  # Dapatkan list nama kurva eliptik dari EC_CURVE_REGISTRY
  curve_names = registry.EC_CURVE_REGISTRY.keys()
  # Cetak list nama kurva eliptik
  print("List nama kurva eliptik:")
  for name in curve_names:
    print(name)

# Contoh penggunaan fungsi di atas
show_curve_names()
