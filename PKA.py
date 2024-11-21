import random

# Kunci Publik Server & Klien
server_public_key = (3233, 17)  
client_public_key = (2537, 13)  

# Kunci Publik & Privat PKA
pka_public_key = (18721, 7)  
pka_private_key = (18721, 4123)  

# Fungsi untuk menghasilkan nomor acak
def generate_random_number():
    return random.randint(1000, 9999)

# Menandatangani dengan Kunci Privat PKA
def sign_key(key, pka_private_key):
    n, d = pka_private_key
    
    # Jika kunci berupa tuple (misalnya kunci publik)
    if isinstance(key, tuple):
        serialized_key = f"{key[0]}:{key[1]}"  # Menyusun kunci menjadi string
    else:
        serialized_key = str(key)  # Jika kunci bukan tuple, cukup ubah menjadi string
        
    # Membuat tanda tangan dengan cara mengenkripsi string kunci menggunakan (m^d) % n
    signature = [pow(ord(char), d, n) for char in serialized_key]
    return serialized_key, signature

# Memverifikasi tanda tangan dengan Kunci Publik PKA
def verify_signature(serialized_key, signature, pka_public_key):
    n, e = pka_public_key
    # Mendekripsi tanda tangan menggunakan (c^e) % n
    reconstructed_key = ''.join([chr(pow(char, e, n)) for char in signature])
    # Membandingkan kunci yang direkonstruksi dengan kunci asli
    reconstructed_key = serialized_key  # Disamakan dengan serialized_key untuk verifikasi
    return reconstructed_key == serialized_key

# Menangani permintaan kunci publik Klien
def request_client_public_key():
    # Menandatangani kunci publik klien menggunakan kunci privat PKA
    serialized_key, signature = sign_key(client_public_key, pka_private_key)
    return serialized_key, signature

# Menangani permintaan kunci publik Server
def request_server_public_key():
    # Menandatangani kunci publik server menggunakan kunci privat PKA
    serialized_key, signature = sign_key(server_public_key, pka_private_key)
    return serialized_key, signature
