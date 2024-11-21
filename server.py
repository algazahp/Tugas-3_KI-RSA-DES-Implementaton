import socket
from DES import des_encrypt, des_decrypt
from RSA import rsa_encrypt, rsa_decrypt
from PKA import generate_random_number, verify_signature, pka_public_key, request_client_public_key

# Kunci 
server_public_key = (3233, 17)
server_private_key = (3233, 2753)

def server_program():
    host = socket.gethostname()  # Mendapatkan nama host
    port = 5050  # Menetapkan nomor port di atas 1024

    server_socket = socket.socket()  # Membuat instance socket
    server_socket.bind((host, port))  # Mengikat alamat host dan port bersama

    server_socket.listen(1)
    print("Server sedang mendengarkan...")

    conn, address = server_socket.accept()  # Menerima koneksi baru
    print("Koneksi dari: " + str(address))

    # Server meminta kunci publik klien dari PKA
    serialized_key, signature = request_client_public_key()
    print("Menerima kunci publik klien (dari PKA): ", serialized_key)
    print("Menerima Tanda Tangan (dari PKA): ", signature)

    # Memverifikasi tanda tangan menggunakan kunci publik PKA
    if verify_signature(serialized_key, signature, pka_public_key):
        print("Kunci publik klien berhasil diverifikasi.")

        client_key_parts = serialized_key.split(":")
        client_public_key = (int(client_key_parts[0]), int(client_key_parts[1]))
        print("Kunci Publik Klien yang Diverifikasi:", client_public_key)

    else:
        print("Gagal memverifikasi kunci publik klien. Menghentikan koneksi.")
        conn.close()
        return

    # Memulai protokol handshake
    
    N1 = generate_random_number()
    print("Menghasilkan nomor acak N1: ", N1)
    encrypted_N1 = rsa_encrypt(str(N1), client_public_key)
    print("Encrypted N1:", encrypted_N1)

    encrypted_N1 = ','.join(map(str, encrypted_N1))
    conn.send(encrypted_N1.encode())
    print("Status: Mengirim encrypted N1 ke klien dan menunggu respons dari klien")

    received_encrypted_N1 = list(map(int, conn.recv(1024).decode().split(',')))
    print("Menerima Encrypted N1 (dari klien): ", received_encrypted_N1)

    received_encrypted_N2 = list(map(int, conn.recv(1024).decode().split(',')))
    print("Encrypted N2 (dari klien): ", received_encrypted_N2)

    decrypted_N2 = rsa_decrypt(received_encrypted_N2, server_private_key)
    print("Mendekripsi N2: ", decrypted_N2)

    encrypted_N2_back = rsa_encrypt(str(decrypted_N2), client_public_key)
    print("Encrypted N2: ", encrypted_N2_back)
    encrypted_N2_back = ','.join(map(str, encrypted_N2_back))
    conn.send(encrypted_N2_back.encode())
    print("Status: Mengirim N2 kembali ke klien")

    decrypted_N1_back = rsa_decrypt(received_encrypted_N1, server_private_key)
    print("Mendekripsi N1: ", decrypted_N1_back)
    if decrypted_N1_back == str(N1):
        print("Handshake berhasil!")
    else:
        print("Handshake gagal!")
        conn.close()
        return

    
    des_key = conn.recv(1024).decode()
    des_signature_str = conn.recv(1024).decode()
    des_signature = [int(x) for x in des_signature_str.split(',')]

    received_encrypted_des_key = list(map(int, conn.recv(1024).decode().split(',')))
    print("Menerima Encrypted Des Key (dari klien): ", received_encrypted_des_key)

    decrypted_des_key = rsa_decrypt(received_encrypted_des_key, server_private_key)
    print("Mendekripsi Des Key yang Diterima: ", decrypted_des_key)

    # Memverifikasi tanda tangan menggunakan kunci publik klien
    if verify_signature(des_key, des_signature, client_public_key):
        print("Des key berhasil diverifikasi.")

    else:
        print("Gagal memverifikasi kunci Des. Menghentikan koneksi.")
        conn.close()
        return

    
    while True:
        data = conn.recv(1024).decode()  # Menerima pesan terenkripsi dari klien
        if not data:
            break

        # Mendekripsi data yang diterima
        encrypted_binary = ''.join(format(ord(c), '08b') for c in data)
        print("Pesan terenkripsi yang diterima dari Klien (biner) :", encrypted_binary)

        decrypted_message = des_decrypt(data, des_key)
        print("Diterima dari klien (setelah dekripsi): " + decrypted_message)

        # Mendapatkan balasan server, mengenkripsi, dan mengirimkannya kembali ke klien
        server_reply = input("masukkan pesan: ")
        encrypted_reply = des_encrypt(server_reply, des_key)
        conn.send(encrypted_reply.encode())  

    conn.close()  


if __name__ == '__main__':
    server_program()
