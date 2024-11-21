import socket
from DES import des_encrypt, des_decrypt, key as Des_Key
from RSA import rsa_encrypt, rsa_decrypt
from PKA import generate_random_number, request_server_public_key, pka_public_key, verify_signature, sign_key

# Kunci untuk Klien
client_public_key = (2537, 13)  # (n, e)
client_private_key = (2537, 937)  # (n, d)

def client_program():
    host = socket.gethostname()  
    port = 5050  # nomor port server socket

    client_socket = socket.socket()  # instansiasi socket
    client_socket.connect((host, port))

    # Meminta kunci publik server dari PKA
    serialized_key, signature = request_server_public_key()
    print("Menerima kunci publik server (dari PKA): ", serialized_key)
    print("Menerima Tanda Tangan (dari PKA): ", signature)

    # Memverifikasi tanda tangan menggunakan kunci publik PKA
    if verify_signature(serialized_key, signature, pka_public_key):
        print("Kunci publik server berhasil diverifikasi.")
        print("Kunci publik server yang diterima: ", serialized_key)
        print("Tanda Tangan yang diterima: ", signature)

        server_key_parts = serialized_key.split(":")
        server_public_key = (int(server_key_parts[0]), int(server_key_parts[1]))
        print("Kunci Publik Server yang Diverifikasi:", server_public_key)
        
    else:
        print("Gagal memverifikasi kunci publik server. Menghentikan koneksi.")
        client_socket.close()
        return

    
    encrypted_N1 = list(map(int, client_socket.recv(1024).decode().split(',')))
    print("Menerima encrypted N1 (Dari server): ", encrypted_N1)

    decrypted_N1 = rsa_decrypt(encrypted_N1, client_private_key)
    print("Klien mendekripsi N1:", decrypted_N1)

    N2 = generate_random_number()
    print("Menghasilkan nomor acak N2: ", N2)

    encrypted_N1_back = rsa_encrypt(decrypted_N1, server_public_key)
    print("Encrypted N1 lagi: ", encrypted_N1_back)
    encrypted_N1_back = ','.join(map(str, encrypted_N1_back))

    encrypted_N2 = rsa_encrypt(str(N2), server_public_key)
    print("Encrypted N2: ", encrypted_N2)
    encrypted_N2 = ','.join(map(str, encrypted_N2))

    client_socket.send(encrypted_N1_back.encode())
    client_socket.send(encrypted_N2.encode())
    print("Status: N1 dan N2 telah dikirim ke Server")

    received_data = list(map(int, client_socket.recv(1024).decode().split(',')))
    print("Menerima Encrypted N2 (Dari server): ", received_data)
    decrypted_N2_back = rsa_decrypt(received_data, client_private_key)
    print("Mendekripsi N2 (dari server): ", decrypted_N2_back)

    if decrypted_N2_back == str(N2):
        print("Handshaking berhasil!")
    else:
        print("Handshaking gagal!")
        client_socket.close()
        return

    
    print("Mendapatkan Kunci Des: ", Des_Key)
    des_key, des_signature = sign_key(Des_Key, client_private_key)
    des_key_str = str(des_key)
    des_signature_str = ','.join(map(str, des_signature))
        
    client_socket.send(des_key_str.encode())
    client_socket.send(des_signature_str.encode())

    encrypted_des_key = rsa_encrypt(Des_Key, server_public_key)
    print("Encrypted Des Key: ", encrypted_des_key)
        
    encrypted_des_key = ','.join(map(str, encrypted_des_key))
    client_socket.send(encrypted_des_key.encode())
    
    
    while True:
        # Mengambil input pengguna, mengenkripsi, dan mengirimnya
        message = input("masukkan pesan: ")
        if message.lower().strip() == 'stop':
            break
        encrypted_message_sent = des_encrypt(message, Des_Key)
        client_socket.send(encrypted_message_sent.encode())
        # Menerima balasan terenkripsi dari server dan mendekripsinya
        data = client_socket.recv(1024).decode()
        # encrypted_message_received = des_encrypt(data, key)
        decrypted_data = des_decrypt(data, Des_Key)
        encrypted_binary = ''.join(format(ord(c), '08b') for c in data)
        print("Pesan terenkripsi yang diterima dari server (biner) :", encrypted_binary)
        print("Diterima dari server (setelah dekripsi): " + decrypted_data)

    client_socket.close()


if __name__ == '__main__':
    client_program()
