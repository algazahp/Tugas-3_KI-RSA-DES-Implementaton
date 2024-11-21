def rsa_encrypt(message, public_key):
    # Extract the modulus (n) and exponent (e) from the public key
    n, e = public_key
    # Convert the message into an integer using ord() and encrypt using (m^e) % n
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message

def rsa_decrypt(encrypted_message, private_key):
    # Extract the modulus (n) and exponent (d) from the private key
    n, d = private_key
    # Decrypt each integer back to characters using (c^d) % n
    decrypted_message = ''.join([chr(pow(char, d, n)) for char in encrypted_message])
    return decrypted_message