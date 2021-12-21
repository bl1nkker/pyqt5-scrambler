# import hashlib
# tx = 'Hello World!'
# md5 = hashlib.md5(f'{tx}'.encode())
# sha256 = hashlib.sha256(b'Hello World')
# print(md5.hexdigest())
# print(sha256.hexdigest())

import rsa
from rsa import PublicKey
text = 'Hello World'
message = text.encode()
hash = rsa.compute_hash(message, 'SHA-256')

(pubkey, privkey) = rsa.newkeys(512)
A = rsa.sign_hash(hash, privkey, 'SHA-256')
A1 = A.decode('utf-8', errors='ignore')
print(pubkey)
print(pubkey.e)
print(pubkey.n)
text = 'Hello World'
message = text.encode()
B = rsa.verify(message, A, pubkey)
B1 = str(B)
print(B1)

alphabet = "abcdefghijklmnopqrstuvwxyz "
letter_to_index = dict(zip(alphabet, range(len(alphabet))))
index_to_letter = dict(zip(range(len(alphabet)), alphabet))


# def encrypt(message, shift=3):
#     cipher = ""
#
#     for letter in message:
#         number = (letter_to_index[letter] + shift) % len(letter_to_index)
#         letter = index_to_letter[number]
#         cipher += letter
#
#     return cipher
#
#
# def decrypt(cipher, shift=3):
#     decrypted = ""
#
#     for letter in cipher:
#         number = (letter_to_index[letter] - shift) % len(letter_to_index)
#         letter = index_to_letter[number]
#         decrypted += letter
#
#     return decrypted
#
#
# def main():
#      message = 'attack at noon'
#      encrypted_message = encrypt(message, shift=3)
#      decrypted_message = decrypt(encrypted_message, shift=3)
#
#      print('Original message: ' + message)
#      print('Encrypted message: ' + encrypted_message)
#      print('Decrypted message: ' + decrypted_message)
#
# main()