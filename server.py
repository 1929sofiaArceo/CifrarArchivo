import socket
import nacl.secret
import nacl.utils
from nacl.signing import SigningKey
from Crypto.Cipher import AES

SIZE = 1024
FORMAT = "utf-8"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 3000))
fileRecieved = s.recv(SIZE).decode(FORMAT)
print("File recieved succesfully")
key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
cipher = AES.new(key, AES.MODE_EAX)
cipher_text, tag = cipher.encrypt_and_digest(bytes(fileRecieved, FORMAT))
encryptedFile = open("encrypedFile.bin", "wb")
[encryptedFile.write(x) for x in (cipher.nonce, tag, cipher_text)]
encryptedFile.close()
print("Encoding file")
print(cipher_text)
print("Tag")
print(tag)
signingKey = SigningKey.generate() # Generamos un random signing key
signedFile = signingKey.sign(cipher_text) # Firmamos archivo encriptado con el signing key
print("Signed File...")
print(signedFile)
verify_key = signingKey.verify_key
print("Vericicando firma")
print(verify_key)
print("Decoding file...")
file = open("encrypedFile.bin", "rb")
nonce, tag, ciphertext = [file.read(x) for x in (16, 16, -1)]
cipher = AES.new(key, AES.MODE_EAX, nonce)
content = cipher.decrypt_and_verify(ciphertext, tag)
print(content)
