from sympy.ntheory import discrete_log
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

p = "0xde26ab651b92a129"
g = "0x2"
A ="0x23ff9f76d72d4d5c"
B ="0x528eea9658883db4"
iv ="fa6dbbdaf5c8121452ed2f6ba61aa6a8"
encrypted_flag = "e5f501e79538167d39fbcb043237c857345d56a802871a25b593e60fa05ea393"
g=int(g,16)
A=int(A,16)
B=int(B,16)
p=int(p,16)

def decrypt_flag(secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext)

x= (discrete_log(p,A,g))
secret = pow(B,x,p)

print (secret)
decrypt_flag(secret,iv,encrypted_flag)