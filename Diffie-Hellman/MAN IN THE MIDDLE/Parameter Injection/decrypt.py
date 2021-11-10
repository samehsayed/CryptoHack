from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib


p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 0x02 
A = 0xa6874a5cdcfb0af86d227826d6c331b51c68fb0caffdbbfb4bd2f9977166668cab15838dcf8a065857eda7b798b30acad41fafff242af8051416dfb70a7662235179215802587c8267eb6605e51598069fba9eb26ae2a6d77326eac2ad9b7f53e80db3a0a6dbe0f9be61d9f87158085cf5b0e87ddcea88d880fbea5d0868dbe500471aa3f6ff9540c42700e725230302c3b9faf262d5f5761feffc2ad1e55ac83a0100a9b4d88c0dcbe40b7b9fe2e99a5e6b1a43f1920e27fb6c42fd5d37cdd3
B = 0xb53ef21117ee1938a00d2639e14c487c8dbb95694f973e2dc1608a058e474b03729af5fbc193cc3a03dd54daf8c7d1475e16e90addcd0a4cec9987fbb8211768ce85a5d192e7374e87b7f0e63315a70144b0745d2405d154d7d5941ab19265d6fdd45f0f2ea5286f011a30cf26ed05cac3375571b3e449682616b7d945d1048659c9ee08d0bfb9709f4164e4bc1372b91ebd23fa74c1592738d3d16ffe249b6027e203956f8fe42e9513d7f66f10f10ed701aae5d50a6bfcf6c127e3f05544a3






def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

msg = {"iv": "2a8c1d596fd509b2f91d3384186f46a6", "encrypted_flag": "d396541109d474d8c63eb0b3e4841222a5d15a8ce80ae83f1766c8341159a429"}

shared_secret = 0
iv = msg['iv']
ciphertext = msg['encrypted_flag']

print(decrypt_flag(shared_secret, iv, ciphertext))
