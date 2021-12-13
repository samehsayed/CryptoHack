from sympy.ntheory import discrete_log
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

p = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff" 
g = "0x02"
A = "0x9bddb111d80420274e1220fb2b3e099d80b8897d5f8bd67b62f1df9ee441c376aab6f4f9626300b1c7844361ae92c8bc0c5f0e869786e5249fde6d77fd18681c9a85c298814f3445c7f6421f101cab1d98a95639974c8df1e951b6424241419ad9fdce0dcc87a6e6e5050bcc555333fa3e656cf5ccaeb0a74e5c713f020209c1624ee0a656cf3eeb0356daffb682bf8ca2989741a530d89245ab05b4cb1bab98625da7ab7a3fad0cb18426f0fb47c15b1560f8f24dd770a662c380688ff109b"
B = "0x729352a1abb0ac2d4d6c9b38fcea27b6f60cd7860cf68d4a8cd7ed45fb8e0539e6af5f9dde4897867cc323d5cdc420e5460735f2a74b3432273c725543bc7fcb8b300362d4137ac0bfaacd242860e1a965d162806b4ebe74e0af79597244bbe0104d4387a8e52ac8a0d75bbff400cdad384633884b8bfbd96175bc11b9eaca08cdbef536c76fa66c01dddf3df5ff740cec7d3f49a6a305cfe7c2f71f010d7053c4f30e218673eaef11d88b73a68a1a7b76a9a86e360d5e765611a10abe31af6c"
msg = {"iv": "011e2abe7d0ef819df3aacfac2af213a", "encrypted": "faebe9c2b82b8764600a43493760486e8a6465eb0492cd89ebd105b59a43c0ab7fdd2082a00dc97a99f20a8409cc073e"}


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

print(decrypt_flag(shared_secret,iv,ciphertext))