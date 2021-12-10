from sympy.ntheory import discrete_log
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
"""""
p= "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
g=  "0x2"
A= "0x887225a1a9f548303b3e555eae076118dba1ffb06e858b5f470da97f22dc94191bca8644a7b8f48bbba602cb8551255fe3b6aa43f1d75e58a7644ab9cdb0a40827cefc6871376f05685a4551863689ecfb909772178c245f924173fe72bab844e152cbed66572029015842e2fabdb93416fe3be142c1f8200d1d2d6fb2af211f2c62c69af5526ddae99ec34704bb58420140327f7058bfc15d440f6593e92940d108044eccc260b2deb52bc995e2445bafcba5ef2179e2ec24b0ce1d6a98bf4d"
B= "0x8d79b69390f639501d81bdce911ec9defb0e93d421c02958c8c8dd4e245e61ae861ef9d32aa85dfec628d4046c403199297d6e17f0c9555137b5e8555eb941e8dcfd2fe5e68eecffeb66c6b0de91eb8cf2fd0c0f3f47e0c89779276fa7138e138793020c6b8f834be20a16237900c108f23f872a5f693ca3f93c3fd5a853dfd69518eb4bab9ac2a004d3a11fb21307149e8f2e1d8e1d7c85d604aa0bee335eade60f191f74ee165cd4baa067b96385aa89cbc7722e7426522381fc94ebfa8ef0"
we will send to bob intercepted A as g , 
We send to bob {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x8388bedc55013b2a79cf60222652fbe0cdb973213432ac4c114cbc16d8113777ebdf07cff7c7831e7849b7b039bc96fab0469c2333021b5b694617e8a45acee58ac50b1fb5cb2e84535e8c79ab11bf0bd76018650b097cd20f6b840c21362c0252ac759ff90bd3dd244f22b1551f0e0958b1ec1a7d75105169a333fe067c4c5a59c42a29c7e1c87bde3179065d3650681be868bd334bf2a84e4d2e51b79c5dfc2a6162f98d13c36984749358326c65ec4303fa8cd0e135691f99f0031fec7684", "A": "0x8388bedc55013b2a79cf60222652fbe0cdb973213432ac4c114cbc16d"}
"""""
shared_secret = 0xe42110a8e71e2c6eb9fc73392c5b4e8e84a4a0bff195b8d4d7a33101d2cc65ee0a6ac59845e123f560388ce036147976c91e758c61cc11f748ae009aa411c7cbe2290fda277e49d3889cbd1aea445d6f6ca803279c56e5d456998c048e080bbac1ab6ed3923617d8fa3c7445554161bf7d93a23538786fa574f410728c8f0207ff3e37e6f3f7eb903e4318a9b33da13f18f6fca84238a5c9d0bc2e4eb160fa4b16baba813567eea4cbb55b88c1da45f98c0e5db6b90f0aeb08d8c62f7b0dd122
msg ={"iv": "0f9c96f1a6b2acebeec472bfcf4afed5", "encrypted": "44028586b66dd7bc99d9560c413f9e86c092df712d82881fc18663bb55058577"}
iv = msg['iv']
ciphertext = msg['encrypted']

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