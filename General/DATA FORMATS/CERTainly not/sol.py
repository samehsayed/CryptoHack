#I used https://www.sslshopper.com/ to convert from .der to .pem 

from Crypto.PublicKey import RSA
pubKey = RSA.importKey(open('C:\Dublin\Crypto\CryptoHack\General\DATA FORMATS\CERTainly not\p.pem').read())
print(pubKey.n)