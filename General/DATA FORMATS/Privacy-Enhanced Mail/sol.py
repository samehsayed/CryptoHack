from Crypto.PublicKey import RSA
pubKey = RSA.importKey(open('C:\Dublin\Crypto\CryptoHack\General\DATA FORMATS\Privacy-Enhanced Mail\privacy_enhanced_mail_1f696c053d76a78c2c531bb013a92d4a.pem').read())
print(pubKey.d)