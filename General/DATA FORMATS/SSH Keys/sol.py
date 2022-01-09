from Crypto.PublicKey import RSA
from base64 import b64decode

key64 = b'MIIBigKCAYEArTy6m2vhhbwx3RVbNVb3ZOenCqqsOXHaJpbtN+OuulLKBSKpIoPB+ZDbDXn0qWkf4lOxtGSgolkUbgG07Lhzfgs+dul4UL84CkwZExmF3Rf1nRv+v7pqLt2dPsCb02YLxJnhHJb4rQaz2ZM4QCtTOcqYDUeKfLHCaZU4Ekm/OApKrpfw4/0ofn8KOrFN0t4/dqnNuwVRgoaUIhsI47reApB2rs0AP4CggSIi8s6BXCxB4YzgThBK5760T1giACYQC5MFdq1Gw+INSFmu0CNqt5wdJ5Z4z5448Gke06R+IMtjUiGDQ3QtT2fK3gWhZxk14M4UNrdETgTW/mQ4B/BcvikxvoBGpKbttG0agfOjTen6wyzpGfcd8N9rSbaqqyUwC8uDotzFtFzzutVAU9d91TagGzWBhNoMfplwVTns27GOOgv1dn5sQSSSmP0hTbPMDlThysKkR9BiOVbBtWGQpV936pPBgyWERGqMqC9xykLdVHv2Vu05T0WMwKCAetgtAgMBAAE='

keyDER = b64decode(key64)
keyPub = RSA.importKey(keyDER)

print(keyPub.n)