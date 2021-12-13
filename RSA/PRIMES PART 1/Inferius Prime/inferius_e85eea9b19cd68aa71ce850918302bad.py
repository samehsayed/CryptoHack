

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD

n = 742449129124467073921545687640895127535705902454369756401331
e = 3
ct = 39207274348578481322317340648475596807303160111338236677373

#using http://factordb.com/ site, i foudn p,q values
p = 752708788837165590355094155871
q = 986369682585281993933185289261

#now we can calcualte d and m as below

phi= (p-1)*(q-1)
d = pow(e,-1,phi)
m = pow(ct,d,n)

#print(hex(m))
decrypted = long_to_bytes(m)
print(decrypted)



"""""
# n will be 8 * (100 + 100) = 1600 bits strong which is pretty good
while True:
    p = getPrime(100)
    q = getPrime(100)
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    if d != -1 and GCD(e, phi) == 1:
        break





n = p * q

flag = b"XXXXXXXXXXXXXXXXXXXXXXX"
pt = bytes_to_long(flag)
ct = pow(pt, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"ct = {ct}")

pt = pow(ct, d, n)
decrypted = long_to_bytes(pt)
assert decrypted == flag
"""""