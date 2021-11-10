from sympy.ntheory import discrete_log

p = 0xde26ab651b92a129
g = 0x2
A = 0x92fffae1850dd593
B =0x1b92f42b077c299a
msg = {"iv": "e481a1805fc540db61ba2003c5a3536a", "encrypted_flag": "685537e87f44bc2399979f3e254da24b2f84e5b60dcf472a3e6262a0065b688e"}

#we nee to get a,b

for i in range (p):
    if pow(g,i,p) == A or pow(g,i,p) == B:
        print(i)
