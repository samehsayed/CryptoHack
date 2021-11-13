#import qmpy

p = 857504083339712752489993810777
q = 1029224947942998075080348647219
e = 65537

n=p*q
x=(p-1)*(q-1)
d=pow(e,-1,x)
#d=qmpy.invert(e,x)

print(d)