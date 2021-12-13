p = 29
ints = [14, 6, 11] 

numbers= []

for i in ints: 
    for j in range(p):
        z= pow(j,2,p)
        if z == i: 
            numbers.append(j)

print(numbers)
