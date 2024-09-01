from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from base64 import b64decode
from egcd import egcd
from math import gcd

def minverse(a, m):
    g,x,y = egcd(a,m)
    if g != 1:
        raise ValueError('Modular inverse does not exist.')
    else:
        return x % m

pkey1 = RSA.importKey(open('key1_pub.pem','r').read()) #extract n and e from public key, n is common to both public key
pkey2 = RSA.importKey(open('key2_pub.pem','r').read())

cipher1 = bytes_to_long(b64decode(open('message1','r').read()))

cipher2 = bytes_to_long(b64decode(open('message2','r').read()))

n = pkey1.n
e1 = pkey1.e
e2 = pkey2.e

s1 = minverse(e1,e2)
s2 = -((gcd(e1,e2) - e1*s1) // e2) #return int value

cipher2_inv = minverse(cipher2, n)

c1 = pow(cipher1, s1, n)
c2_inv = pow(cipher2_inv, s2, n)

output = long_to_bytes((c1*c2_inv) % n)

print(output)
