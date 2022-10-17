# Elliptic Curve Cryptography
def xgcd(a,b):
    """xgcd(a,b) returns a tuple of form (g,x,y), where g is gcd(a,b) and
	x,y satisfy the equation g = ax + by."""
    a1=1; b1=0; a2=0; b2=1; aneg=1; bneg=1
    if(a < 0):
        a = -a; aneg=-1
    if(b < 0):
        b = -b; bneg=-1
    while (1):
        quot = -(a // b)
        a = a % b
        a1 = a1 + quot*a2; b1 = b1 + quot*b2
        if(a == 0):
            return (b, a2*aneg, b2*bneg)
        quot = -(b // a)
        b = b % a;
        a2 = a2 + quot*a1; b2 = b2 + quot*b1
        if(b == 0):
            return (a, a1*aneg, b1*bneg)


def inverse_mod(a,n):
    """inverse_mod(b,n) - Compute 1/b mod n."""
    (g,xa,xb) = xgcd(a,n)
    if(g != 1): raise ValueError("***** Error *****: {0} has no inverse (mod {1}) as their gcd is {2}, not 1.".format(a,n,g))
    return xa % n


def el_add(p, q, n, a):
    if p == q:
        s = ((3*(p[0]**2)+a)*inverse_mod(2*p[1], n)) % n
    else:
        s = ((q[1]-p[1])*inverse_mod(q[0]-p[0], n)) % n
    x = (s**2-p[0]-q[0]) % n
    y = (s*(p[0]-x)-p[1]) % n
    return (x, y)


def sam(c, p, n, a):
    # Square and multiply algorithm
    # n is the modulo
    # a is the curve parameter
    # Given an initial point p and a binary scalar c, sam returns the resulting point after adding p+p c times
    # Assuming the scalar is already in binary, going from left to right, the number is translated into a procedure:
    #    For every new digit, the new point is the previous point squared
    #    If the new digit is a 1, we add p
    #    Otherwise, we go to the next digit
    op = p
    if isinstance(c, float):
        c = bin(int(c)).replace('0b', '')
    for x in range(1, len(c)):
        op = el_add(op, op, n, a)
        if c[x] == '1':
            op = el_add(op, p, n, a)
    return op

# --------------------------------------------------------------------------------------------------------------------#
# The curve parameters used for the scheme were those in secp192r1:
from random import random
p_hex = 'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFF'
a_hex= 'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFC'
b_hex = '64210519 E59C80E7 0FA7E9AB 72243049 FEB8DEEC C146B9B1'
x_hex = '188DA80E B03090F6 7CBF20EB 43A18800 F4FF0AFD 82FF1012'
y_hex = '07192B95 FFC8DA78 631011ED 6B24CDD5 73F977A1 1E794811'

p = int(p_hex.replace(" ", ""), 16)
a = int(a_hex.replace(" ", ""), 16)
b = int(b_hex.replace(" ", ""), 16)
x = int(x_hex.replace(" ", ""), 16)
y = int(y_hex.replace(" ", ""), 16)
G = (x, y)

# A private key d is generated for Alice, and e is generated for Bob
# d = (p-1)*random()
d = 1.5358263433047043e+57
# e = (p-1)*random()
e = 4.931774275263541e+55
# K_A = d * G is calculated
K_A = sam(d, G, p, a)

# K_A is sent over (???)

# K_B is calculated
K_B = sam(e, G, p, a)

# K_B is received (???) and used to calculate the shared secret K_AB
K_AB = sam(d, K_B, p, a)
# or sam(e, K_A, p, a)

# The message is converted to hexadecimal and then to binary
message = 'Escuadron 404'
bin_mess = bin(int(message.encode('utf-8').hex(), 16))
print(bin_mess)

# The x coordinate of K_AB is chopped to the size of the message - 1
Kx = str(bin(K_AB[0]).replace('0b', ''))[0:len(bin_mess)-1]
print(Kx)

# The chopped x coordinate of K_AB with a zero to the left is then XOR'd with the secret message
enc_mess = bin(int("".join(["0", Kx]), 2) ^ int(bin_mess, 2))
print(enc_mess)

# The message is then XOR'd with the chopped x coordinate of K_AB
dec_mess = bin(int("".join(["0", Kx]), 2) ^ int(enc_mess, 2))

# The message is converted to hexadecimal and then to string
final_mess = bytes.fromhex(hex(int(dec_mess, 2)).replace('0x', '')).decode('utf-8')


print(final_mess)