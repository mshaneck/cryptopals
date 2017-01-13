#!/usr/bin/python
import sys, getopt
from Crypto.Random import random
import hashlib, gmpy2
from rsa_utils import *

#dsa parameters from challenge 43:
p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

def genDsaKeys():
    x = random.randint(0,q)
    y = pow(g,x,p)
    return (x,y,g,p,q)

def dsaSignMessage(message, x, g,p,q):
    r=0
    s=0
    while (s == 0):
        while (r == 0):
            k = random.randint(0,q)
            r = pow(g,k,p)%q
        kinv = modInv(k,q)[1]
        h = int(hashlib.sha1(message).hexdigest(),16)
        s = (kinv*((h) + (x*r))) % q
    return (r,s)

def dsaVerifyMessage(r,s,message, y,g,p,q):
    if (r<0 or r>q or s<0 or s>q):
        return False
    w = modInv(s,q)[1]
    u1 = (int(hashlib.sha1(message).hexdigest(),16) * w) % q
    u2 = (r*w)%q
    v = ((pow(g,u1,p)* pow(y,u2,p))%p)%q
    if (v == r):
        return True
    return False

def main(argv):
    command=""
    commands=0
    bits=1024
    tests=15
    try:
        opts, args = getopt.getopt(argv,"b:t:s",["bits=", "testsig"])
    except getopt.GetoptError:
        print 'blerg'
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-b", "--bits"):
            bits = int(arg)
        if opt in ("-t", "--tests"):
            tests = int(arg)
        if opt in ("-s", "--testsig"):
            commands = commands+1
            command = "t"
    if (commands > 1):
        print "Too many commands specified"
        exit(2)

    if (commands == 0):
        print "No command specified"
        exit(2)

    if (command == "t"):
        (x,y,g,p,q) = genDsaKeys()
        message = "This is a message we will sign"
        (r,s)=dsaSignMessage(message, x, g,p,q)
        print "R"
        print r
        print "S"
        print s
        print "Verifying"
        print dsaVerifyMessage(r,s,message, y,g,p,q)




    exit(0)

if __name__ == "__main__":
   main(sys.argv[1:])
