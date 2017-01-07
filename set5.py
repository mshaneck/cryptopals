#!/usr/bin/python
from set1 import *
from set2 import *
from set3 import *
from set4 import *
from hashing import *

def diffieHellman(p,g):
    print "Computing Diffie Hellman shared key for p=" + str(p) + " and g=" + str(g)
    a = random.randint(2,p)
    A = pow(g,a,p)
    b = random.randint(2,p)
    B = pow(g,b,p)

    sB = pow(A,b,p)
    sA = pow(B,a,p)
    print "Printing session key: "
    print sA
    print sB



def set5challenge33():
    diffieHellman(37,5)
    diffieHellman(0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff, 2)


set5challenge33()
