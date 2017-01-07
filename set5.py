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

#set5challenge33()

def set5challenge34():
    secret_message = "This is the secret message!!!!"

    # A sends to B, but intercepted by M
    p=37
    g=5
    a = random.randint(2,p)
    A=pow(g,a,p)

    # M replaces A with p
    A=p

    # B sends to A, but is intercepted by M
    b = random.randint(2,p)
    B=pow(g,b,p)

    # M intercepts and replaces B with p
    B=p

    # Both sides will compute s
    sA = pow(B,a,p)
    sB = pow(A,b,p)

    # A sends message to B
    ivA="{0:0{1}x}".format(random.getrandbits(128), 32).decode('hex')
    keyA = sha1(str(sA))[0:16]
    ciphertextA = aes_128_cbc(pkcs7Padding(secret_message, AES.block_size), keyA, ivA, ENCRYPT)

    # It gets passed on to B and B decrypts it
    keyB = sha1(str(sB))[0:16]
    plaintextB = removePkcs7Padding(aes_128_cbc(ciphertextA, keyB, ivA, DECRYPT), AES.block_size)
    print "Bob got: " + plaintextB

    # Bob sends it back
    ivB="{0:0{1}x}".format(random.getrandbits(128), 32).decode('hex')
    ciphertextB = aes_128_cbc(pkcs7Padding(plaintextB, AES.block_size), keyB, ivB, ENCRYPT)

    # A decrypts
    plaintextA = removePkcs7Padding(aes_128_cbc(ciphertextB, keyA, ivB, DECRYPT), AES.block_size)
    print "Alice received this: " + plaintextA


    # Eve needs to decrypt. But since A and B were replaced with p, then p^a mod p is 0 and p^b mod p is also 0
    sE = pow(0,1,p)
    keyEve = sha1(str(sE))[0:16]
    plaintextEve1 = removePkcs7Padding(aes_128_cbc(ciphertextA, keyEve, ivA, DECRYPT), AES.block_size)
    plaintextEve2 = removePkcs7Padding(aes_128_cbc(ciphertextB, keyEve, ivB, DECRYPT), AES.block_size)
    print "Eve got these:"
    print plaintextEve1
    print plaintextEve2
    

set5challenge34()
