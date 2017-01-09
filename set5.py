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

def diffieHellmanMITM(p,g,replaceAB, replaceABwith):
    secret_message = "This is the secret message!!!!"

    # A sends to B, but intercepted by M
    a = random.randint(2,p)
    A=pow(g,a,p)

    # M replaces A with replaceABwith
    if (replaceAB):
        A=replaceABwith

    # B sends to A, but is intercepted by M
    b = random.randint(2,p)
    B=pow(g,b,p)

    # M intercepts and replaces B with replaceABwith
    if (replaceAB):
        B=replaceABwith
    print A
    print B
    # Both sides will compute s
    sA = pow(B,a,p)
    sB = pow(A,b,p)
    print sA
    print sB

    # A sends message to B
    ivA="{0:0{1}x}".format(random.getrandbits(128), 32).decode('hex')
    keyA = sha1(str(sA))[0:16]
    print keyA
    ciphertextA = aes_128_cbc(pkcs7Padding(secret_message, AES.block_size), keyA, ivA, ENCRYPT)

    # It gets passed on to B and B decrypts it
    keyB = sha1(str(sB))[0:16]
    print keyB
    plaintextB = removePkcs7Padding(aes_128_cbc(ciphertextA, keyB, ivA, DECRYPT), AES.block_size)
    print "Bob got: " + plaintextB

    # Bob sends it back
    ivB="{0:0{1}x}".format(random.getrandbits(128), 32).decode('hex')
    ciphertextB = aes_128_cbc(pkcs7Padding(plaintextB, AES.block_size), keyB, ivB, ENCRYPT)

    # A decrypts
    plaintextA = removePkcs7Padding(aes_128_cbc(ciphertextB, keyA, ivB, DECRYPT), AES.block_size)
    print "Alice received this: " + plaintextA

    return (ivA, ciphertextA, ivB, ciphertextB, A, B)

def set5challenge34():
    p=37
    g=5

    print "Replacing A and B with p"
    (ivA, ciphertextA, ivB, ciphertextB, A, B) = diffieHellmanMITM(p,g,True,p)
    # Eve needs to decrypt. But since A and B were replaced with p, then p^a mod p is 0 and p^b mod p is also 0
    sE = pow(0,1,p)
    print "sE = " + str(sE)
    keyEve = sha1(str(sE))[0:16]
    plaintextEve1 = removePkcs7Padding(aes_128_cbc(ciphertextA, keyEve, ivA, DECRYPT), AES.block_size)
    plaintextEve2 = removePkcs7Padding(aes_128_cbc(ciphertextB, keyEve, ivB, DECRYPT), AES.block_size)
    print "Eve got these:"
    print plaintextEve1
    print plaintextEve2

#set5challenge34()

def set5challenge35():
    # same as 34 but with messed up g:
    p=37
    g=5

    # g = 1 --> sA will be 1
    print "\nReplacing g with 1"

    (ivA, ciphertextA, ivB, ciphertextB, A, B) = diffieHellmanMITM(p,1,False,g)
    sE = pow(1,1,p)
    print "sE = " + str(sE)
    keyEve = sha1(str(sE))[0:16]
    plaintextEve1 = removePkcs7Padding(aes_128_cbc(ciphertextA, keyEve, ivA, DECRYPT), AES.block_size)
    plaintextEve2 = removePkcs7Padding(aes_128_cbc(ciphertextB, keyEve, ivB, DECRYPT), AES.block_size)
    print "Eve got these:"
    print plaintextEve1
    print plaintextEve2

    # g = p   --> this will be same as above, sA = sB = 0
    print "\nReplacing g with p"
    (ivA, ciphertextA, ivB, ciphertextB, A, B) = diffieHellmanMITM(p,p,False,g)
    sE = pow(0,1,p)
    print "sE = " + str(sE)
    keyEve = sha1(str(sE))[0:16]
    plaintextEve1 = removePkcs7Padding(aes_128_cbc(ciphertextA, keyEve, ivA, DECRYPT), AES.block_size)
    plaintextEve2 = removePkcs7Padding(aes_128_cbc(ciphertextB, keyEve, ivB, DECRYPT), AES.block_size)
    print "Eve got these:"
    print plaintextEve1
    print plaintextEve2

    # g = p - 1 --> sA and sB will be either 1 or p-1 based on parity of a*b
    # --> a odd means A is p-1, b odd means B is p-1
            # a odd, b odd,  ab is odd --> sA is p-1
            # a odd, b even, ab is even --> sA is 1
            # a even, b odd, ab is even --> sA is 1
            # a even, b even, ab is even --> sA is 1
    print "\nReplacing g with p-1"
    (ivA, ciphertextA, ivB, ciphertextB, A, B) = diffieHellmanMITM(p,p-1,False,g)
    sE = pow(1,1,p)
    print A
    print B
    if (A==p-1 and B==p-1):
        sE = pow(p-1,1,p)
    print "sE = " + str(sE)
    keyEve = sha1(str(sE))[0:16]
    plaintextEve1 = removePkcs7Padding(aes_128_cbc(ciphertextA, keyEve, ivA, DECRYPT), AES.block_size)
    plaintextEve2 = removePkcs7Padding(aes_128_cbc(ciphertextB, keyEve, ivB, DECRYPT), AES.block_size)
    print "Eve got these:"
    print plaintextEve1
    print plaintextEve2




#set5challenge35()

def set5challenge36():
    print "Run Server with ./SRPServer.py --port 6000"
    print "Run Client with ./SRPClient.py --port 6000"

def set5challenge37():
    print "Run Server with ./SRPServer.py --port 6000"
    print "Run Client with ./SRPClient.py --port 6000 -z"

#set5challenge36()
#set5challenge37()
