#!/usr/bin/python
import sys, getopt, socket
import hashlib, gmpy, gmpy2
from Crypto.Random import random
from hashing import *
from rsa_utils import *
from dsa import *
import math
import binascii
from decimal import *
from subprocess import *
from set2 import *

def genCbcMac(message, key, iv):
    ciphertext = aes_128_cbc(pkcs7Padding(message,16), key, iv, ENCRYPT)
    l = len(ciphertext)
    return ciphertext[l-16:]

def verifyCbcMac(message, mac, key, iv):
    print message
    print mac.encode("hex")
    print key.encode("hex")
    print key.encode("hex")
    validTag = genCbcMac(message, key, iv)
    return validTag == mac

# See c49.py and c49client.py for Challenge 49

def set7challenge50():
    code=""
    with open('set7challenge50-good.js', 'r') as myfile:
        code=myfile.read()
    mac= genCbcMac(code, b'YELLOW SUBMARINE', "\x00"*16).encode("hex")
    print mac
    # Hash/Mac value is 296b8d7cb78a243dda4d0a61d33bbdd1
    with open('set7challenge50-bad.js', 'r') as myfile:
        code=myfile.read()
    mac= genCbcMac(code, b'YELLOW SUBMARINE', "\x00"*16).encode("hex")
    print mac

    # This is how the js file was generated. Print to screen and redirect to a file.
    # targetCode = "alert('Ayo, the Wu is back!');      \n//     "
    # macTarget= genCbcMac(targetCode, b'YELLOW SUBMARINE', "\x00"*16).encode("hex")
    # paddedTargetCode = pkcs7Padding(targetCode,16)
    # mask = "00"*len(paddedTargetCode) + macTarget + "0"*(len(code)*2-len(macTarget))
    # #print mask
    # newMsg = paddedTargetCode+code
    # #print newMsg.encode("hex")
    # maskedMsg = hexxor(newMsg.encode("hex"),mask)
    # #print maskedMsg
    # newMac = genCbcMac(maskedMsg.decode("hex"), b'YELLOW SUBMARINE', "\x00"*16).encode("hex")
    # print maskedMsg.decode("hex"),

#set7challenge50()

def set7challenge51():
    print "TODO"

set7challenge51()
