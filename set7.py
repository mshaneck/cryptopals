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
