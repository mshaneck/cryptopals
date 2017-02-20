#!/usr/bin/python
import sys, getopt, socket
import hashlib, gmpy, gmpy2
from Crypto.Random import random
from hashing import *
from rsa_utils import *
from dsa import *
import math
import zlib
import binascii
from decimal import *
from subprocess import *
from set2 import *
from set3 import *

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

def c51OracleCTR(P):
    request = "POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\nContent-Length: "+str(len(P))+"\n\n"+P
    # Encrypt with CTR mode using random key each time and random nonce after compressing it using zlib
    return len(aes_128_ctr(zlib.compress(request, 9), getRandomAESKey(), getRandomAESKey()[:8]))

def c51OracleCBC(P):
    #          123456789012345_ 123456789012345_12 3456789012345_123456789012345_123456789012345_123456789012345_1 23456789012345_
    request = "POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\nContent-Length: "+str(len(P))+"\n\n"+P
    # Encrypt with CTR mode using random key each time and random nonce after compressing it using zlib
    #print len(zlib.compress(request, 9))
    return len(aes_128_cbc(pkcs7Padding(zlib.compress(request, 9),16), getRandomAESKey(), getRandomAESKey(), ENCRYPT))

def set7challenge51():
    realCookie = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
    sessionCookie=""
    print "Breaking Session Cookie with CTR mode (Stream cipher)"
    for i in range(99):
        shortestLength=-1
        guessLetter=""
        # By doing it two at a time, the issue of compression not crossing a byte boundary is no longer an issue.
        for x in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/=\n":
            for y in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/=\n":
                length = c51OracleCTR("sessionid="+sessionCookie+x+y)
                if shortestLength == -1 or length < shortestLength:
                    shortestLength = length
                    guessLetter = x+y
                #if length > shortestLength:
                    # We actually got one that was longer
        if guessLetter == "\nC":
            break
        sessionCookie = sessionCookie + guessLetter
        print sessionCookie
    print sessionCookie
    print realCookie

    # Now do it with CBC
    sessionCookie=""
    print "Breaking Session Cookie with CBC mode (Block cipher)"
    for i in range(99):
        shortestLength=-1
        guessLetter=""
        length=0
        # Padding has to do with ensuring that the byte compression crosses a block boundary
        # Found this essentially by debugging and guessing and checking
        paddingLength=5
        if i>=4:
            paddingLength=4

        padding = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"[:paddingLength-1]+":"

        # By doing it two at a time, the issue of compression not crossing a byte boundary is no longer an issue.
        for x in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/=\n":
            for y in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/=\n":
                #print x+y
                #print len(sessionCookie)
                #print paddingLength

                #print padding
                #padding = "#############"
                length = c51OracleCBC(padding+"sessionid="+sessionCookie+x+y)
                #print length
                if shortestLength == -1 or length < shortestLength:
                    shortestLength = length
                    guessLetter = x+y
                #if length > shortestLength:
                    # We actually got one that was longer
        if guessLetter == "\nC":
            break
        if guessLetter == "aa":
            print length
            print sessionCookie
            exit()
        sessionCookie = sessionCookie + guessLetter
        print sessionCookie

        #exit()
    print sessionCookie
    print realCookie

set7challenge51()
