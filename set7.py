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
from hashing import *

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

#set7challenge51()

print mdsuck("0dde4118629163a019cb8489d780ecbf")
print mdsuck("testing")
print mdsuckmore("testing")
# print MDSuckWithState(0xdead,"test",4)

def genMDSuckCollisions(n):
    # Generate 2^n collisions

    # Produce a list of n pairs, each of which collides with the same previous state.
    # So you can take any one from each pair, and produce a collision
    #Start at initial state 0xBEEF
    internalState = 0xBEEF
    collisionBlocks = []
    hashCalls = 0
    # Use _process_mdsuck_chunk(chunk, h)
    for i in range(0,n):
        while True:
            chunk1 = "{0:0{1}x}".format(random.getrandbits(64), 16)
            chunk2 = "{0:0{1}x}".format(random.getrandbits(64), 16)
            # print chunk1.encode("hex")
            # print chunk2.encode("hex")
            #print len(chunk1)
            #print len(chunk2)
            newState1 = process_mdsuck_chunk(chunk1, internalState)
            newState2 = process_mdsuck_chunk(chunk2, internalState)
            hashCalls  = hashCalls  + 2
            if (newState1 == newState2):
                print "Got collision " + str(i)
                #print chunk1
                #print chunk2
                collisionBlocks.append((chunk1,chunk2))
                internalState = newState1
                break
    print "Got the " + str(pow(2,n)) + " collisions, took " + str(hashCalls) + " calls to the hash function"
    return collisionBlocks

def superCrapHash(m):
    return mdsuck(m)+mdsuckmore(m)

def getCollisionString(cb, indexString, numBlocks):
    retStr = ""
    for i in range(0,numBlocks):
        retStr += cb[i][int(indexString[i])]
    return retStr

def set7challenge52():
    # First generate 2^n collisions
    print "Generating 2^2 collisions"
    cb = genMDSuckCollisions(2)
    for a in range(0,2):
        for b in range(0,2):
            print "MDSuck  hash for " + cb[0][a]+cb[1][b] + " is " + mdsuck(cb[0][a]+cb[1][b])

    print "Super Crap Hash:"
    print superCrapHash("testing")

    # Part 2: Generate 2^(b2/2) colliding messages in f.
    # b2 = length of mdsuckmore which is 24 bits, so generate 2^(24/2) collisions
    cb = genMDSuckCollisions(12)
    print "Collisions generated in MDSuck, now looking for collisions in MDSuckMore"
    hashCalls = 0
    for i in range(0,2**12):
        x = '{0:012b}'.format(i)
        for j in range(0,2**12):
            if i != j:
                y = '{0:012b}'.format(j)
                check1 = getCollisionString(cb,x,12)
                check2 = getCollisionString(cb,y,12)
                hash1 = mdsuckmore(check1)
                hash2 = mdsuckmore(check2)
                hashCalls = hashCalls + 2
                if (hash1 == hash2):
                    print "Got a collision: "
                    print check1
                    print check2
                    print "Super Crap Hash of those are:"
                    print superCrapHash(check1)
                    print superCrapHash(check2)
                    print "Got the collision, took " + str(hashCalls) + " more calls to the hash function"
                    exit(0)
    print "Did not find any collisions... To bad... So sad..."

#set7challenge52()

def findCollidingMessages(k):
    # find messages of length (k, k + 2^k - 1)
    internalState = 0xBEEF
    collidingBlocks=[]
    """
    Here's how:

Starting from the hash function's initial state, find a collision between a single-block message and a message of 2^(k-1)+1 blocks.
DO NOT hash the entire long message each time. Choose 2^(k-1) dummy blocks, hash those, then focus on the last block.
Take the output state from the first step.
Use this as your new initial state and find another collision between a single-block message and a message of 2^(k-2)+1 blocks.
Repeat this process k total times. Your last collision should be between a single-block message and a message of 2^0+1 = 2 blocks.
Now you can make a message of any length in (k, k + 2^k - 1) blocks by choosing the appropriate message (short or long) from each pair.
"""
    for i in range(k):
        # find collision between single block message and 2^(k-1-i)+1 blocks
        longmsg = "{0:0{1}x}".format(random.getrandbits(64*(2**(k-1-i))), 16)
        longState = 0xBEEF
        longMsgBlocks = splitIntoBlocks(longmsg, 16)
        for b in longMsgBlocks:
            longState = process_mdsuck_chunk(chunk1, internalState)
        while True:
            chunk1 = "{0:0{1}x}".format(random.getrandbits(64), 16)
            chunk2 = "{0:0{1}x}".format(random.getrandbits(64), 16)
            # print chunk1.encode("hex")
            # print chunk2.encode("hex")
            #print len(chunk1)
            #print len(chunk2)
            newState1 = process_mdsuck_chunk(chunk1, internalState)
            newState2 = process_mdsuck_chunk(chunk2, internalState)
            hashCalls  = hashCalls  + 2
            if (newState1 == newState2):
                #print "Got collision " + str(i)
                #print chunk1
                #print chunk2
                collidingBlocks.append((chunk1,chunk2))
                internalState = newState1
                break
"""
Now we're ready to attack a long message M of 2^k blocks.

Generate an expandable message of length (k, k + 2^k - 1) using the strategy outlined above.
Hash M and generate a map of intermediate hash states to the block indices that they correspond to.
From your expandable message's final state, find a single-block "bridge" to intermediate state in your map. Note the index i it maps to.
Use your expandable message to generate a prefix of the right length such that len(prefix || bridge || M[i..]) = len(M).
The padding in the final block should now be correct, and your forgery should hash to the same value as M.
"""


def set7challenge53():
