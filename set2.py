#!/usr/bin/python
from Crypto.Cipher import AES
from Crypto.Random import random
from set1 import hexxor, isECB
import base64 
import string

ENCRYPT="e"
DECRYPT="d"

def splitIntoBlocks(data, blockSize):
    o = []
    while(data):
        o.append(data[0:blockSize])
        data = data[blockSize:]
    return o

def pkcs7Padding(data, blockSize):
    # First determine how much is needed
    bytesNeeded = blockSize-len(data)%blockSize
    return data + chr(bytesNeeded)*bytesNeeded

def set2challenges9():
    print pkcs7Padding("YELLOW SUBMARINE", 20)
    print pkcs7Padding("Testing Testing 123", 10)
    print pkcs7Padding("This is a test", 14)
    print pkcs7Padding("Test2", 75)

#set2challenge()

def aes_128_ecb(input, key, mode):
    cipher = AES.new(key, AES.MODE_ECB)
    if (mode == DECRYPT):
        #print "Decrypting ", input.encode('hex')
        return cipher.decrypt(input)
    else:
        #print "Encrypting ", input.encode('hex')
        return cipher.encrypt(input)

def aes_128_cbc(input, key, iv, mode):
    #Process the data into blocks
    input = splitIntoBlocks(input, AES.block_size)
    output=""
    if (mode ==DECRYPT):
        iv=input[0]
        input=input[1:]
    else:
        output+=iv

    #print input
    for block in input:
        #print "------------------------"
        nextBlock=""
        
        if (mode == ENCRYPT):
            nextBlock = aes_128_ecb(hexxor(iv.encode('hex'), block.encode('hex')).decode('hex'), key, ENCRYPT)
            iv=nextBlock
        else:
            nextBlock = hexxor(iv.encode('hex'), aes_128_ecb(block, key, DECRYPT).encode('hex') ).decode('hex')
            iv=block
        #print nextBlock

        output += nextBlock
        #print output.encode('hex')

    return output


def set2challenge10():
    plaintext=pkcs7Padding("We all live in a yellow submarine, a yellow submarine, a yellow submarine. Ice Ice Baby. Woo!", AES.block_size)
    key="YELLOW SUBMARINE"
    iv="\x00"*AES.block_size
    ciphertext=aes_128_cbc(plaintext, key, iv, ENCRYPT)
    print ciphertext
    print "#########################################"
    decrypted = aes_128_cbc(ciphertext, key, iv, DECRYPT)
    print decrypted

#set2challenge10()
    
def getRandomAESKey():
    return "{0:0{1}x}".format(random.getrandbits(128), 32).decode('hex')
    
def encryptWithRandomKey(plaintext):
    key = getRandomAESKey()
    
    prependlen = random.randint(5,10)
    postpendlen = random.randint(5,10)
    prepend = "{0:0{1}x}".format(random.getrandbits(prependlen*8), prependlen*2).decode('hex')
    postpend = "{0:0{1}x}".format(random.getrandbits(postpendlen*8), postpendlen*2).decode('hex')
    
    mode = random.randint(0,1)
    plaintext = pkcs7Padding(prepend+plaintext+postpend, AES.block_size)
    
    if (mode==0):
        #print "ECB"
        return aes_128_ecb(plaintext, key, ENCRYPT)
    else:
        #print "CBC"
        iv=getRandomAESKey()
        return aes_128_cbc(plaintext, key, iv, ENCRYPT)

def set2challenge11():
    ciphertext = encryptWithRandomKey("A"*256)
    #print ciphertext.encode('hex')
    print isECB(ciphertext)
    
    
#set2challenge11()

consistent_key = getRandomAESKey()
def aes_oracle(plaintext):
    #print plaintext
    #print len(plaintext)
    secretString = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    paddedPlaintext = pkcs7Padding(plaintext + secretString, AES.block_size)
    #print len(secretString)
    #print len(paddedPlaintext)
    ciphertext = aes_128_ecb(paddedPlaintext, consistent_key, ENCRYPT)
    #print splitIntoBlocks(ciphertext.encode('hex'), AES.block_size*2)
    return ciphertext

def set2challenge12():
    A="A"
    # Discover block size by feeding ECB oracle increasing size inputs to discover the block size
    ctxtlen=len(aes_oracle(A))
    blockSize=-1
    for i in range(64):
        ctxt = aes_oracle(A*i)
        if len(ctxt) > ctxtlen:
            blockSize = len(ctxt)-ctxtlen
            #print blockSize
            break
    
    numberOfUnknownBlocks = len(aes_oracle(""))/blockSize
    #print numberOfUnknownBlocks, " total unknown blocks"

    # detect that it is using ECB mode
    if (isECB(aes_oracle(A*(2*blockSize)))):
        usingECB=True   
    else:
        print "Not using ECB"
        return

    # Knowing the block size, build a dictionary for all possible last bytes for the first block:
    crack={}

    decryptedMessage = ""
    # Decrypt each block, one at a time
    for j in range(numberOfUnknownBlocks):
        # j is the block I need to keep
        # Decrypt the block iteratively, since you can 
        for i in range(blockSize):
            addToDecryptionDictionary(A*(blockSize-i-1)+decryptedMessage, crack, j, blockSize)
            block = getHexBlock(aes_oracle(A*(blockSize-i-1)), j, blockSize)

            # at the very end, after the last byte,
            # the padding changes since the size of the message is changing 
            # So you cannot break that final byte
            # so if the block that you obtain is not in the dictionary
            # then you are done and can stop
            if block in crack:
                decryptedMessage += crack[block]

    print decryptedMessage


    # Print out the secret string

def addToDecryptionDictionary(prefixStr, crackDict, blockNumber, blockSize):
    for c in range(256):
        block = getHexBlock(aes_oracle(prefixStr+chr(c)), blockNumber, blockSize)
        crackDict[block] = chr(c)


def getHexBlock(ciphertext, i, blockSize):
    block = ciphertext.encode('hex')[(i*blockSize)*2: (i+1)*blockSize*2]
    #print "------"
    #print block
    #print (i*blockSize)*2
    #print (i+1)*blockSize*2
    #print "------"
    return block

set2challenge12()
