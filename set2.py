#!/usr/bin/python
from Crypto.Cipher import AES
from Crypto.Random import random
from set1 import hexxor, isECB
import base64 
import string

ENCRYPT="e"
DECRYPT="d"
USE_PREFIX=True

class PaddingNotValidException(Exception):
    pass

def getRandomString():
    length = random.randint(1,200)
    randStr = "{0:0{1}x}".format(random.getrandbits(length*8), length*2).decode('hex')
    return randStr

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

def isPkcs7PaddingValid(data, blockSize):
    lastChar=data[-1]
    #print "Last character is ", lastChar.encode('hex')
    for x in range(len(data)-ord(lastChar), len(data)):
        #print data[x].encode('hex')
        if data[x] != lastChar:
            raise PaddingNotValidException("The padding is not valid")
            return False
    return True

def removePkcs7Padding(data, blockSize):
    if isPkcs7PaddingValid(data, blockSize):
        lastChar=data[-1]
        return data[:len(data)-ord(lastChar)]
    else:
        return data

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
random_string = getRandomString()
# Just for debugging purposes
#print len(random_string)
#print len(random_string) % 16

def aes_oracle(plaintext):
    #print plaintext
    #print len(plaintext)
    prefix = ""
    if (USE_PREFIX):
        prefix=random_string
    secretString = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    paddedPlaintext = pkcs7Padding(prefix+plaintext + secretString, AES.block_size)
    print paddedPlaintext
    #print len(secretString)
    #print len(paddedPlaintext)
    ciphertext = aes_128_ecb(paddedPlaintext, consistent_key, ENCRYPT)
    #print splitIntoBlocks(ciphertext.encode('hex'), AES.block_size*2)
    return ciphertext

def set2challenge12():
    USE_PREFIX=False
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

#set2challenge12()

def profileFor(email):
    #First strip out & and = from email
    email = email.replace("&","")
    email = email.replace("=","")

    profileString = "email="+email+"&uid=10&role=user"
    print parseCookie(profileString)
    return profileString


def parseCookie(cookie):
    kvPairs = cookie.split("&")
    kvObject={}
    for pair in kvPairs:
        kv = pair.split("=")
        kvObject[kv[0]] = kv[1]
    return kvObject



def set2challenge13():
    randomKey = getRandomAESKey()

    "email=foo@bar.co m&uid=10&role=us er"
    "email=xxxxxxxxxx adminBBBBBBBBBBB &uid=10&role=use r"
    "email=fooby@bar. com&uid=10&role= adminBBBBBBBBBBB"

    profile1 = profileFor("xxxxxxxxxxadmin"+chr(11)*11)
    profile2 = profileFor("fooby@bar.com")

    ciphertext1 = aes_128_ecb(pkcs7Padding(profile1, AES.block_size), randomKey, ENCRYPT)
    ciphertext2 = aes_128_ecb(pkcs7Padding(profile2, AES.block_size), randomKey, ENCRYPT)
    ciphertext3 = ciphertext2[:32]+ciphertext1[16:32]

    finalProfile = aes_128_ecb(ciphertext3, randomKey, DECRYPT)
    print parseCookie(removePkcs7Padding(finalProfile, AES.block_size))



#set2challenge13()

def set2challenge14():
    USE_PREFIX=True
    A="A"
    # Discover block size by feeding ECB oracle increasing size inputs to discover the block size
    ctxtlen=len(aes_oracle(""))
    blockSize=-1
    for i in range(64):
        ctxt = aes_oracle(A*i)
        if len(ctxt) > ctxtlen:
            blockSize = len(ctxt)-ctxtlen
            #print blockSize
            break
    #print blockSize

    # detect that it is using ECB mode
    # Need to use 3 blocks of A since we don't know how long the prefix string is
    if (isECB(aes_oracle(A*(3*blockSize)))):
        usingECB=True   
        #print "Using ECB"
    else:
        print "Not using ECB"
        return
    
    blocks = splitIntoBlocks(aes_oracle(A*(3*blockSize)).encode('hex'), blockSize*2)
    #print blocks;
    # Find the blocks that match our input
    x=-1
    y=-1
    for i, block in enumerate(blocks):
        if (blocks[i] == blocks[i+1]):
            x=i
            y=i+1
            break
    #print x, y

    # Next find the offset
    # by sending 2 blocks of As, followed by a third that ends in a Z
    # repeatedly increase the starting A's in the third block until you get the two repeated ciphertext blocks
    # that were used to detect ECB mode
    # the moment that they are equal, that means that the Z is pushed out into the next block
    # The number of leading A's in that third block is the offset
    offset=-1
    for i in range(blockSize):
        testplaintext = A*2*blockSize + A*i + 'Z'
        #print testplaintext
        ciphertext = aes_oracle(testplaintext)
        blocks=splitIntoBlocks(ciphertext.encode('hex'), blockSize*2)
        if (blocks[x] == blocks[y]):
            offset=i
            break

    print "Offset is ", offset

    # Compute the number of unknown blocks
    numberOfUnknownBlocks = len(aes_oracle(""))/blockSize - x

    # Now we can proceed with the previous algorithm, just adding A*offset before our strings
    # and adding x to the j block offset

    crack={}

    decryptedMessage = ""
    # Decrypt each block, one at a time
    # Added one to the numberof unknown blocks since if the offset is large, it doesn't decrypt the final block
    for j in range(numberOfUnknownBlocks+1):
        # j is the block I need to keep
        # Decrypt the block iteratively, since you can 
        for i in range(blockSize):
            addToDecryptionDictionary(A*offset + A*(blockSize-i-1)+decryptedMessage, crack, j+x, blockSize)
            block = getHexBlock(aes_oracle(A*offset + A*(blockSize-i-1)), j+x, blockSize)

            # at the very end, after the last byte,
            # the padding changes since the size of the message is changing 
            # So you cannot break that final byte
            # so if the block that you obtain is not in the dictionary
            # then you are done and can stop
            if block in crack:
                if (crack[block] == '\x01'):
                    # We are into the padding area. Maybe?
                    break
                decryptedMessage += crack[block]
            else:
                # If its not there, we are done
                break

    print decryptedMessage.rstrip('\n') # Rstrip since the plaintext already includes a newline

#set2challenge14()

def set2challenge15():
    blockSize=8
    data1="Test" + '\x04'*4
    data2 = "test" + '\x01\x02\x03\x04'
    try:
        print isPkcs7PaddingValid(data1, blockSize)
        print isPkcs7PaddingValid(data2, blockSize)
    except PaddingNotValidException as e:
        print e

#set2challenge15()

def cbc_encrypt_oracle(plaintext):
    prefix="comment1=cooking%20MCs;userdata="
    suffix=";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = pkcs7Padding(prefix+plaintext.replace(";","").replace("=","")+suffix, AES.block_size)
    iv="AAAAAAAAAAAAAAAA"
    return aes_128_cbc(plaintext, consistent_key, iv, ENCRYPT)


def cbc_decrypt_oracle(ciphertext):
    plaintext = removePkcs7Padding(aes_128_cbc(ciphertext, consistent_key, "", DECRYPT), AES.block_size)
    #print plaintext
    #print splitIntoBlocks(plaintext, 16)
    pairs = plaintext.split(";")
    for pair in pairs:
        keyValue = pair.split('=')
        #print keyValue[0], " = ", keyValue[1]
        if keyValue[0]=="admin" and keyValue[1]=="true":
            print "W00t W00t. You win!"
            return True
    print "FAIL!"


def set2challenge16():
    plaintext = "Zhis iZ a tester:admin<true"
    ciphertext=cbc_encrypt_oracle(plaintext)
    #print ciphertext
    blocks = splitIntoBlocks(ciphertext.encode('hex'), AES.block_size*2)
    #print blocks
    #print blocks[3]
    x = "01000000000001000000000000000000"
    #print x
    blocks[3] = hexxor(x, blocks[3])
    #print blocks[3]
    #print blocks
    ciphertext = "".join(blocks).decode('hex')
    #print ciphertext
    cbc_decrypt_oracle(ciphertext)


set2challenge16()

