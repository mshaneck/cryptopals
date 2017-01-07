#!/usr/bin/python
from set1 import *
from set2 import *
from set3 import *
from hashing import *
import requests
from timeit import default_timer as timer

def edit(ciphertext, key, nonce, offset, newtext):
    # It seems to me that I will essentially just decrypt the whole thing, replace the plaintext with newtext, then reencrypt...
    # I suppose ideally I would generate just the piece that I need, but it's proof of concept stuff, right?
    plaintext = aes_128_ctr(ciphertext, key, nonce)
    newplaintext = plaintext[:offset] + newtext + plaintext[offset+len(newtext):]
    return aes_128_ctr(newplaintext, key, nonce)

def attackeredit(ciphertext, offset, newtext):
    return edit(ciphertext, consistent_key, consistent_nonce, offset, newtext)

def set4challenge25():
    x = base64.b64decode(open('set4.challenge25.txt', 'r').read())
    key = b'YELLOW SUBMARINE'
    cipher = AES.new(key, AES.MODE_ECB)
    recoveredPlaintext = cipher.decrypt(x)
    ctrCiphertext = aes_128_ctr(recoveredPlaintext, consistent_key, consistent_nonce)

    #print "Testing the edit function"
    #testpt = "Well hello there, pardner. How are you doing today?"
    #print "Plaintext: "
    #print testpt
    #cipher = aes_128_ctr(testpt, consistent_key, consistent_nonce)
    #newtext = "goodbye bub"
    #cipher = attackeredit(cipher, 5, newtext)
    #print aes_128_ctr(cipher, consistent_key, consistent_nonce)

    # use the attackeredit function to recover the plaintext
    newtext = "\x00"*len(recoveredPlaintext)
    newcipher = attackeredit(ctrCiphertext, 0, newtext)
    # now xor the newcipher with the ctrCiphertext
    originalPlaintext = hexxor(newcipher.encode("hex"), ctrCiphertext.encode("hex")).decode("hex")
    print originalPlaintext

#set4challenge25()

def c26_ctr_encrypt_oracle(plaintext):
    prefix="comment1=cooking%20MCs;userdata="
    suffix=";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = prefix+plaintext.replace(";","").replace("=","")+suffix
    return aes_128_ctr(plaintext, consistent_key, consistent_nonce)

def c26_ctr_decrypt_oracle(ciphertext):
    plaintext = aes_128_ctr(ciphertext, consistent_key, consistent_nonce)
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

def set4challenge26():
    plaintext = "Zhis iZ a tester:admin<true"
    ciphertext=c26_ctr_encrypt_oracle(plaintext)
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
    c26_ctr_decrypt_oracle(ciphertext)

#set4challenge26()

c27key = b'YELLOW SUBMARINE'
# The directions for this one seema bit off. I'm going to just do it my own way. I think it captures the intent.
def c27_cbc_encrypt(plaintext):
    return aes_128_cbc(plaintext, c27key, c27key, ENCRYPT)

def c27_cbc_decrypt(ciphertext):
    plaintext = aes_128_cbc(c27key+ciphertext, c27key, c27key, DECRYPT)
    #print len(plaintext)
    #Check if any byte in the plaintext is high ascii, meaning over 127
    # If yes, return plaintext
    for s in plaintext:
        if (ord(s)>127):
            # This is our error condition, return the plaintext
            return plaintext
    return "Ok"

def set4challenge27():
    p1 = "A"*AES.block_size
    p2 = "B"*AES.block_size
    p3 = "C"*AES.block_size

    ciphertext = c27_cbc_encrypt(p1+p2+p3)
    c1 = ciphertext[:AES.block_size]
    modc = c1+'\x00'*AES.block_size+c1
    #print modc.encode("hex")
    #print len(modc)
    answer = c27_cbc_decrypt(modc)
    if (answer == "Ok"):
        print "Ok"
    else:
        print "Error condition..."
        #print len(answer)
        p1 = answer[:AES.block_size]
        p3 = answer[AES.block_size*2:]
        #print p1.encode("hex")
        #print p3.encode("hex")
        print hexxor(p1.encode("hex"),p3.encode("hex")).decode("hex")

#set4challenge27()

def getGluePadding(msgLen):
    padding=''
    # append the bit '1' to the message
    padding += b'\x80'

    #   append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    padding += b'\x00' * ((56 - (msgLen + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message_bit_length = msgLen * 8
    padding += struct.pack(b'>Q', message_bit_length)
    return padding

def verifyMac(msg, key, tag):
    checkTag = sha1Mac(key, msg)
    return (tag == checkTag)

def set4challenge28():
    #macKey = "yellow"
    macKey = random.choice(open("/usr/share/dict/words").readlines()).rstrip()
    #print "Key is " + macKey

    msg = "comment1=cooking MCs;userdata=foo;comment2= like a pound of bacon"
    hashMac = sha1Mac(macKey, msg)
    #print "HashMac of original: " + hashMac
    #print "Verifying mac on original:"
    res = verifyMac(msg, macKey, hashMac)
    if (not res):
        print "WHAT??"
        exit()

    #160 bits hash function
    h0=int(hashMac[0:8], 16)
    h1=int(hashMac[8:16], 16)
    h2=int(hashMac[16:24], 16)
    h3=int(hashMac[24:32], 16)
    h4=int(hashMac[32:], 16)

    additionalMsg = "comment3=yetsomemorecomments;admin=true"
    longestKeyLen=32
    originalMsgLen=len(msg)
    for i in range(1,longestKeyLen):
    #for i in range(len(macKey), len(macKey)+1):
        #print "\n\nGuessing " + str(i)
        #print "Original Msg Len plus key length:" + str(originalMsgLen+i)
        padding = getGluePadding(originalMsgLen+i)
        #print padding.encode("hex")
        #print len(padding)
        tag = sha1WithState(h0,h1,h2,h3,h4,additionalMsg,originalMsgLen+i+len(padding))
        #print "We got                 " + tag
        #print "We should have gotten: " + sha1Mac(macKey, msg+padding+additionalMsg)
        if(verifyMac(msg+padding+additionalMsg, macKey, tag)):
            print "We win! Key length is " + str(i)
            print "Forged Mac for "+msg+padding+additionalMsg
            exit()
    print "Did not forge the message... :("

# This really should be challenge 29, but i don't care that much...
#set4challenge28()



def getGluePaddingMD4(length):

    padding = "\x80" + "\x00" * ((55 - length) % 64) + struct.pack("<Q", length * 8)
    #print "Glue padding:     " + padding.encode("hex")
    #print len(padding)
    return padding

def verifyMD4Mac(msg, key, tag):
    checkTag = md4Mac(key, msg)
    return (tag == checkTag)

def set4challenge30():
    #m = MD4()
    #m.add("hello")
    #h = m.finish()
    #print h
    #hstate=struct.unpack("<4I", h.decode("hex"))
    #print hstate

    macKey = random.choice(open("/usr/share/dict/words").readlines()).rstrip()
    print "Key is " + macKey

    msg = "comment1=cooking MCs;userdata=foo;comment2= like a pound of bacon"
    hashMac = md4Mac(macKey, msg)
    #print "HashMac of original: " + hashMac
    #print "Verifying mac on original:"
    res = verifyMD4Mac(msg, macKey, hashMac)
    if (not res):
        print "WHAT??"
        exit()
    print "Verified normally"
    #exit()

    hstate=struct.unpack("<4I", hashMac.decode("hex"))

    additionalMsg = "comment3=yetsomemorecomments;admin=true"
    #print "Additional message length="+str(len(additionalMsg))
    longestKeyLen=32
    originalMsgLen=len(msg)
    for i in range(1,longestKeyLen):
    #for i in range(len(macKey), len(macKey)+1):
        #print "\n\nGuessing " + str(i)
        #print "Original Msg Len plus key length:" + str(originalMsgLen+i)
        padding = getGluePaddingMD4(originalMsgLen+i)
        #print padding.encode("hex")
        #print len(padding)
        forge = MD4()
        forge.setInternalState(hstate, (originalMsgLen+i+len(padding))/64)
        forge.add(additionalMsg)
        tag = forge.finish()

        print "We got                 " + tag
        print "We should have gotten: " + md4Mac(macKey, msg+padding+additionalMsg)
        if(verifyMD4Mac(msg+padding+additionalMsg, macKey, tag)):
            print "We win! Key length is " + str(i)
            print "Forged Mac for "+msg+padding+additionalMsg
            exit()
    print "Did not forge the message... :("

#set4challenge30()

def set4challenge31():
    #print "Empty HMAC: 0x" + hmac_sha1("","")
    #print "Should be   0xfbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
    #print ""
    #print "HMAC_SHA1(\"key\", \"The quick brown fox jumps over the lazy dog\"): 0x" + hmac_sha1("key", "The quick brown fox jumps over the lazy dog")
    #print "HMAC_SHA1 is working..."

    # going to use set4.hmacfile
    testsig=""#"d8fd65a24f8132956c4aaa5f866022e7ab710ec5"
    #print len(testsig)
    #HMAC length is 40 bytes in 0-9a-f
    macLength=40
    macCharacters = "abcdef0123456789"
    try:
        for i in range(0,macLength):
            maxRespTime = 0.0
            maxRespTimeCharacter = ""
            for j in macCharacters:
                #Look for the longest response time, that;s probably the correct character
                start = timer()
                r = requests.head("http://localhost:8080/test?file=set4.hmacfile&signature="+testsig+j)
                end = timer()
                respTime = (end - start)
                if (respTime>maxRespTime):
                    maxRespTime = respTime
                    maxRespTimeCharacter = j
            testsig = testsig + maxRespTimeCharacter
        # At this point, we shoud have built up the signature.
        # Let's try it
        print "Trying: " + testsig
        r=requests.head("http://localhost:8080/test?file=set4.hmacfile&signature="+testsig)
        if(r.status_code == 200):
            print "Success!"
        else:
            print "Fail!"
        # prints the int of the status code. Find more at httpstatusrappers.com :)
    except requests.ConnectionError:
        print("failed to connect")

#set4challenge31()

def set4challenge32():
    # going to use set4.hmacfile
    testsig=""#"d8fd65a24f8132956c4aaa5f866022e7ab710ec5"

    # print "Testing python stuff"
    # x = int("a", 16)
    # y = int("0", 16)
    # z = int("5", 16)
    # print x, y, z
    # print "{0:0{1}x}".format(x, 1)
    # print "{0:0{1}x}".format(y, 1)
    # print "{0:0{1}x}".format(z, 1)
    # exit()

    #HMAC length is 40 bytes in 0-9a-f
    macLength=40
    macCharacters = "abcdef0123456789"
    numberOfRuns = 20
    try:
        for i in range(0,macLength):
            results=[0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0]
            #Simple time comparison is not enough now. We need to take several runs and use the one that is longest the most
            for k in range(0,numberOfRuns):
                maxRespTime = 0.0
                maxRespTimeCharacter = ""
                for j in macCharacters:
                    #Look for the longest response time, that;s probably the correct character
                    start = timer()
                    r = requests.head("http://localhost:8080/test?file=set4.hmacfile&signature="+testsig+j)
                    end = timer()
                    respTime = (end - start)
                    if (respTime>maxRespTime):
                        maxRespTime = respTime
                        maxRespTimeCharacter = j
                results[int(maxRespTimeCharacter,16)] = results[int(maxRespTimeCharacter,16)]+1
            # Now scan through the results array and find the one with the largest value
            largestValue = 0
            largestIndex = -1
            for i,j in enumerate(results):
                if (results[i] > largestValue):
                    largestValue = results[i]
                    largestIndex = i
            testsig = testsig + "{0:0{1}x}".format(largestIndex, 1)
        # At this point, we shoud have built up the signature.
        # Let's try it
        print "Trying: " + testsig
        r=requests.head("http://localhost:8080/test?file=set4.hmacfile&signature="+testsig)
        if(r.status_code == 200):
            print "Success!"
        else:
            print "Fail!"
        # prints the int of the status code. Find more at httpstatusrappers.com :)
    except requests.ConnectionError:
        print("failed to connect")

set4challenge32()
