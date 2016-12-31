#!/usr/bin/python
from set1 import *
from set2 import *
from set3 import *

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

set4challenge27()
