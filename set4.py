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

set4challenge25()
