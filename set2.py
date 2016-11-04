#!/usr/bin/python
from Crypto.Cipher import AES

def pkcs7Padding(data, blocksize):
    # First determine how much is needed
    bytesNeeded = blocksize-len(data)%blocksize
    return data + chr(bytesNeeded)*bytesNeeded

def set2challenges9():
    print pkcs7Padding("YELLOW SUBMARINE", 20)
    print pkcs7Padding("Testing Testing 123", 10)
    print pkcs7Padding("This is a test", 14)
    print pkcs7Padding("Test2", 75)

#set2challenge()

def aes-128-ecb(input, key, mode):
    cipher = AES.new(key, AES.MODE_ECB)
    y = ""
    if (mode == "decrypt"):
        return cipher.decrypt(input)
    else:
        return cipher.encrypt(input)

def aes-128-cbc(input, key, iv):



