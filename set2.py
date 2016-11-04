#!/usr/bin/python

def pkcs7Padding(data, blocksize):
    # First determine how much is needed
    bytesNeeded = blocksize-len(data)%blocksize
    print bytesNeeded

def set2challenge1():
    print pkcs7Padding("YELLOW SUBMARINE", 20)
    print pkcs7Padding("Testing Testing 123", 10)
    print pkcs7Padding("This is a test", 14)

set2challenge1()
