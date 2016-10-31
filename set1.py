#!/usr/bin/python
#Now with source control

import binascii
import base64
import string

#Set 1, Challenge 1
def convertHexToBase64(hexString):
    byteString=binascii.unhexlify(hexString)
    return base64.b64encode(byteString)    
#print convertHexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

#Set 1, Challenge 2
def hexxor(hexStr1, hexStr2):
    return "{0:0{1}x}".format(int(hexStr1, 16) ^ int(hexStr2, 16), len(hexStr1))
#print hexxor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")

#Set 1, Challenge 3
def set1challenge3():
    ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key, score, plaintext=bestDecryption(ciphertext)
    print "Challenge 3 answer"
    print key, score
    print plaintext

def bestDecryption(ciphertext):
    ciphertextlen = len(ciphertext)/2 #34
    #print ciphertextlen
    bestKey=-1
    maxScore=-1
    bestPlaintext=""
    for i in range(256):
        plaintext = xorDecrypt(ciphertext, ciphertextlen, i).decode('hex')
        score=englishScore(plaintext)
        if score > maxScore:
            maxScore=score
            bestKey=i
            bestPlaintext = plaintext
    #print bestKey, maxScore
    #print bestPlaintext
    return (bestKey, maxScore, bestPlaintext)

def xorDecrypt(ciphertext, ciphertextlen, key):
    key="{0:0{1}x}".format(key,2)
    key=key*ciphertextlen
    hexplain=hexxor(ciphertext, key)
    return hexplain

def englishScore(hexStr):
    #First ensure that all characters are printable
    if all(c in string.printable for c in hexStr):
        # compute count of alphabet characters over total string length
        # rudimentary but seems to work for this example...
        letterCount=0
        for c in hexStr:
            if c.isalpha():
                letterCount=letterCount+1
        #print letterCount, len(hexStr)
        return float(letterCount)/len(hexStr)
    else:
        return 0.0

#set1challenge3()

def set1challenge4():
    #read in each line of the file set1.challenge4.txt
    with open("set1.challenge4.txt") as f:
        i=1
        maxScore=0
        bestPlaintext=""
        bestLine=-1
        for line in f:
            key, score, plaintext=bestDecryption(line.rstrip())
            if (score>maxScore):
                maxScore=score
                bestPlaintext=plaintext
                bestKey=key
                bestLine=i
            i=i+1
        print "Plaintext number", bestLine
        print bestPlaintext, " (", bestKey, ")"

#set1challenge4()

def set1challenge5():
    plaintext="""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    key="ICE"
    #First make the key the same length as the plaintext
    hexPlain=plaintext.encode('hex')
    xorkey = key.encode('hex')
    #print xorkey
    xorkey = xorkey*len(hexPlain)
    xorkey = xorkey[0:len(hexPlain)]
    #print hexPlain
    #print xorkey

    #Then hexxor
    print hexxor(hexPlain, xorkey)
    
set1challenge5()

