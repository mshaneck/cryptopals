#!/usr/bin/python

import binascii
import base64
import string
from fractions import gcd
from Crypto.Cipher import AES

#Set 1, Challenge 1
def convertHexToBase64(hexString):
    byteString=hexString.decode('hex')
    return base64.b64encode(byteString)    
#print convertHexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
#print convertHexToBase64("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
#exit()

#Set 1, Challenge 2
def hexxor(hexStr1, hexStr2):
    assert len(hexStr1) == len(hexStr2)
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
    ciphertextlen = len(ciphertext)/2 
    #print ciphertextlen
    bestKey=-1
    maxScore=-1
    bestPlaintext=""
    for i in range(256):
        plaintext = xorDecrypt(ciphertext, ciphertextlen, i).decode('hex')
        score=englishScore(plaintext)
        #print score, plaintext
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
    #print ciphertext
    #print key
    hexplain=hexxor(ciphertext, key)
    #print hexplain
    #print ""
    return hexplain

def englishScore(hexStr):
    #First ensure that all characters are printable
    #if all(c in string.printable for c in hexStr):
        # compute count of alphabet characters over total string length
        # rudimentary but seems to work for this example...
        letterCount=0
        for c in hexStr:
            if c.isalpha() or c==" " or c=="'" or c=="." or c=="," or c=="?" or c=="!":
                letterCount=letterCount+1
            if c.upper() in "ETAOIN SHRDLU":
                letterCount=letterCount+1
        #print letterCount, len(hexStr)
        baseScore = float(letterCount)/len(hexStr)
        #words=hexStr.split(" ")
        # somehow incorporate the word count into the score
        #baseScore = baseScore + float(len(words))/len(hexStr)
        return baseScore
    #else:
        #return 0.0

#set1challenge3()
#print "Exiting..."
#exit()

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
#exit()

def vigenereCrypt(plain, key):
    #First make the key the same length as the plaintext
    hexPlain=plain.encode('hex')
    xorkey = key.encode('hex')
    #print xorkey
    #print hexPlain
    xorkey = xorkey*len(hexPlain)
    xorkey = xorkey[0:len(hexPlain)]
    #print hexPlain
    #print xorkey

    #Then hexxor
    return hexxor(hexPlain, xorkey)
    
def set1challenge5():
    plaintext="""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    key="ICE"
    print vigenereCrypt(plaintext, key)

#set1challenge5()
#exit()

def hammingDistance(string1, string2):
    assert len(string1)==len(string2)
    distance=0
    for i,c in enumerate(string1):
        x = ord(c)^ord(string2[i:i+1])
        while (x):
            x = x&(x-1)
            distance=distance+1
    return distance

def getNAvgHammingDistances(data, maxKeyLength):
    avgHDs = []
    datalen=len(data)
    for keysize in range(2, maxKeyLength):
        #Take as many hamming distances as possible
        hd=0
        for i in range(0, datalen/(keysize*2)):
            str1 = data[keysize*2*i:keysize*(2*i+1)]
            str2 = data[keysize*(2*i+1):keysize*(2*i+2)]
            hd = hd+hammingDistance(str1, str2)
        #average hamming distance between substrings
        hd = float(hd)/float(datalen/(keysize*2))
        #normalize it based on keysize
        hd = hd/float(keysize)
        avgHDs.append([hd, keysize])

        #str1=data[0:keysize]
        #str2=data[keysize:2*keysize]
        #str3=data[2*keysize:3*keysize]
        #str4=data[3*keysize:4*keysize]
        #hd1 = hammingDistance(str1, str2)
        #hd2 = hammingDistance(str3, str4)
        #hd = (float(hd1+hd2)/2.0)/float(keysize)
        #avgHDs.append([hd, keysize])
    avgHDs.sort()
    #print avgHDs
    return avgHDs

def set1challenge6():
    with open('set1.challenge6.txt', 'r') as myfile:
            data=myfile.read().replace('\n', '')
    data= base64.b64decode(data)
    #print data.encode('hex')
    #print len(data)
    #print hammingDistance("this is a test", "wokka wokka!!!")
    maxKeySize=42

    hds = getNAvgHammingDistances(data, maxKeySize)
    #print "Best keysize and distance: ", hds[0][1], hds[0][0]
    #print "Second best keysize and distance: ", hds[1][1], hds[1][0]
    #split the data into chunks of size bestKeySize

    # Algorithm idea from https://trustedsignal.blogspot.com/2015/06/xord-play-normalized-hamming-distance.html
    gcd12=gcd(hds[0][1], hds[1][1])
    gcd13=gcd(hds[0][1], hds[2][1])
    gcd23=gcd(hds[1][1], hds[2][1])
    bestKeySize=-1
    if (gcd12 != 1):
        # This next one could possibly be improved to search a configurable top n
        if (gcd12 == hds[0][1] or gcd12 == hds[1][1] or gcd12 == hds[2][1] or gcd12 == hds[3][1]):
            if (gcd12==gcd13 and gcd12==23) or (gcd12 == hds[0][1] or gcd12==[1][1]):
                bestKeySize=gcd12
    if (bestKeySize == -1):
        bestKeySize=hds[0][1]

    lines=[data[i:i+bestKeySize] for i in range(0, len(data), bestKeySize)]
    rearrangedLines=""

    for i in range(0,bestKeySize):
        for line in lines:
            try:
                rearrangedLines+=line[i]
            except IndexError:
                continue
      
    vigenereLines=[rearrangedLines[i:i+len(lines)] for i in range(0,len(data), len(lines))]
    #print vigenereLines
    i=0
    vigenereKeys=""
    #print vigenereLines

    for line in vigenereLines:
        #print '--------------------------'
        #print len(line)
        #print line.encode('hex')
        vigenereKey, vigenereScore, vigenerePlaintext=bestDecryption(line.encode('hex'))
        #print vigenereKey, vigenereScore
        vigenereKeys+="{0:0{1}x}".format(vigenereKey,2)
    maybePlain = vigenereCrypt(data, vigenereKeys.decode('hex')).decode('hex')
    #print maybePlain
    score =englishScore(maybePlain)
    #print score
    print maybePlain
    print vigenereKeys.decode('hex')
    

#set1challenge6()


def set1challenge7():
    x = base64.b64decode(open('set1.challenge7.txt', 'r').read())
    print "Decrypting AES ECB mode"
    key = b'YELLOW SUBMARINE'
    cipher = AES.new(key, AES.MODE_ECB)
    y = cipher.decrypt(x)
    print(y)

#set1challenge7()

def set1challenge8():
    


set1challenge8()    
