#!/usr/bin/python
from set1 import *

plaintext = open('csis463.checkpoint1.txt', 'r').read()
key = "SECRETKEY"
ciphertext=vigenereCrypt(plaintext, key).decode("hex")

ciphertext = base64.encodestring(ciphertext )
print ciphertext

data= base64.b64decode(ciphertext)
print data
#print data.encode('hex')
#print len(data)
#print hammingDistance("this is a test", "wokka wokka!!!")
maxKeySize=42
results=bestVigenereDecrypt(data, maxKeySize, False)
print results[0]
print results[1]
