#!/usr/bin/python
from set1 import *

import sys, getopt, socket

BUFFER_SIZE = 2048
port=4632
host="127.0.0.1"

def checkpoint2_oracle(plaintext, sock):
    if (plaintext == ""):
        plaintext = "NULL"
    sock.send(plaintext)
    #print "Sending: " + plaintext
    resp = sock.recv(BUFFER_SIZE)
    #print "Received: " + resp
    return resp.decode("hex")

def splitIntoBlocks(data, blockSize):
    o = []
    while(data):
        o.append(data[0:blockSize])
        data = data[blockSize:]
    return o

def addToDecryptionDictionary(prefixStr, crackDict, blockNumber, blockSize, sock):
    for c in range(256):
        block = getHexBlock(checkpoint2_oracle(prefixStr+chr(c), sock), blockNumber, blockSize)
        crackDict[block] = chr(c)


def getHexBlock(ciphertext, i, blockSize):
    block = ciphertext.encode('hex')[(i*blockSize)*2: (i+1)*blockSize*2]
    #print "------"
    #print block
    #print (i*blockSize)*2
    #print (i+1)*blockSize*2
    #print "------"
    return block


print "Connecting to port " + str(port)
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    #print >>sys.stderr, 'connecting to %s port %s' % server_address
    sock.connect(server_address)
    print 'Connected to %s port %s' % server_address
except socket.error:
    print >>sys.stderr, "Could not connect to the server"
    exit(1)


A="A"
# Discover block size by feeding ECB oracle increasing size inputs to discover the block size
ctxtlen=len(checkpoint2_oracle("", sock))
blockSize=-1
for i in range(64):
    ctxt = checkpoint2_oracle(A*i, sock)
    if len(ctxt) > ctxtlen:
        blockSize = len(ctxt)-ctxtlen
        #print blockSize
        break
#print blockSize

# detect that it is using ECB mode
# Need to use 3 blocks of A since we don't know how long the prefix string is
if (isECB(checkpoint2_oracle(A*(3*blockSize), sock))):
    usingECB=True
    #print "Using ECB"
else:
    print "Not using ECB"
    exit(1)

blocks = splitIntoBlocks(checkpoint2_oracle(A*(3*blockSize), sock).encode('hex'), blockSize*2)
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
    ciphertext = checkpoint2_oracle(testplaintext, sock)
    blocks=splitIntoBlocks(ciphertext.encode('hex'), blockSize*2)
    if (blocks[x] == blocks[y]):
        offset=i
        break

print "Offset is ", offset

# Compute the number of unknown blocks
numberOfUnknownBlocks = len(checkpoint2_oracle("", sock))/blockSize - x

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
        addToDecryptionDictionary(A*offset + A*(blockSize-i-1)+decryptedMessage, crack, j+x, blockSize, sock)
        block = getHexBlock(checkpoint2_oracle(A*offset + A*(blockSize-i-1), sock), j+x, blockSize)

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
print "Decrypted:"
print decryptedMessage.rstrip('\n') # Rstrip since the plaintext already includes a newline
