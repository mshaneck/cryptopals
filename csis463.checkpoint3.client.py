#!/usr/bin/python
from set1 import *
from set2 import *

import sys, getopt, socket

BUFFER_SIZE = 2048
port=4633
host="10.101.1.10"

def cbcPaddingOracleGuess(cipherblock, guess, byte, currentPlaintext):
    # currentPlaintext is what we know so far about the block
    # It will go at the end and will get xor'd with its length
    # cipherblock is the block to modify
    # guess is our guess
    # byte is the byte position from 0 to 15

    paddingValue = 16-byte
    #print "Guessing ", guess
    mask = "00"*byte + "{0:0{1}x}".format(paddingValue,2)*paddingValue
    guessblock = "00"*(byte)+"{0:0{1}x}".format(guess,2)+currentPlaintext
    #print mask
    #print guessblock
    #print cipherblock
    mask = hexxor(mask, guessblock)
    mask = hexxor(mask, cipherblock)
    return mask

def challenge17_consumeCiphertext(ciphertext, sock):
    sock.send(ciphertext)
    result = sock.recv(BUFFER_SIZE)
    return result.rstrip() == "True"

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
try:
    ciphertext = sock.recv(BUFFER_SIZE).rstrip().decode("hex")
    plaintext = ""
    ctxtBlocks = splitIntoBlocks(ciphertext.encode('hex'), 32)
    #print ctxtBlocks
    # CBC Padding Oracle Attack
    # Guess from 0 to 255 the last byte of block 1
    # Take block 0 and XOR the last byte with guess and 01
    # Check if padding is correct
    # If yes, guess is correct
    # Set byte equal to guess
    # Guess second to last byte of block 1
    # Take block 0 and XOR the second to last byte with guess and 02 and last byte with known and 02
    lastBlock=False

    # Repeat entire thing for each block
    # We will actually be guessing for the next block, since that is the one that will have the padding check
    for block in range(len(ctxtBlocks)-1):
        # Problem: If the block is the last block, you can't really guess 01 as the last byte
        # In fact the last block has several problems, since there is actual padding

        # In fact, for the last block, the last byte should be the padding block
        # So we can skip those final bytes...
        if (block == len(ctxtBlocks)-2):
            #print "We are working on the last block"
            lastBlock = True

        decryptedBlock = ""
        paddingStart = -1
        #print "Guessing block ", block
        # Repeat for each byte in the block, increasing the padding guess and building up the final parts
        for byte in range(16):
            # We will be guessing byte 16-byte-1
            i=16-byte-1
            lastByte = False
            if (lastBlock and i==15):
                lastByte=True
                #print "Guessing the last byte of the ciphertext"
            #print "    Guessing byte ", i, " (really ", byte, ")"

            guessedLastByte = False
            # Each guess of b for byte i
            for b in range(256):
                # Guessing value of b for byte i of block+1
                modblock = cbcPaddingOracleGuess(ctxtBlocks[block], b, i, decryptedBlock.encode('hex'))
                # Send the modified block and the next block to the oracle
                if (challenge17_consumeCiphertext((modblock+ctxtBlocks[block+1]), sock)):
                    # Padding is correct, so our guess is right
                    if (lastByte and b==1):
                        # this may not be correct
                        # keep going and try to see if another one matches. If it does, that is correct, otherwise, this is the last byte
                        guessedLastByte = False
                        continue
                    decryptedBlock = chr(b)+decryptedBlock
                    #print decryptedBlock
                    guessedLastByte = True
                    break
            if (lastByte and not guessedLastByte):
                decryptedBlock = chr(1)+decryptedBlock


        #print decryptedBlock
        plaintext = plaintext + decryptedBlock
        print plaintext
    print removePkcs7Padding(plaintext, 16)
    #challenge17_consumeCiphertext(ciphertext)
except socket.error:
    print >>sys.stderr, "Error while communicating with server"
    exit(1)
