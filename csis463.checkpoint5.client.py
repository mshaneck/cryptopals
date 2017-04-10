#!/usr/bin/python
from set1 import *
from set2 import *

from hashing import *
import sys, getopt, socket

BUFFER_SIZE = 2048
port=4635
host="127.0.0.1"

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
    readFile = sock.makefile()
    message = readFile.readline().rstrip()
    print "Message: " + message
    mac = readFile.readline().rstrip()
    print "MAC: " + mac


    #160 bits hash function
    h0=int(mac[0:8], 16)
    h1=int(mac[8:16], 16)
    h2=int(mac[16:24], 16)
    h3=int(mac[24:32], 16)
    h4=int(mac[32:], 16)

    additionalMsg = "this is a longer message that I am adding to the initial message"
    longestKeyLen=32
    originalMsgLen=len(message)
    for i in range(1,longestKeyLen):
    #for i in range(len(macKey), len(macKey)+1):
        print "Guessing " + str(i) + " for key length"
        #print "Original Msg Len plus key length:" + str(originalMsgLen+i)
        padding = getGluePadding(originalMsgLen+i)
        #print padding.encode("hex")
        #print len(padding)
        tag = sha1WithState(h0,h1,h2,h3,h4,additionalMsg,originalMsgLen+i+len(padding))
        print "We got                 " + tag
        #print "We should have gotten: " + sha1Mac(macKey, msg+padding+additionalMsg)
        print "Sending..."
        sock.send(message+padding+additionalMsg+"\n")
        sock.send(tag+"\n")
        print "Sent the message and MAC"
        response = readFile.readline().rstrip()
        print "Got a response:"
        print response
        if (response == "True"):
            print "We win! Key length is " + str(i)
            print "Forged Mac for "+message+padding+additionalMsg
            response = readFile.readline().rstrip()
            while("END" not in response):
                print response
                response = readFile.readline()
            exit()
    print "Did not forge the message... :("


except socket.error:
    print >>sys.stderr, "Error while communicating with server"
    exit(1)
