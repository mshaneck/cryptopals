#!/usr/bin/python
import sys, getopt, socket
import hashlib
from Crypto.Random import random
from hashing import *
from rsa_utils import *


BUFFER_SIZE = 2048

def main(argv):
    port=63079
    try:
        opts, args = getopt.getopt(argv,"p:",["port="])
    except getopt.GetoptError:
        print 'c41server.py -p <listen port> '
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-p", "--port"):
            port = int(arg)

    print "Generating RSA credentials"
    (e,d,n) = genRsa(2048, 15)
    print n
    print "Challenge ciphertext: "
    secretmessage = "This is a super sekret message. It is totally secure from unauthorized access. TOP SEKRET! Also, this message apparently needs to be much longer or else it is the same each time, since it doesnt wrap around and thus is vulnerable to the last challenge attack"
    ciphertext = rsaStringEncrypt(secretmessage,e,n)
    print ciphertext

    testmessage = "This is a test message. You know, for testing purposes"
    print "Testing message:"
    print rsaStringEncrypt(testmessage,e,n)

    #create an INET, STREAMing socket
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #bind the socket to a public host,
    # and a well-known port
    print "Listening on port " + str(port)
    serversocket.bind(('127.0.0.1', port))
    #become a server socket

    serversocket.listen(5)

    while 1:
        #accept connections from outside
        (clientsocket, address) = serversocket.accept()
        print "Got a connection!"

        cipher = int(clientsocket.recv(BUFFER_SIZE))
        print cipher
        if (cipher == ciphertext):
            # Not allowed...
            clientsocket.send("NO NO NO. BAD!")
        else:
            plaintext = str(rsaDecrypt(cipher,d,n))
            #print "Sending:"
            #print plaintext
            clientsocket.send(plaintext)

        clientsocket.close()

    serversocket.close()
    exit(0)

if __name__ == "__main__":
   main(sys.argv[1:])
