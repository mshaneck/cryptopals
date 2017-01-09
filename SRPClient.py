#!/usr/bin/python
import sys, getopt, socket
import hashlib
from Crypto.Random import random
from hashing import *
BUFFER_SIZE = 1024

# If these get changed, copy over to SRPServer.py
N=0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
g = 2
k=3
I="shaneck@gmail.com"
P="fiddlesticks"


def SRPClient(conn):
    print "Initiating SRP Protocol"

    #Send I, A=g**a % N (a la Diffie Hellman)
    # C -> S: I, A
    conn.send(I)
    a = random.randint(2,N)
    A = pow(g,a,N)
    print "Sending A"
    print str(A)
    conn.send(str(A))

    # S -> C: salt, B
    salt = int(conn.recv(BUFFER_SIZE))
    B = int(conn.recv(BUFFER_SIZE))
    print "Salt:"
    print salt
    print "B:"
    print B

    # S,C compute u= SHA256(A|B)
    u=int(hashlib.sha256(str(A)+str(B)).hexdigest(), 16)
    print "U:"
    print u

    # C compute K
    #xH=SHA256(salt|password)
    x = int(hashlib.sha256(str(salt)+P).hexdigest(), 16)
    # S = (B - k * g**x)**(a + u * x) % N
    S = pow(B - (k*pow(g,x,N)),a+(u*x),N)
    # K = SHA256(S)
    K = int(hashlib.sha256(str(S)).hexdigest(), 16)
    print "S Client:"
    print S
    print "K:"
    print K

    #Send HMAC-SHA256(K, salt)
    M = hmac_sha256(str(K), str(salt))
    print "Sending M:"
    print M
    conn.send(M)

    # Receive verification result
    msg = conn.recv(BUFFER_SIZE)
    if (msg == "OK"):
        print "Wonderful!"
    else:
        print "FAILED!!"

def main(argv):
    port=63079
    try:
        opts, args = getopt.getopt(argv,"p:",["port="])
    except getopt.GetoptError:
        print 'SRPClient.py -p <listen port> '
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-p", "--port"):
            port = int(arg)

    print "Connecting to port " + str(port)
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Connect the socket to the port where the server is listening
        server_address = ('localhost', port)
        print >>sys.stderr, 'connecting to %s port %s' % server_address
        sock.connect(server_address)
        print >>sys.stderr, 'connected to %s port %s' % server_address

    except socket.error:
        print >>sys.stderr, "Could not connect to the server"
        exit(1)

    SRPClient(sock)
    sock.close()
    exit(0)

if __name__ == "__main__":
   main(sys.argv[1:])
