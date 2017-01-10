#!/usr/bin/python
import sys, getopt, socket
import hashlib
from Crypto.Random import random
from hashing import *


BUFFER_SIZE = 1024

# If these get changed, copy over to SRPClient.py
N=0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
g = 2
k=3
I="shaneck@gmail.com"
P="fiddlesticks"

def SRPServer(conn, password, simpleSRP):
    print "Initiating SRP Protocol"
    P=password
    # Initialize. This would normally be done ahead of time
    salt=random.getrandbits(32)
    x = int(hashlib.sha256(str(salt)+P).hexdigest(), 16)
    v=pow(g,x,N)
    #Save everything except x
    x=0

    # C -> S: I, A
    I = conn.recv(BUFFER_SIZE)
    A = int(conn.recv(BUFFER_SIZE))
    print "I:"
    print I
    print "A:"
    print A

    # S -> C: salt, B
    print "Sending salt:"
    print salt
    conn.send(str(salt))
    b = random.randint(2,N)
    B = k*v + pow(g,b,N)
    if (simpleSRP):
        B = pow(g,b,N)
    print "Sending B:"
    print B
    conn.send(str(B))
    if (simpleSRP):
        u = random.getrandbits(128)
        print "Sending Random U: "
        print str(u)
        conn.send(str(u))
    else:
        # S,C compute u= SHA256(A|B)
        u=int(hashlib.sha256(str(A)+str(B)).hexdigest(), 16)
        print "U:"
        print u

    # S compute K
    #S = (A * v**u) ** b % N
    S = pow(( A*pow(v,u,N) ),b,N)
    #K = SHA256(S)
    K = int(hashlib.sha256(str(S)).hexdigest(), 16)
    print "S Server:"
    print S
    print "K:"
    print K

    M = conn.recv(BUFFER_SIZE)
    print "Received M:"
    print M
    if (verifySHA256Mac(str(salt), str(K), M)):
        print "OK"
        conn.send("OK")
    else:
        conn.send("FAIL")


def main(argv):
    port=63079
    simpleSRP = False
    try:
        opts, args = getopt.getopt(argv,"p:s",["port=", "simple"])
    except getopt.GetoptError:
        print 'SRPServer.py -p <listen port> '
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-p", "--port"):
            port = int(arg)
        if opt in ("-s", "--simple"):
            simpleSRP = True


    password = random.choice(open("/usr/share/dict/words").readlines()).rstrip()
    print "Using password: " + password
    #create an INET, STREAMing socket
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #bind the socket to a public host,
    # and a well-known port
    print "Listening on port " + str(port)
    serversocket.bind(('127.0.0.1', port))
    #become a server socket
    serversocket.listen(5)

    #while 1:
    #accept connections from outside
    (clientsocket, address) = serversocket.accept()
    print "Got a connection!"

    SRPServer(clientsocket, password, simpleSRP)

    clientsocket.close()
    serversocket.close()
    exit(0)

if __name__ == "__main__":
   main(sys.argv[1:])
