#!/usr/bin/python
from Crypto.Cipher import AES
from Crypto.Random import random
import sys, getopt, socket
import threading

# This is a server that will read in plaintext bytes, prepend a consistent random string and append some target bytes and AES ECB encrypt them
# and returns the ciphertext

def getRandomString():
    length = random.randint(1,200)
    randStr = "{0:0{1}x}".format(random.getrandbits(length*8), length*2).decode('hex')
    return randStr
def getRandomAESKey():
    return "{0:0{1}x}".format(random.getrandbits(128), 32).decode('hex')

consistentKey = getRandomAESKey()
randomString = getRandomString()
targetBytes = "And exploit development, encrypted tunnels too\nThe kid was a natural, he knew just what to do"

BUFFER_SIZE = 20480
port=4632
ENCRYPT="e"
DECRYPT="d"

def aes_128_ecb(input, key, mode):
    cipher = AES.new(key, AES.MODE_ECB)
    if (mode == DECRYPT):
        #print "Decrypting ", input.encode('hex')
        return cipher.decrypt(input)
    else:
        #print "Encrypting ", input.encode('hex')
        return cipher.encrypt(input)
def pkcs7Padding(data, blockSize):
    # First determine how much is needed
    bytesNeeded = blockSize-len(data)%blockSize
    return data + chr(bytesNeeded)*bytesNeeded

# #create an INET, STREAMing socket
# serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #bind the socket to a public host,
# # and a well-known port
# print "Listening on port " + str(port)
# serversocket.bind(('0.0.0.0', port))
# #become a server socket
#
# serversocket.listen(15)
#
# while 1:
#     #accept connections from outside
#     (clientsocket, address) = serversocket.accept()
#     print "Got a connection!"
#
#     studentBytes = clientsocket.recv(BUFFER_SIZE)
#     print "Received from student: " + studentBytes
#     ciphertext = aes_128_ecb(pkcs7Padding(randomString+studentBytes+targetBytes, AES.block_size), consistentKey, ENCRYPT)
#     print "Sending: " + ciphertext.encode("hex")
#     clientsocket.send(ciphertext.encode("hex"))
#
#     clientsocket.close()
#


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            print "Received new connection from " + str(address)
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):

        while True:
            try:
                #data = client.recv(size)
                studentBytes = client.recv(BUFFER_SIZE)

                if studentBytes:
                    # Set the response to echo back the recieved data
                    #print "Received from student: " + studentBytes
                    if (studentBytes == "NULL"):
                        studentBytes = ""
                    ciphertext = aes_128_ecb(pkcs7Padding(randomString+studentBytes+targetBytes, AES.block_size), consistentKey, ENCRYPT)
                    #print "Sending: " + ciphertext.encode("hex")
                    client.send(ciphertext.encode("hex"))
                    # response = data
                    # client.send(response)
                else:
                    raise error('Client disconnected')
            except:
                client.close()
                return False

if __name__ == "__main__":
    ThreadedServer('',port).listen()
