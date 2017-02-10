#!/usr/bin/python
from Crypto.Cipher import AES
from Crypto.Random import random
import sys, getopt, socket
import threading
from set2 import *
import traceback

consistentKey = getRandomAESKey()
consistentIV = getRandomAESKey()
targetBytes = "Now, what y'all wanna do?\nWanna be hackers? Code crackers? Slackers\nWastin' time with all the chatroom yakkers?\n9 to 5, chillin' at Hewlett Packard?"
targetCiphertext = aes_128_cbc(pkcs7Padding(targetBytes, AES.block_size), consistentKey, consistentIV, ENCRYPT)
pt = aes_128_cbc(targetCiphertext, consistentKey, "", DECRYPT)
BUFFER_SIZE = 20480
port=4633


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        # print "Initial plaintext:"
        # print pt
        # print "Initial Ciphertext:"
        # print targetCiphertext.encode("hex")
        while True:
            client, address = self.sock.accept()
            print "Received a new connection from " + str(address)
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):

        # First send the ciphertext
        client.send(targetCiphertext.encode("hex"))

        while True:
            try:
                #data = client.recv(size)
                studentBytes = client.recv(BUFFER_SIZE)
                #print "Received " + str(len(studentBytes)) + " from client"
                if studentBytes:
                    # Decrypt the message from the student and determine if padding is correct.
                    # IV is expected to be in the first block
                    #print "Decrypting..."
                    decrypted = aes_128_cbc(studentBytes.rstrip().decode("hex"), consistentKey, "", DECRYPT)
                    #print decrypted
                    if (isPkcs7PaddingValid(decrypted, AES.block_size)):
                        client.send("True")
                    else:
                        client.send("False")

                else:
                    raise error('Client disconnected')
            except Exception as e:
                # traceback.print_exc()
                # print "ERROR"
                # print str(e)
                client.close()
                return False

if __name__ == "__main__":
    ThreadedServer('',port).listen()
