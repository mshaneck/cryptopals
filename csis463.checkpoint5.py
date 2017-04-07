#!/usr/bin/python
from Crypto.Cipher import AES
from Crypto.Random import random
import sys, getopt, socket
import threading
from set2 import *
from hashing import *
import traceback

consistentKey = "SomeKey"
initial_message = "This is a message. This is only a message. If this were real information, something interesting would be in here..."
BUFFER_SIZE = 20480
port=4635
superSecretMessage = "This super secret message is totally lame. Replace it with something interesting..."

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

        # First send the message
        client.send(initial_message+"\n")
        # Next send the MAC
        client.send(sha1Mac(consistentKey, initial_message)+"\n")
        readFile = client.makefile()
        while True:
            try:
                #data = client.recv(size)
                print "Waiting for client data..."
                studentMessage = readFile.readline().rstrip()
                print "Received message: " + studentMessage
                studentMAC = readFile.readline().rstrip()
                print "Received MAC: " + studentMAC
                if studentMessage:
                    # Verify the MAC
                    print "Verifying the MAC"
                    MACShouldBe = sha1Mac(consistentKey, studentMessage)
                    print MACShouldBe
                    print studentMAC
                    if (MACShouldBe == studentMAC):
                        print "MAC verifies"
                        client.send("True\n")
                        if (studentMessage.startswith(initial_message)):
                            print "Message starts with right prefix"
                            if (studentMessage == initial_message):
                                print "Message was not the correct one"
                                client.send("But was that really so difficult? You just sent the same message and MAC that I sent in the beginning... \n")
                                client.send("Try harder...\n")
                            else:
                                print "There you have it?"
                                client.send("Way to be!!!!!\n")
                                client.send(superSecretMessage+"\n")
                        else:
                            print "Say what?"
                            client.send("But you are supposed to extend the initial message\n")
                            client.send("In fact, how did you even do this? It shouldn't be possible...\n")
                    else:
                        print "FAIL"
                        client.send("False\n")

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
