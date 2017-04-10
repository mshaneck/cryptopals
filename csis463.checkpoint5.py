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
superSecretMessage = """
I begin every sentence with an apology
Sorry that's the case. That's just British policy
Probably the case with, everything in honesty
I use ten words when two would do, honestly

I'm British

And that makes me unique
At least I think so, when I hear you speak
See we used to have an empire, but we got a little cocky
Like haha, Johnny foreigner, I'd like to see you stop me
And sure enough, we rhubarb crumbled
Now in every town, all the drunk teens stumble
I'm rather glad really, it made us more humble
Come and ask me where I'm from, dear boy, I won't mumble

I'm British

I don't want to be fantastic
Just adequate, and if I'm nice it's probably sarcastic
Ridiculously cynical that's what we're like
If you can't take a joke, get on your bike

I'm British

Like a clotted cream tea
Apologetic Morris dancer then you must be me

I'm British

Like the wickets in Cricket
Like crikey, blimey, nice one, wicked

I'm British
As a fat dame in a panto
Like Wodehouse, Orwell, Wells and Poe
So if you're down with the Brits then make some noise
But if you'd rather not, that's fine
We're ever so nice to our pets
And we know not to work too hard
We're inventive, accepting, eccentric
And yes, I suppose we're a bit bizarre
But if you delight in celebrities taken down
Just because of the way they live
Or you can feel bleak joy in a seaside town as the rain pours down on your chips
Or you can drink ten pints of Admirals
Without ever breaking your stride
Or repress your emotions and passions
And bury them deep inside
Then I've kept a room in a cramped B&B
With a TV that only shows BBC2
And I have the keys right here
I've been keeping them just for you

I'm British

As Williams, James, Hattie Jacques
School dinners, roast dinners, massive cakes

I'm British

As a chimney sweep
Chim chim cheree!
Or a professor in a pith accompanied by Chimpanzees
So if you're down with the Brits then put your hands in the air
But if you'd rather not, that's fine, actually
I mean I don't want to cause too much of a fuss

Well, at this point I'd just like to take a moment to apologise on behalf of Britain for all the things that we've brought to the world
Simon Cowell, for example, and eh, Jim Davidson. Fox hunting. Black pudding. Racism
But most of all, we're all terribly, terribly sorry about Piers Morgan"""


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
                                client.send(superSecretMessage+"\nEND\n")
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
