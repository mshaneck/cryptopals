#!/usr/bin/python
from set1 import *
from set2 import *
from set3 import *

#from __future__ import print_function
import struct
import io

try:
    range = xrange
except NameError:
    pass

def _left_rotate(n, b):
    """Left rotate a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def _process_chunk(chunk, h0, h1, h2, h3, h4):
    """Process a chunk of data and return the new digest variables."""
    assert len(chunk) == 64
    #print "Processing chunk: " + chunk.encode("hex")
    w = [0] * 80

    # Break chunk into sixteen 4-byte big-endian words w[i]
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i*4:i*4 + 4])[0]

    # Extend the sixteen 4-byte words into eighty 4-byte words
    for i in range(16, 80):
        w[i] = _left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

    # Initialize hash value for this chunk
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    for i in range(80):
        if 0 <= i <= 19:
            # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, a, _left_rotate(b, 30), c, d)

    # Add this chunk's hash to result so far
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4

class Sha1Hash(object):
    """A class that mimics that hashlib api and implements the SHA-1 algorithm."""

    name = 'python-sha1'
    digest_size = 20
    block_size = 64

    def __init__(self):
        # Initial digest variables
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )

        # bytes object with 0 <= len < 64 used to store the end of the message
        # if the message length is not congruent to 64
        self._unprocessed = b''
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0

    def setInternalState(self,h0,h1,h2,h3,h4, msgLen):
        self._h=(h0,h1,h2,h3,h4)
        self._message_byte_length = msgLen
        #print "State initialized to: " + "{0:0{1}x}".format(self._h[0],8) + ", " + "{0:0{1}x}".format(self._h[1],8) + ", "  + "{0:0{1}x}".format(self._h[2],8) + ", "  + "{0:0{1}x}".format(self._h[3],8) + ", " + "{0:0{1}x}".format(self._h[4],8)
        #print "Message length set to " + str(msgLen)

    def update(self, arg):
        """Update the current digest.
        This may be called repeatedly, even after calling digest or hexdigest.

        Arguments:
            arg: bytes, bytearray, or BytesIO object to read from.
        """
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)

        # Try to build a chunk out of the unprocessed data, if any
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            self._h = _process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)
            #print "State set to: " + "{0:0{1}x}".format(self._h[0],8) + ", " + "{0:0{1}x}".format(self._h[1],8) + ", "  + "{0:0{1}x}".format(self._h[2],8) + ", "  + "{0:0{1}x}".format(self._h[3],8) + ", " + "{0:0{1}x}".format(self._h[4],8)

        self._unprocessed = chunk
        return self


    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return '%08x%08x%08x%08x%08x' % self._produce_digest()

    def _produce_digest(self):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)
        #print "Msg Byte Len: " + str(message_byte_length)
        # append the bit '1' to the message
        padding = b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        padding += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        message_bit_length = message_byte_length * 8
        padding += struct.pack(b'>Q', message_bit_length)
        message += padding
        #print padding.encode("hex")
        #print "Padding length: " + str(len(padding))
        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.
        h = _process_chunk(message[:64], *self._h)
        #print "State set to: " + "{0:0{1}x}".format(h[0],8) + ", " + "{0:0{1}x}".format(h[1],8) + ", "  + "{0:0{1}x}".format(h[2],8) + ", "  + "{0:0{1}x}".format(h[3],8) + ", " + "{0:0{1}x}".format(h[4],8)

        if len(message) == 64:
            return h
        return _process_chunk(message[64:], *h)


def sha1(data):
    """SHA-1 Hashing Function
    A custom SHA-1 hashing function implemented entirely in Python.
    Arguments:
        data: A bytes or BytesIO object containing the input message to hash.
    Returns:
        A hex SHA-1 digest of the input message.
    """
    return Sha1Hash().update(data).hexdigest()

def sha1WithState(h0,h1,h2,h3,h4,data,origlen):
    s=Sha1Hash()
    s.setInternalState(h0,h1,h2,h3,h4,origlen)
    return s.update(data).hexdigest()

def edit(ciphertext, key, nonce, offset, newtext):
    # It seems to me that I will essentially just decrypt the whole thing, replace the plaintext with newtext, then reencrypt...
    # I suppose ideally I would generate just the piece that I need, but it's proof of concept stuff, right?
    plaintext = aes_128_ctr(ciphertext, key, nonce)
    newplaintext = plaintext[:offset] + newtext + plaintext[offset+len(newtext):]
    return aes_128_ctr(newplaintext, key, nonce)

def attackeredit(ciphertext, offset, newtext):
    return edit(ciphertext, consistent_key, consistent_nonce, offset, newtext)

def set4challenge25():
    x = base64.b64decode(open('set4.challenge25.txt', 'r').read())
    key = b'YELLOW SUBMARINE'
    cipher = AES.new(key, AES.MODE_ECB)
    recoveredPlaintext = cipher.decrypt(x)
    ctrCiphertext = aes_128_ctr(recoveredPlaintext, consistent_key, consistent_nonce)

    #print "Testing the edit function"
    #testpt = "Well hello there, pardner. How are you doing today?"
    #print "Plaintext: "
    #print testpt
    #cipher = aes_128_ctr(testpt, consistent_key, consistent_nonce)
    #newtext = "goodbye bub"
    #cipher = attackeredit(cipher, 5, newtext)
    #print aes_128_ctr(cipher, consistent_key, consistent_nonce)

    # use the attackeredit function to recover the plaintext
    newtext = "\x00"*len(recoveredPlaintext)
    newcipher = attackeredit(ctrCiphertext, 0, newtext)
    # now xor the newcipher with the ctrCiphertext
    originalPlaintext = hexxor(newcipher.encode("hex"), ctrCiphertext.encode("hex")).decode("hex")
    print originalPlaintext

#set4challenge25()

def c26_ctr_encrypt_oracle(plaintext):
    prefix="comment1=cooking%20MCs;userdata="
    suffix=";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = prefix+plaintext.replace(";","").replace("=","")+suffix
    return aes_128_ctr(plaintext, consistent_key, consistent_nonce)

def c26_ctr_decrypt_oracle(ciphertext):
    plaintext = aes_128_ctr(ciphertext, consistent_key, consistent_nonce)
    #print plaintext
    #print splitIntoBlocks(plaintext, 16)
    pairs = plaintext.split(";")
    for pair in pairs:
        keyValue = pair.split('=')
        #print keyValue[0], " = ", keyValue[1]
        if keyValue[0]=="admin" and keyValue[1]=="true":
            print "W00t W00t. You win!"
            return True
    print "FAIL!"

def set4challenge26():
    plaintext = "Zhis iZ a tester:admin<true"
    ciphertext=c26_ctr_encrypt_oracle(plaintext)
    #print ciphertext
    blocks = splitIntoBlocks(ciphertext.encode('hex'), AES.block_size*2)
    #print blocks
    #print blocks[3]
    x = "01000000000001000000000000000000"
    #print x
    blocks[3] = hexxor(x, blocks[3])
    #print blocks[3]
    #print blocks
    ciphertext = "".join(blocks).decode('hex')
    #print ciphertext
    c26_ctr_decrypt_oracle(ciphertext)

#set4challenge26()

c27key = b'YELLOW SUBMARINE'
# The directions for this one seema bit off. I'm going to just do it my own way. I think it captures the intent.
def c27_cbc_encrypt(plaintext):
    return aes_128_cbc(plaintext, c27key, c27key, ENCRYPT)

def c27_cbc_decrypt(ciphertext):
    plaintext = aes_128_cbc(c27key+ciphertext, c27key, c27key, DECRYPT)
    #print len(plaintext)
    #Check if any byte in the plaintext is high ascii, meaning over 127
    # If yes, return plaintext
    for s in plaintext:
        if (ord(s)>127):
            # This is our error condition, return the plaintext
            return plaintext
    return "Ok"

def set4challenge27():
    p1 = "A"*AES.block_size
    p2 = "B"*AES.block_size
    p3 = "C"*AES.block_size

    ciphertext = c27_cbc_encrypt(p1+p2+p3)
    c1 = ciphertext[:AES.block_size]
    modc = c1+'\x00'*AES.block_size+c1
    #print modc.encode("hex")
    #print len(modc)
    answer = c27_cbc_decrypt(modc)
    if (answer == "Ok"):
        print "Ok"
    else:
        print "Error condition..."
        #print len(answer)
        p1 = answer[:AES.block_size]
        p3 = answer[AES.block_size*2:]
        #print p1.encode("hex")
        #print p3.encode("hex")
        print hexxor(p1.encode("hex"),p3.encode("hex")).decode("hex")

#set4challenge27()

def sha1Mac(key, message):
    return sha1(key+message)

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

def verifyMac(msg, key, tag):
    checkTag = sha1Mac(key, msg)
    return (tag == checkTag)

def set4challenge28():
    #macKey = "yellow"
    macKey = random.choice(open("/usr/share/dict/words").readlines()).rstrip()
    #print "Key is " + macKey

    msg = "comment1=cooking MCs;userdata=foo;comment2= like a pound of bacon"
    hashMac = sha1Mac(macKey, msg)
    #print "HashMac of original: " + hashMac
    #print "Verifying mac on original:"
    res = verifyMac(msg, macKey, hashMac)
    if (not res):
        print "WHAT??"
        exit()

    #160 bits hash function
    h0=int(hashMac[0:8], 16)
    h1=int(hashMac[8:16], 16)
    h2=int(hashMac[16:24], 16)
    h3=int(hashMac[24:32], 16)
    h4=int(hashMac[32:], 16)

    additionalMsg = "comment3=yetsomemorecomments;admin=true"
    longestKeyLen=32
    originalMsgLen=len(msg)
    for i in range(1,longestKeyLen):
    #for i in range(len(macKey), len(macKey)+1):
        #print "\n\nGuessing " + str(i)
        #print "Original Msg Len plus key length:" + str(originalMsgLen+i)
        padding = getGluePadding(originalMsgLen+i)
        #print padding.encode("hex")
        #print len(padding)
        tag = sha1WithState(h0,h1,h2,h3,h4,additionalMsg,originalMsgLen+i+len(padding))
        #print "We got                 " + tag
        #print "We should have gotten: " + sha1Mac(macKey, msg+padding+additionalMsg)
        if(verifyMac(msg+padding+additionalMsg, macKey, tag)):
            print "We win! Key length is " + str(i)
            print "Forged Mac for "+msg+padding+additionalMsg
            exit()
    print "Did not forge the message... :("


set4challenge28()
