#from __future__ import print_function
import struct
import io
from set1 import *
from set2 import *
import hashlib

def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))

def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return x ^ y ^ z

class MD4(object):
    def __init__(self, data=""):
        self.remainder = data
        self.count = 0
        self.h = [
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476
                ]
        #print "Initial State: " + str(self.h)

    def setInternalState(self,hstate, chunks):
        self.h[0]=hstate[0]
        self.h[1]=hstate[1]
        self.h[2]=hstate[2]
        self.h[3]=hstate[3]
        self.count = chunks
        #print "State initialized to: " + str(self.h)
        #print "Message length set to " + str(chunks)

    def _add_chunk(self, chunk):
        self.count += 1
        #print "New chunk count = " + str(self.count)
        #print "Adding chunk: " + chunk
        X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
        h = [x for x in self.h]
        # Round 1
        s = (3,7,11,19)
        for r in xrange(16):
            i = (16-r)%4
            k = r
            h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4
            k = 4*(r%4) + r//4
            h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in xrange(16):
            i = (16-r)%4
            h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

        #print "New state: " + str(self.h)

    def add(self, data):
        #print "Adding data: " + data.encode("hex")
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = ""
        for chunk in xrange(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk+64] )
        return self

    def finish(self):
        l = len(self.remainder) + 64 * self.count
        #print "Length before padding: " + str(l)
        padding = "\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8)
        #print "Computed padding: " + padding.encode("hex")
        #print len(padding)
        self.add( padding)
        out = struct.pack("<4I", *self.h)
        #print "Final State: " + str(self.h[0]) + ", " + str(self.h[1]) + ", " + str(self.h[2]) + ", " + str(self.h[3])
        #print "Final state: " + "{0:0{1}x}".format(self.h[0],8) + ", " + "{0:0{1}x}".format(self.h[1],8) + ", "  + "{0:0{1}x}".format(self.h[2],8) + ", "  + "{0:0{1}x}".format(self.h[3],8)

        self.__init__()
        return out.encode("hex")


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


def sha1Mac(key, message):
    return sha1(key+message)

def md4Mac(key, message):
    m=MD4()
    m.add(key+message)
    return m.finish()

def hmac_sha1(key, message):
    blocksize = 64 # Block size of SHA1 in bytes
    if (len(key) > blocksize):
        key = sha1(key) # keys longer than blocksize are shortened
    if (len(key) < blocksize):
        # keys shorter than blocksize are zero-padded
        key = key + '\x00'*(blocksize-len(key))

    #print key.encode("hex")
    #print ("\x36"*blocksize).encode("hex")
    #print ("\x5c"*blocksize).encode("hex")
    #print len(key)
    o_key_pad = hexxor(('\x5c' * blocksize).encode("hex"), key.encode("hex")).decode("hex") # Where blocksize is that of the underlying hash function
    i_key_pad = hexxor(('\x36' * blocksize).encode("hex"), key.encode("hex")).decode("hex")
    #print o_key_pad

    return sha1(o_key_pad + sha1(i_key_pad + message).decode("hex"))

def hmac_sha256(key, message):
    blocksize = 64 # Block size of SHA256 in bytes
    if (len(key) > blocksize):
        key = sha1(key) # keys longer than blocksize are shortened
    if (len(key) < blocksize):
        # keys shorter than blocksize are zero-padded
        key = key + '\x00'*(blocksize-len(key))

    #print key.encode("hex")
    #print ("\x36"*blocksize).encode("hex")
    #print ("\x5c"*blocksize).encode("hex")
    #print len(key)
    o_key_pad = hexxor(('\x5c' * blocksize).encode("hex"), key.encode("hex")).decode("hex") # Where blocksize is that of the underlying hash function
    i_key_pad = hexxor(('\x36' * blocksize).encode("hex"), key.encode("hex")).decode("hex")
    #print o_key_pad

    return hashlib.sha256(o_key_pad + hashlib.sha256(i_key_pad + message).digest()).hexdigest()



def verifySHA256Mac(msg, key, tag):
    checkTag = hmac_sha256(key, msg)
    return (tag == checkTag)


#HMAC_SHA1("", "")   = 0xfbdb1d1b18aa6c08324b7d64b71fb76370690e1d
#HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog")   = 0xde7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
#HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog\n")   = 0xc880ba6df628c22978b20215b5f982d6ac24b9dd

def process_mdsuck_chunk(chunk, h):
    return _process_mdsuck_chunk(chunk, h)

def _process_mdsuck_chunk(chunk, h):
    """Process a chunk of data and return the new digest variables."""
    assert len(chunk) == 16
    #print "Processing chunk: " + chunk.encode("hex")
    #print h
    #print hex(h)
    c = aes_128_ecb(chunk, struct.pack(">Q", h)+struct.pack(">Q", 0), ENCRYPT)[0:2]
    #print c.encode("hex")
    return int(c.encode("hex"),16)

class MDSuckHash(object):
    name = 'python-smdsuck'
    # Size in bits
    digest_size = 2
    block_size = 16

    def __init__(self):
        # Initial digest variables
        self._h = 0xBEEF

        # bytes object with 0 <= len < 64 used to store the end of the message
        # if the message length is not congruent to 64
        self._unprocessed = b''
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0

    def setInternalState(self,h, msgLen):
        self._h=h
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
        chunk = self._unprocessed + arg.read(16 - len(self._unprocessed))

        # Read the rest of the data, 16 bytes at a time
        while len(chunk) == 16:
            self._h = _process_mdsuck_chunk(chunk, self._h)
            self._message_byte_length += 16
            chunk = arg.read(16)
            #print "State set to: " + "{0:0{1}x}".format(self._h[0],8) + ", " + "{0:0{1}x}".format(self._h[1],8) + ", "  + "{0:0{1}x}".format(self._h[2],8) + ", "  + "{0:0{1}x}".format(self._h[3],8) + ", " + "{0:0{1}x}".format(self._h[4],8)

        self._unprocessed = chunk
        return self

    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return struct.pack(b'>I', self._produce_digest())

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return "{0:0{1}x}".format(self._produce_digest(), 4)

    def _produce_digest(self):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)
        #print "Msg Byte Len: " + str(message_byte_length)

        message = pkcs7Padding(message, 16)
        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.
        h = _process_mdsuck_chunk(message, self._h)
        #print "State set to: " + "{0:0{1}x}".format(h[0],8) + ", " + "{0:0{1}x}".format(h[1],8) + ", "  + "{0:0{1}x}".format(h[2],8) + ", "  + "{0:0{1}x}".format(h[3],8) + ", " + "{0:0{1}x}".format(h[4],8)

        if len(message) == 16:
            return h
        return _process_mdsuck_chunk(message[16:], h)

def mdsuck(data):
    return MDSuckHash().update(data).hexdigest()

def MDSuckWithState(h,data,origlen):
    s=MDSuckHash()
    s.setInternalState(h,origlen)
    return s.update(data).hexdigest()




def process_mdsuckmore_chunk(chunk, h):
    return _process_mdsuckmore_chunk(chunk, h)

def _process_mdsuckmore_chunk(chunk, h):
    """Process a chunk of data and return the new digest variables."""
    assert len(chunk) == 16
    #print "Processing chunk: " + chunk.encode("hex")
    #print h
    #print hex(h)
    c = aes_128_ecb(chunk, struct.pack(">Q", h)+struct.pack(">Q", 0), ENCRYPT)[0:3]
    #print c.encode("hex")
    return int(c.encode("hex"),16)

class MDSuckMoreHash(object):
    name = 'python-smdsuckmore'
    # Size in bits
    digest_size = 2
    block_size = 16

    def __init__(self):
        # Initial digest variables
        self._h = 0xBEEEEF

        # bytes object with 0 <= len < 64 used to store the end of the message
        # if the message length is not congruent to 64
        self._unprocessed = b''
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0

    def setInternalState(self,h, msgLen):
        self._h=h
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
        chunk = self._unprocessed + arg.read(16 - len(self._unprocessed))

        # Read the rest of the data, 16 bytes at a time
        while len(chunk) == 16:
            self._h = _process_mdsuckmore_chunk(chunk, self._h)
            self._message_byte_length += 16
            chunk = arg.read(16)
            #print "State set to: " + "{0:0{1}x}".format(self._h[0],8) + ", " + "{0:0{1}x}".format(self._h[1],8) + ", "  + "{0:0{1}x}".format(self._h[2],8) + ", "  + "{0:0{1}x}".format(self._h[3],8) + ", " + "{0:0{1}x}".format(self._h[4],8)

        self._unprocessed = chunk
        return self


    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return struct.pack(b'>I', self._produce_digest())

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return "{0:0{1}x}".format(self._produce_digest(), 6)

    def _produce_digest(self):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)
        #print "Msg Byte Len: " + str(message_byte_length)

        message = pkcs7Padding(message, 16)
        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.
        h = _process_mdsuckmore_chunk(message, self._h)
        #print "State set to: " + "{0:0{1}x}".format(h[0],8) + ", " + "{0:0{1}x}".format(h[1],8) + ", "  + "{0:0{1}x}".format(h[2],8) + ", "  + "{0:0{1}x}".format(h[3],8) + ", " + "{0:0{1}x}".format(h[4],8)

        if len(message) == 16:
            return h
        return _process_mdsuckmore_chunk(message[16:], h)

def mdsuckmore(data):
    return MDSuckMoreHash().update(data).hexdigest()

def MDSuckMoreWithState(h,data,origlen):
    s=MDSuckMoreHash()
    s.setInternalState(h,origlen)
    return s.update(data).hexdigest()
