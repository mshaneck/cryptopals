#!/usr/bin/python
from set2 import *
from set1 import *

from struct import *
from Crypto.Cipher import AES
from Crypto.Random import random
import base64
import string
import time

consistent_key = getRandomAESKey()
random_string = getRandomString()

def challenge17_consumeCiphertext(ciphertext):
	decrypted = aes_128_cbc(ciphertext, consistent_key, "", DECRYPT)
	#print decrypted.encode('hex')
	return isPkcs7PaddingValid(decrypted, AES.block_size)

def challenge17_produceCiphertext():
	messages = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
				"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
				"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
				"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
				"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
				"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
				"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
				"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
				"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
				"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
	#for m in messages:
		#print splitIntoBlocks(base64.b64decode(m), 16)
	msg = random.randint(0,len(messages)-1)

	plaintext = pkcs7Padding(base64.b64decode(messages[msg]), AES.block_size)
	iv = getRandomAESKey()
	ciphertext = aes_128_cbc(plaintext, consistent_key, iv, ENCRYPT)
	return ciphertext

def cbcPaddingOracleGuess(cipherblock, guess, byte, currentPlaintext):
	# currentPlaintext is what we know so far about the block
	# It will go at the end and will get xor'd with its length
	# cipherblock is the block to modify
	# guess is our guess
	# byte is the byte position from 0 to 15

	paddingValue = 16-byte
	#print "Guessing ", guess
	mask = "00"*byte + "{0:0{1}x}".format(paddingValue,2)*paddingValue
	guessblock = "00"*(byte)+"{0:0{1}x}".format(guess,2)+currentPlaintext
	#print mask
	#print guessblock
	#print cipherblock
	mask = hexxor(mask, guessblock)
	mask = hexxor(mask, cipherblock)
	return mask


def set3challenge17():
	ciphertext = challenge17_produceCiphertext()
	# Let's decrypt this sucker
	plaintext = ""
	ctxtBlocks = splitIntoBlocks(ciphertext.encode('hex'), 32)
	#print ctxtBlocks
	# CBC Padding Oracle Attack
	# Guess from 0 to 255 the last byte of block 1
	# Take block 0 and XOR the last byte with guess and 01
	# Check if padding is correct
	# If yes, guess is correct
	# Set byte equal to guess
	# Guess second to last byte of block 1
	# Take block 0 and XOR the second to last byte with guess and 02 and last byte with known and 02
	lastBlock=False

	# Repeat entire thing for each block
	# We will actually be guessing for the next block, since that is the one that will have the padding check
	for block in range(len(ctxtBlocks)-1):
		# Problem: If the block is the last block, you can't really guess 01 as the last byte
		# In fact the last block has several problems, since there is actual padding

		# In fact, for the last block, the last byte should be the padding block
		# So we can skip those final bytes...
		if (block == len(ctxtBlocks)-2):
			#print "We are working on the last block"
			lastBlock = True

		decryptedBlock = ""
		paddingStart = -1
		#print "Guessing block ", block
		# Repeat for each byte in the block, increasing the padding guess and building up the final parts
		for byte in range(16):
			# We will be guessing byte 16-byte-1
			i=16-byte-1
			lastByte = False
			if (lastBlock and i==15):
				lastByte=True
				#print "Guessing the last byte of the ciphertext"
			#print "    Guessing byte ", i, " (really ", byte, ")"

			guessedLastByte = False
			# Each guess of b for byte i
			for b in range(256):
				# Guessing value of b for byte i of block+1
				modblock = cbcPaddingOracleGuess(ctxtBlocks[block], b, i, decryptedBlock.encode('hex'))
				# Send the modified block and the next block to the oracle
				if (challenge17_consumeCiphertext((modblock+ctxtBlocks[block+1]).decode('hex'))):
					# Padding is correct, so our guess is right
					if (lastByte and b==1):
						# this may not be correct
						# keep going and try to see if another one matches. If it does, that is correct, otherwise, this is the last byte
						guessedLastByte = False
						continue
					decryptedBlock = chr(b)+decryptedBlock
					guessedLastByte = True
					#print "Added ", b
					#print "Decrypted block now '", decryptedBlock, "'"
					break
			if (lastByte and not guessedLastByte):
				decryptedBlock = chr(1)+decryptedBlock


		#print decryptedBlock
		plaintext = plaintext + decryptedBlock

	print removePkcs7Padding(plaintext, 16)
	#challenge17_consumeCiphertext(ciphertext)

#set3challenge17()


def aes_128_ctr(plaintext, key, nonce):
	# Encrypt and decrypt is the same
	blocks = splitIntoBlocks(plaintext, 16)
	ciphertext = ""
	#print nonce + pack('<q', 4)
	for i in range(len(blocks)):
		#print "Block ", i
		#print nonce + pack('<q', i)
		nonceandctr=nonce + pack('<q', i)
		cipherblock = aes_128_ecb(nonceandctr, key, ENCRYPT)
		cipherblock = cipherblock[:len(blocks[i])]
		ciphertext = ciphertext + hexxor(cipherblock.encode('hex'), blocks[i].encode('hex'))
	return ciphertext.decode('hex')

def set3challenge18():
	ciphertext = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	key="YELLOW SUBMARINE"
	nonce=pack('<q', 0)
	print aes_128_ctr(ciphertext, key, nonce)

#set3challenge18()

# Check if all letters at the given index are printable
# list: list of all encrypted texts
# index: the index into each line
# letter: guess for that letter in list[guessindex]
# Go through each line in list:
	#xor the list[i][index] with list[guessindex][index] and letter
	# see if the resulting letter is printable
	# return false if not printable
# return true if all are printable
# need to adjust it so that it is ranked
def allPrintable(list, index, letter, guessindex):
	#print index
	#print guessindex
	#print len(list[guessindex])
	for line in list:
		p = ord(line[index])^ord(list[guessindex][index])^ord(letter)
		if not chr(p) in string.printable:
			return False
	return True

def set3challenge1920helper(filename):
	i=0
	data = [aes_128_ctr(base64.b64decode(line.rstrip('\n')), consistent_key, pack('<q', 0)) for line in open(filename, 'r')]

	#print len(data)
	longestline = -1
	longestlineIndex = -1
	shortestline = 10000000000
	shortestlineindex = -1
	for i, line in enumerate(data):
		#print line.encode('hex')
		if len(line) > longestline:
			longestline = len(line)
			longestlineIndex = i
		if len(line) < shortestline:
			shortestline = len(line)
			shortestlineindex = i

	print "Longest line is ", longestlineIndex, " with length ", longestline
	print "Shortest line is ", shortestlineindex, " with length ", shortestline

	possibleLetters=[]

	for i in range(shortestline):
		guesses=[]
		for c in string.printable:
			if (allPrintable(data, i, c, longestlineIndex)):
				guesses.append(c)
		possibleLetters.append(guesses)

	#for possible in possibleLetters:
		#print len(possible)
		#print possible
	#print len(possibleLetters)
	#print len(string.printable)
	# Guess it letter by letter, find all letters for the longest string that results in english letters for each other string at the same position
	# Guess in [a-zA-Z ',]   for first letter

	# Truncate the lines to the shortest length
	for i,line in enumerate(data):
		data[i] = data[i][:shortestline]

	combined = "".join(data)
	results = bestVigenereDecrypt(combined, shortestline, True)
	n=shortestline
	plaintext = [results[0][i:i+n] for i in range(0, len(results[0]), n)]
	print "\n".join(plaintext)

def set3challenge19():
	set3challenge1920helper('set3.challenge19.txt')

#set3challenge19()

def set3challenge20():
	set3challenge1920helper('set3.challenge20.txt')

#set3challenge20()

# I'll be honest here and say that I didn't do the substitutions thing completely and I don't really care
# The problem statement said that it is a subpar method and I agree, and it seemed like a big pain. Granted this
# way doesn't get the entire plaintext, but it gets enough that you get the idea. I don't want this to slow
# me down though and so I am going to just move on.



# Anyway, back to the Crypto
# The following I got from Wikipedia:
def _int32(x):
    # Get the 32 least significant bits.
    return int(0xFFFFFFFF & x)

class MT19937:
    def __init__(self, seed):
        # Initialize the index to 0
        self.index = 624
        self.mt = [0] * 624
        self.mt[0] = seed  # Initialize the initial state to the seed
        for i in range(1, 624):
            self.mt[i] = _int32(
                1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def extract_number(self):
        if self.index >= 624:
            self.twist()

        y = self.mt[self.index]

        # Right shift by 11 bits
        y = y ^ y >> 11
        # Shift y left by 7 and take the bitwise and of 2636928640
        y = y ^ y << 7 & 2636928640
        # Shift y left by 15 and take the bitwise and of y and 4022730752
        y = y ^ y << 15 & 4022730752
        # Right shift by 18 bits
        y = y ^ y >> 18

        self.index = self.index + 1

        return _int32(y)

    def twist(self):
        for i in range(624):
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            y = _int32((self.mt[i] & 0x80000000) +
                       (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
        self.index = 0

def set3challenge21():
	m = MT19937(10)
	print m.extract_number()
	print m.extract_number()
	print m.extract_number()
	print m.extract_number()

def set3challenge22():
	time.sleep(random.randint(40,1000))
	seed=int(time.time()*1000)
	print "Seed: " + str(seed)
	m = MT19937(seed)
	time.sleep(random.randint(40,1000))
	randNum = m.extract_number()
	print randNum
	current_time = int(time.time()*1000)
	notFound=True
	tests=1
	while(notFound):
		mt = MT19937(current_time)
		if (mt.extract_number() == randNum):
			print "Found the seed: " + str(current_time) + " in " + str(tests) + " tests"
			exit()
		current_time = current_time - 1
		tests = tests + 1

#set3challenge22()
