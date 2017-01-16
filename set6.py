#!/usr/bin/python
import sys, getopt, socket
import hashlib, gmpy, gmpy2
from Crypto.Random import random
from hashing import *
from rsa_utils import *
from dsa import *
import math
import binascii
from decimal import *
from subprocess import *

def set6challenge41():
    # Connect to the server
    BUFFER_SIZE=2048
    port=63079
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Connect the socket to the port where the server is listening
        server_address = ('localhost', port)
        #print >>sys.stderr, 'connecting to %s port %s' % server_address
        sock.connect(server_address)
        #print >>sys.stderr, 'connected to %s port %s' % server_address

    except socket.error:
        print >>sys.stderr, "Could not connect to the server"
        exit(1)

    # STart the c41server and paste the values in here that it prints out
    testmsg = 48899355915805511642110150196064308962603564745444508810275819120731286345840412710027476540416231884513699083507561624530449919454857842327411239743214255850426587689829214459670112301111969606032716145292787243205927374961627836714404408900068725999000241698766864760519893787139091541390568689658234348529344829663318958861159999544209921990915264901015074205509289211105091915705367531
    challenge=136406206546059434456514645460101989829040712212624733764911513819504826381122431903391044492317004057059946449696903192374884481254794026871099488739080176418237313584034652563887042614652126373824158044035388575724150685898374878431594870183015020010073485914308081155363935173207216016458308754406024495840441921973791592148674961564274652982720865344707413403669118143526076992867826906190785381216649422410466306700730109363417884294197899374992977619093193167738215975972727152758986753526293705096272464234516505961095898069382993556727774926680133772041449262058107967687937303097039812642434076918767793689005419733716617211855569585309563453439913217000177061795150276599738314573855987436717227722066974716242793313553277746021095062802951326364409475079918504375199299320857146379486614615139186969524375375124254202938339957689327983176345785330248141366757582750279507505960062121709596715781030353288728120843943059331712534634039289868475386148921778388442649267782089098287667167908337293464339895724780597956603744523231127860091159519880289103149012770514811880643515103988774419563161959124869677776338312855029883853975262605720458647503824826483769853603143264775702963555857165012478358034678072575810838428198
    n=336048601020661672935337435153047114037577142777560167081229464146909363355473757668672394055597190989662333291347412722963792419312750882415040398982998960197318920329540192205409068648361481058783532400029987432729670035439078463484324180038572270046993826640357952881153520933472127314809476599481326660803342326092389665395028755699526629243341567790528920427105635617681172431192860089779412698416651780171717114340339103078369480971892225600547293460165381279723878208821866502749193580270489896862762985976915985405598522731584284285505365570956117618325769320185236559096991844769074355235908843878370381477208301556520737513916768934493683469954593537411422060706019980266067873418396732495155318210541287075125280425155184676258165808360501725227070244107389349604595220861985223846202994155934448252438956137869062023149741503657840829230710342467415396412218164525042713753143585165750521924841489927907669242581792829399938517921114245738790175492366730966228477555371402788831645131812263723894182580488656458521557998589939970504743974814227020412964100397669938764414301126418362332684315091080191758341213039192833972260650081040796347948581681074649570584681184306691812482190489098553077205444566997842794575794663

    # First let's do the test message
    #sock.send(str(testmsg))
    #resp=sock.recv(BUFFER_SIZE)
    #print "{0:x}".format(long(resp)).decode("hex")
    #exit(1)

    s = random.randint(2,n-2)
    sinv = modInv(s,n)[1]
    #print "S:"
    #print s
    #print "SInv:"
    #print sinv
    sEnc = long(gmpy2.powmod(s, 3, n))
    challengemod = (sEnc * challenge) % n
    sock.send(str(challengemod))
    resp=sock.recv(BUFFER_SIZE)
    #print "Received:"
    #print resp
    if (resp == "NO NO NO. BAD!"):
        print "NO NO NO. BAD!"
        exit(1)

    pmod = long(resp)
    #print "Pmod:"
    #print pmod
    if (sinv==-1):
        print "No inverse for s?"
        exit(1)
    p = (pmod * sinv) % n
    #print "P"
    #print p
    plaintext = "{0:x}".format(p).decode("hex")

    print plaintext

#set6challenge41()


def set6challenge42():
    print "Forge a signature"
    (e,d,n) = genRsa(1024, 15)
    #print n
    #print "{0:x}".format(n)
    #print len("{0:x}".format(n))
    #message = "Super Secret Message that I definitely sent"
    #sign = rsaSign(message, d, n)
    #print sign
    #if (rsaVerify(sign,message,e,n, 1024)):
    #    print "Signature verifies"

    length = 256
    #print length
    forgeMessage = "Forged Secret Message that I definitely DID NOT send"
    forgePrefix = "0001" + "FF"*3 + "00" + "3021300906052b0e03021a05000414"
    forgeHash = hashlib.sha1(forgeMessage).hexdigest()
    forgeSuffix = "F"*(length-len(forgePrefix)-len(forgeHash))
    forgeTarget = int(forgePrefix+forgeHash+forgeSuffix, 16)
    #print "Forge for:"
    #print "{0:0{1}x}".format(forgeTarget, length)
    #print "Integer Cube root:"
    forgeTarget=gmpy.mpz(forgeTarget)
    forgeTargetCubeRoot=long(forgeTarget.root(3)[0])
    #print forgeTargetCubeRoot
    #print "Cubed:"
    forgeTargetCubed = pow(forgeTargetCubeRoot,3, n)
    #print "{0:0{1}x}".format(forgeTargetCubed, length)
    if (rsaVerify(forgeTargetCubeRoot,forgeMessage,e,n,1024)):
        print "Forgery Signature verifies!"
        print "Forged signature for: " + forgeMessage
    else:
        print "Forgery Failed!"


#set6challenge42()


def recoverDsaPrivateKey(s,k,message, r, q):
    #(s*k-h(message))r^-1 mod q
    rInv = modInv(r,q)[1]
    h = int(hashlib.sha1(message).hexdigest(),16)
    return (((s*k) - h)*rInv) % q

def set6challenge43():
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    message = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    #print "{0:x}".format(q)
    #print hashlib.sha1(message).hexdigest()
    for k in range(0,65535):
        x = recoverDsaPrivateKey(s,k,message, r, q)
        #ycheck = pow(g,x,p)
        ycheck = long(gmpy2.powmod(g,x,p))
        if (ycheck == y):
            print "Found k:"
            print "0x" + "{0:x}".format(k)
            print "Found x:"
            hexX = "{0:x}".format(x)
            print "0x" + hexX
            print hashlib.sha1(hexX).hexdigest()

            exit(0)
    print "Fail!"

#set6challenge43()


def set6challenge44():
    # Break Dsa with repeated k
    y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
    msg1 = "Listen for me, you better listen for me now. "
    s1 = 29097472083055673620219739525237952924429516683
    r1 = 51241962016175933742870323080382366896234169532
    hm1 = 0xa4db3de27e2db3e5ef085ced2bced91b82e0df19

    msg2 = "Yeah me shoes a an tear up an' now me toes is a show a "
    s2 = 506591325247687166499867321330657300306462367256
    r2 = 51241962016175933742870323080382366896234169532
    hm2 = 0xbc7ec371d951977cba10381da08fe934dea80314

    mDiff = (hm1 - hm2 ) % q
    sDiff = (s1 - s2) % q
    sDiffInv = modInv(sDiff,q)[1]
    k = (mDiff * sDiffInv) % q

    x = recoverDsaPrivateKey(s1,k,msg1, r1, q)
    print "Found x:"
    hexX = "{0:x}".format(x)
    print "0x" + hexX
    print hashlib.sha1(hexX).hexdigest()

#set6challenge44()

def set6challenge45():
    # DSA Parameter tampering
    # First set g=0
    # I have to disable the check for r=0 in the signature function, since this produces an r of 0
    (x,y,g,p,q) = genDsaKeys()
    g=0
    msg1 = "Listen for me, you better listen for me now. "
    f1 = "Hello World"
    f2 = "Goodbye World"
    (r,s) = dsaSignMessage(msg1, x, g,p,q)
    print "Setting g=0"
    print "R"
    print r
    print "S"
    print s
    print dsaVerifyMessage(r,s,msg1, y,g,p,q)
    print dsaVerifyMessage(r,s,f1, y,g,p,q)
    print dsaVerifyMessage(r,s,f2, y,g,p,q)
    # g=0 means that r=0, which means that the signature works for all messages

    # Then set g=p+1
    print "Setting g=p+1"
    g=p+1
    z=random.randint(2,p-1)
    zInv = modInv(z,q)[1]
    r = pow(y,z,p) % q
    s = (r*zInv) % q

    print dsaVerifyMessage(r,s,f1, y,g,p,q)
    print dsaVerifyMessage(r,s,f2, y,g,p,q)

    # g = p+1 means that g is 1, but y still stays g^x, so r in this case is g^xz and for
    # v in the verification, the u1 component goes to 1, but the u2 compoenent reduces to z (r cancels out)
    # so v is just g^xz, which is what r is set to


#set6challenge45()

def c46Oracle(c, d, n):
    # decrypt and return true if the last bit is even
    # false if odd
    p=rsaDecrypt(c,d,n)
    #print p
    return p%2 == 0

def set6challenge46():
    (e,d,n) = genRsa(1024, 15)
    #print n
    b64msg = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    msg = base64.b64decode(b64msg)
    #print msg
    origP = int(msg.encode("hex"),16)
    ciphertext = rsaStringEncrypt(msg,e,n)

    #(e,d,n)=genRsa(100, 15)
    #print n, e, d
    #m = "test string"
    #ciphertext = rsaStringEncrypt(m,e,n)
    #print "Plaintext: " + str(m)

    #If the plaintext after doubling is even, doubling the plaintext didn't wrap the modulus
    #    --- the modulus is an odd number.
    #That means the plaintext is less than half the modulus.
    # If the plaintext is odd, it is from teh upper half of the range
    plaintextRange = [0,n]
    twoEnc = rsaEncrypt(2,e,n)
    k = int(math.ceil(math.log(n,2)))  # n. of iterations
    # There is an issue with precision on this attacker
    # My naive solution would consistently get the last character wrong
    # But this solution almost always works.
    getcontext().prec = k    # allows for 'precise enough' floats
    l=Decimal(0)
    u=Decimal(n)
    for i in range(0,1024):
        #print "\nIteration " + str(i)
        #print plaintextRange
        ciphertext = (ciphertext * twoEnc) % n
        h = (l+u)/2
        if (c46Oracle(ciphertext,d,n)):
            # Even
            #print "Even"
            u=h
        else:
            #print "Odd"
            l=h
        #print "\t"*5, l,h, "{0:x}".format(h).decode("hex")
        #if (plaintextRange[0]+2 == plaintextRange[1]):
        #    print "Done: " + str(i)
        #    break
    #print l,h, "{0:x}".format(int(h)).decode("hex")
    print "{0:x}".format(int(h)).decode("hex")
    #print int(msg.encode("hex"),16)
    #print n




set6challenge46()
