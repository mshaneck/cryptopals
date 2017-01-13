#!/usr/bin/python
import sys, getopt, socket
import hashlib, gmpy, gmpy2
from Crypto.Random import random
from hashing import *
from rsa_utils import *

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


set6challenge42()