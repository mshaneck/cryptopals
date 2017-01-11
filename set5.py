#!/usr/bin/python
from set1 import *
from set2 import *
from set3 import *
from set4 import *
from hashing import *
from rsa_utils import *
import gmpy

def diffieHellman(p,g):
    print "Computing Diffie Hellman shared key for p=" + str(p) + " and g=" + str(g)
    a = random.randint(2,p)
    A = pow(g,a,p)
    b = random.randint(2,p)
    B = pow(g,b,p)

    sB = pow(A,b,p)
    sA = pow(B,a,p)
    print "Printing session key: "
    print sA
    print sB



def set5challenge33():
    diffieHellman(37,5)
    diffieHellman(0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff, 2)

#set5challenge33()

def diffieHellmanMITM(p,g,replaceAB, replaceABwith):
    secret_message = "This is the secret message!!!!"

    # A sends to B, but intercepted by M
    a = random.randint(2,p)
    A=pow(g,a,p)

    # M replaces A with replaceABwith
    if (replaceAB):
        A=replaceABwith

    # B sends to A, but is intercepted by M
    b = random.randint(2,p)
    B=pow(g,b,p)

    # M intercepts and replaces B with replaceABwith
    if (replaceAB):
        B=replaceABwith
    print A
    print B
    # Both sides will compute s
    sA = pow(B,a,p)
    sB = pow(A,b,p)
    print sA
    print sB

    # A sends message to B
    ivA="{0:0{1}x}".format(random.getrandbits(128), 32).decode('hex')
    keyA = sha1(str(sA))[0:16]
    print keyA
    ciphertextA = aes_128_cbc(pkcs7Padding(secret_message, AES.block_size), keyA, ivA, ENCRYPT)

    # It gets passed on to B and B decrypts it
    keyB = sha1(str(sB))[0:16]
    print keyB
    plaintextB = removePkcs7Padding(aes_128_cbc(ciphertextA, keyB, ivA, DECRYPT), AES.block_size)
    print "Bob got: " + plaintextB

    # Bob sends it back
    ivB="{0:0{1}x}".format(random.getrandbits(128), 32).decode('hex')
    ciphertextB = aes_128_cbc(pkcs7Padding(plaintextB, AES.block_size), keyB, ivB, ENCRYPT)

    # A decrypts
    plaintextA = removePkcs7Padding(aes_128_cbc(ciphertextB, keyA, ivB, DECRYPT), AES.block_size)
    print "Alice received this: " + plaintextA

    return (ivA, ciphertextA, ivB, ciphertextB, A, B)

def set5challenge34():
    p=37
    g=5

    print "Replacing A and B with p"
    (ivA, ciphertextA, ivB, ciphertextB, A, B) = diffieHellmanMITM(p,g,True,p)
    # Eve needs to decrypt. But since A and B were replaced with p, then p^a mod p is 0 and p^b mod p is also 0
    sE = pow(0,1,p)
    print "sE = " + str(sE)
    keyEve = sha1(str(sE))[0:16]
    plaintextEve1 = removePkcs7Padding(aes_128_cbc(ciphertextA, keyEve, ivA, DECRYPT), AES.block_size)
    plaintextEve2 = removePkcs7Padding(aes_128_cbc(ciphertextB, keyEve, ivB, DECRYPT), AES.block_size)
    print "Eve got these:"
    print plaintextEve1
    print plaintextEve2

#set5challenge34()

def set5challenge35():
    # same as 34 but with messed up g:
    p=37
    g=5

    # g = 1 --> sA will be 1
    print "\nReplacing g with 1"

    (ivA, ciphertextA, ivB, ciphertextB, A, B) = diffieHellmanMITM(p,1,False,g)
    sE = pow(1,1,p)
    print "sE = " + str(sE)
    keyEve = sha1(str(sE))[0:16]
    plaintextEve1 = removePkcs7Padding(aes_128_cbc(ciphertextA, keyEve, ivA, DECRYPT), AES.block_size)
    plaintextEve2 = removePkcs7Padding(aes_128_cbc(ciphertextB, keyEve, ivB, DECRYPT), AES.block_size)
    print "Eve got these:"
    print plaintextEve1
    print plaintextEve2

    # g = p   --> this will be same as above, sA = sB = 0
    print "\nReplacing g with p"
    (ivA, ciphertextA, ivB, ciphertextB, A, B) = diffieHellmanMITM(p,p,False,g)
    sE = pow(0,1,p)
    print "sE = " + str(sE)
    keyEve = sha1(str(sE))[0:16]
    plaintextEve1 = removePkcs7Padding(aes_128_cbc(ciphertextA, keyEve, ivA, DECRYPT), AES.block_size)
    plaintextEve2 = removePkcs7Padding(aes_128_cbc(ciphertextB, keyEve, ivB, DECRYPT), AES.block_size)
    print "Eve got these:"
    print plaintextEve1
    print plaintextEve2

    # g = p - 1 --> sA and sB will be either 1 or p-1 based on parity of a*b
    # --> a odd means A is p-1, b odd means B is p-1
            # a odd, b odd,  ab is odd --> sA is p-1
            # a odd, b even, ab is even --> sA is 1
            # a even, b odd, ab is even --> sA is 1
            # a even, b even, ab is even --> sA is 1
    print "\nReplacing g with p-1"
    (ivA, ciphertextA, ivB, ciphertextB, A, B) = diffieHellmanMITM(p,p-1,False,g)
    sE = pow(1,1,p)
    print A
    print B
    if (A==p-1 and B==p-1):
        sE = pow(p-1,1,p)
    print "sE = " + str(sE)
    keyEve = sha1(str(sE))[0:16]
    plaintextEve1 = removePkcs7Padding(aes_128_cbc(ciphertextA, keyEve, ivA, DECRYPT), AES.block_size)
    plaintextEve2 = removePkcs7Padding(aes_128_cbc(ciphertextB, keyEve, ivB, DECRYPT), AES.block_size)
    print "Eve got these:"
    print plaintextEve1
    print plaintextEve2

#set5challenge35()

def set5challenge36():
    print "Run Server with ./SRPServer.py --port 6000"
    print "Run Client with ./SRPClient.py --port 6000"

def set5challenge37():
    print "Run Server with ./SRPServer.py --port 6000"
    print "Run Client with ./SRPClient.py --port 6000 -z"

#set5challenge36()
#set5challenge37()

# set 5 challenges 38 and 39 are in rsa_utils.py

def set5challenge40():
    secretMessage = "Help me for I am in trouble. And this is my super secret message that I don't want anyone to read"
    n1=1200343295058419559034965277333232788830742694547897906643451152421154634551144963921240715495757096529547649950198659894347484879027218429267765619345399911107614771236181796099338830037799072828670785451198693467517313251295242686077217673838562232907073266225868810264810529634562327693634670688757166189229431960298273123007350072830724704045854542393636421831411164579298719218767791869000946388828647238310605650037631156413345841275723020541795070338141166829852787195868871734304526897225139954161534501902232399162609952293859761714068705465645812105023938429448520967775865658693969879265727505060275828169
    n2=21833929926876129497394114992019540228383774643307425510237434632948940048679235339377257321757862244122747258570244478963780152731304050133906900905881207640354828201259406939570215853947141741317961417136244413626970061729715433170872458974998280409369882077403217903157745079157176221972654506281456318126814455425984831176394870417257343784369106628150352860261986321893893897768151012156443030229282328746117183184339659548001792525548079591664287920764806613172212622231931685440214229057667219083709327604375674646838461419265282931436015038570444784295749868183703848181406912698523703475168520854759863162443
    n3=3764458767629364254690242556692254610462172909273411281177906532562841922116498971954938740936684768650120909019744024118798055964185380177709983599039125995992083770118267044119453203414056022836243544574771115688771349772156691577595279186139908455402646204809884553282604811919513164720762805640201793790356456315367602878910898139429094098794812617703081458716786463358000879575684753442000233995254982958070970655934714609961956861794068065795901860016862502930500497738570977524071862980836748518728546480358797583220374885989468457329380204503336888624851543704063511016155416099628818382538211328834895187003
    #n1=250477977605200665987006871163758224295679573807669538968294715934097363649563692249263271
    #n2=231947088600680429869850160984278579388489623761855289007450171693523240274653761192682411
    #n3=740162998804161888464279410863312021877439686091270532541213730433625530604390324313912803
    #n1=717047920189
    #n2=377573587987
    #n3=66516231913


    e=3

    c1=rsaStringEncrypt(secretMessage,e,n1)
    c2=rsaStringEncrypt(secretMessage,e,n2)
    c3=rsaStringEncrypt(secretMessage,e,n3)

    print "Cs:"
    print c1
    print c2
    print c3
    m=crt([c1,c2,c3], [n1,n2,n3], True)
    print "CRT Answer: "
    print m
    m=gmpy.mpz(m)
    m=long(m.root(3)[0])
    #m = int(m**(1.0/3.0))
    print "Recovered M:"
    print m
    print "{0:x}".format(m)
    print "{0:x}".format(m).decode("hex")


set5challenge40()
