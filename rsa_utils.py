#!/usr/bin/python
import sys, getopt
from Crypto.Random import random
import hashlib, gmpy2

smallPrimes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919)

def millerRabin(n):
    #Miller Rabin
    #Given n
    #Find: k, q, k > 0, q odd such that n - 1 = (2^k)q
    q=n-1
    n1=n-1
    k=0
    while (q % 2 == 0):
        q = q/2
        k=k+1

    #print "2^" + str(k) + "*" + str(q) + " = " + str(n-1)
    #Select random base a between 1 and n - 1
    a = random.randint(2,n-2)
    #print "a="+str(a)
    #If a^q == 1 mod n return "Probably Prime"
    #aq = pow(a,q,n)
    aq = long(gmpy2.powmod(a, q, n))
    #print "a^q == 1? aq=" + str(aq)
    if (aq == 1 or aq == n1):
        return True

    #For j = 1 to k - 1 (I already checked for j=0)
    for j in range(1,k):
        #If a^()(2^j) q) = n - 1 mod n return "Probably Prime"
        #aq = pow(aq,2,n)
        aq = (aq*aq)%n
        #print "a^(2^"+str(j)+")q == n-1? "+str(aq)
        if (aq == n1):
            return True
    #print "Composite"
    return False

def fermatPrime(n):
    a = random.randint(2,n-2)
    x = long(gmpy2.powmod(a, n-1, n))
    if (x == 1):
        return True
    else:
        return False

def isPrime(n,t):
    # Trial division with 1000 smallest primes
    for p in smallPrimes:
        if (n%p == 0 and n != p):
            return False

    # Maybe do a few Fermat tests?
    for i in range(0,3):
        if (not fermatPrime(n)):
            return False

    #Now do Miller Rabin
    for i in range(0,t):
        if (not millerRabin(n)):
            return False
    return True

def genPrime(bits, tests):
    n=random.getrandbits(bits)
    if (n%2==0):
        n = n+1
    #print "Checking " + str(n)
    while(not isPrime(n, tests)):
        n=n+2
        #print "Checking " + str(n)
    return n

def modInv(a,b):
    # Generate a^(-1) mod b
    (A1,A2,A3) = (1,0,a)
    (B1, B2, B3) =  (0,1,b)
    while(B3 > 1):
        Q = A3/B3
        (T1,T2,T3) = (A1-Q*B1,A2-Q*B2,A3-Q*B3)
        (A1,A2,A3) = (B1,B2,B3)
        (B1,B2,B3) = (T1,T2,T3)
    if (B3==0):
        # there is no modular inverse
        return (A3, -1) #gcd(a,b)=A3
    if (B3 == 1):
        # modular inverse is B1
        if (B1 < 0):
            B1 = B1 + b
        return (B3, B1)
    # This should never happen...
    print "Blerg"
    return (-1,-1)

def genRsa(bits, tests):
    while(True):
        p=genPrime(bits/2,tests)
        q=genPrime(bits/2,tests)
        n=p*q
        phi=(p-1)*(q-1)
        e=3
        (gcd,d) = modInv(e,phi)
        if (gcd==1):
            return (e,d,n)

def rsaEncrypt(m,e,n):
    return long(gmpy2.powmod(m, e, n))
    # return pow(m,e,n)

def rsaStringEncrypt(s,e,n):
    #print s.encode("hex")
    m = int(s.encode("hex"),16)
    #print "Encrypting " + str(m) + "("+s+")"
    if (m>n):
        print "Message is too large"
    #print "M:"
    #print m
    return rsaEncrypt(m,e,n)

def rsaDecrypt(c,d,n):
    return long(gmpy2.powmod(c,d, n))
    # return pow(c,d,n)

def rsaStringDecrypt(c,d,n):
    m = pow(c,d,n)
    #print m
    return "{0:x}".format(m).decode("hex")
    #m.decode("hex")

def rsaSign(message, d, n):
    # Use ASN.1 notation PKCS1.5 padding
    sha1_asn_prefix = 0x3021300906052b0e03021a05000414
    length = len("{0:x}".format(n))/2
    h = hashlib.sha1(message).hexdigest()
    padding = "0x0001" + "FF"*(length-15-20-3) + "00"
    msgToSign = int(padding + "{0:x}".format(sha1_asn_prefix) + h,16)
    #print "Message to sign:"
    #print "{0:0{1}x}".format(msgToSign, length*2)
    return rsaDecrypt(msgToSign, d, n)


def rsaVerify(signature, message, e, n, bitsForN):
    #     The error that Bleichenbacher exploits is if the implementation does
    # not check that the hash+ASN.1 data is right-justified within the PKCS-1
    # padding.  Some implementations apparently remove the PKCS-1 padding by
    # looking for the high bytes of 0 and 1, then the 0xFF bytes, then
    # the zero byte; and then they start parsing the ASN.1 data and hash.
    # The ASN.1 data encodes the length of the hash within it, so this tells
    # them how big the hash value is.  These broken implementations go ahead
    # and use the hash, without verifying that there is no more data after it.
    # Failing to add this extra check makes implementations vulnerable to a
    # signature forgery, as follows.
    sha1_asn_prefix = "3021300906052b0e03021a05000414"
    h = hashlib.sha1(message).hexdigest()
    length = bitsForN/8
    #print length
    signToCheck = rsaEncrypt(signature, e, n)
    signToCheck = "{0:0{1}x}".format(signToCheck, length*2)
    #print "Verifying"
    #print signToCheck
    #Scan for 00 01 FF then scan for FF 00, then check (15 bytes) sha1_asn_prefix and then
    # compare the hash (next 20 bytes) to h
    if (not signToCheck.startswith("0001ff")):
        #print "Does not have correct prefix"
        return False
    hashstart = signToCheck.find(sha1_asn_prefix)
    if (hashstart < 0):
        return False
    hashstart = hashstart+ len(sha1_asn_prefix)
    hashToCheck = signToCheck[hashstart:hashstart+40]
    #print hashToCheck
    #print h
    if (hashToCheck == h):
        return True
    return False

def pairwiseCoprime(m):
    for i,a in enumerate(m):
        for j,b in enumerate(m):
            if (i < j):
                (gcd,inv) = modInv(a,b)
                #print "GCD("+str(a)+", "+str(b)+")=" + str(gcd)
                if (gcd> 1):
                    return False
    return True

def crt(a, m, checkCoprime):
    # a and m should be lists
    # a contains all coefficients
    # m contains all pairwise coprime moduli
    #print m
    #
    print a
    if (checkCoprime):
        if (not pairwiseCoprime(m)):
            return False

    M = reduce(lambda x, y: x*y, m)
    #print "M="+str(M)
    x = 0
    #print "Parts:"
    for i,j in enumerate(m):
        #print i
        #print m[i]
        #print a[i]
        (gcd,c) = modInv(M/(m[i]), m[i])
        #print c
        #print "M/m["+str(i)+"]="+str((M/(m[i])))
        #print "C="+str(c)
        #print "A["+ str(i)+"]="+str(a[i])
        x = x + (M/(m[i]))*(c)*(a[i])
    #print "Results:"
    #print x
    #print M
    return x%M

def main(argv):
    command=""
    commands=0
    bits=1024
    tests=15
    a=0
    b=0
    n=0
    d=0
    ciphertext=0
    plaintext=0
    plainmessage=""
    stringMode = False
    mlist=[]
    alist=[]
    try:
        opts, args = getopt.getopt(argv,"gb:t:ma:b:reds:p:c:",["checkpoint6", "genprime", "bits=", "tests=", "modinv", "genrsa", "encrypt", "decrypt", "private=", "modulus=", "ciphertext=", "message=", "string", "plaintext=", "crt", "mlist=", "alist="])
    except getopt.GetoptError:
        print 'blerg'
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-g", "--genprime"):
            commands = commands+1
            command = "g"
        if opt in ("--checkpoint6"):
            commands = commands+1
            command = "checkpoint6"
        if opt in ("--crt"):
            commands = commands+1
            command = "c"
        if opt in ("-b", "--bits"):
            bits = int(arg)
        if opt in ("-t", "--tests"):
            tests = int(arg)
        if opt in ("-a"):
            a = int(arg)
        if opt in ("-b"):
            b = int(arg)
        if opt in ("--ciphertext"):
            ciphertext = int(arg)
        if opt in ("--plaintext"):
            plaintext = int(arg)
        if opt in ("-s", "--private"):
            d = int(arg)
        if opt in ("-p", "--modulus"):
            n = int(arg)
        if opt in ("--string"):
            stringMode = True
        if opt in ("--message"):
            plainmessage=arg
        if opt in ("--mlist"):
            mlist=map(long, arg.split(','))
        if opt in ("--alist"):
            alist=map(long, arg.split(','))
        if opt in ("-m", "--modinv"):
            commands = commands+1
            command = "m"
        if opt in ("-r", "--genrsa"):
            commands = commands+1
            command = "r"
        if opt in ("-e", "--encrypt"):
            commands = commands+1
            command = "e"
        if opt in ("-d", "--decrypt"):
            commands = commands+1
            command = "d"

    if (commands > 1):
        print "Too many commands specified"
        exit(2)

    if (commands == 0):
        print "No command specified"
        exit(2)

    if (command == "g"):
        print genPrime(bits, tests)

    if (command == "m"):
        if (a==0):
            a = genPrime(bits, tests)
            print "Using random prime for a: " + str(a)
        if (b==0):
            b = genPrime(bits, tests)
            print "Using random prime for b: " + str(b)
        (gcd,inv) = modInv(a, b)
        if (gcd == 1):
            print str(a) + "*" + str(inv) + " mod " + str(b) + " = 1"
        else:
            print str(a) + " and " + str(b) + " are not coprime. gcd is " + str(gcd)

    if (command == "r"):
        print genRsa(bits, tests)

    if (command == "checkpoint6"):
        message = "https://www.youtube.com/watch?v=MtN1YnoL46Q"
        (e1,d1,n1) = genRsa(1024,15)
        (e2,d2,n2) = genRsa(1024,15)
        (e3,d3,n3) = genRsa(1024,15)
        c1 = rsaStringEncrypt(message,e1,n1)
        c2 = rsaStringEncrypt(message,e2,n2)
        c3 = rsaStringEncrypt(message,e3,n3)


        print "Verified:"
        print rsaStringDecrypt(c1, d1, n1)

        print "RSA1:"
        print "n1=" + str(n1)
        print "e1=" + str(e1)
        print "c1=" + str(c1)

        print "RSA2:"
        print "n2=" + str(n2)
        print "e2=" + str(e2)
        print "c2=" + str(c2)

        print "RSA3:"
        print "n3=" + str(n3)
        print "e3=" + str(e3)
        print "c3=" + str(c3)

    if (command == "e"):
        # Make sure that modulus has been specified
        if (n==0):
            print "Please specify a public modulus"
            exit(2)
        # Make sure that plaintext has been specified
        if (plaintext > 0 and not stringMode):
            #numeric mode
            print rsaEncrypt(plaintext,3,n)
        elif (plainmessage != "" and stringMode):
            # string mode
            print rsaStringEncrypt(plainmessage, 3, n)
        else:
            if (stringMode and plainmessage == ""):
                print "String mode specified but no plainmessage specified"
            if (not stringMode and plaintext ==0):
                print "Integer mode specified but not plaintext specified"
            else:
                print "Parameters not specified properly"
                print stringMode
                print plaintext
                print plainmessage

    if (command == "d"):
        if (n==0):
            print "Please specify a public modulus"
            exit(2)
        if (d==0):
            print "Please specify a private key"
            exit(2)
        if (stringMode):
            print rsaStringDecrypt(ciphertext, d, n)
        else:
            print rsaDecrypt(ciphertext, d, n)

    if (command =="c"):
        print "Doing the CRT"
        alist=(5540655028622021934429306287937775291955623308965208384582009857376053583575510784169616065113641391169613969813652523507421157045377898542386933198269451,9066897320308834206952359399737747311983309062764178906269475847173966073567988170415839954996322314157438770225952491560052871464136163421892050057498651)
        mlist=(7901324502264899236349230781143813838831920474669364339844939631481665770635584819958931021644265960578585153616742963330195946431321644921572803658406281,12802918451444044622583757703752066118180068668479378778928741088302355425977192996799623998720429594346778865275391307730988819243843851683079000293815051)
        print alist
        print mlist
        print crt(alist, mlist, False)


    exit(0)

if __name__ == "__main__":
   main(sys.argv[1:])
