from rsatool import *
from rsa_utils import *
from factordb.factordb import FactorDB



def main(argv):
    n=0
    e=0
    try:
        opts, args = getopt.getopt(argv,"n:e:",[])
    except getopt.GetoptError:
        print 'blerg'
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-n"):
            n=int(arg, 16)
        if opt in ("-e"):
            e = int(arg)
    if n == 0:
        print "Enter an N"
        exit(1)
    if e == 0:
        print "Enter an e"
        exit(2)

    #print "Factoring " + str(n)
    pq = FactorDB(n)
    pqlist = pq.get_factor_list()
    phi = (pqlist[0]-1)*(pqlist[1]-1)
    d = modInv(e,phi)[1]
    #print d
    rsa = RSA(pqlist[0], pqlist[1], e)
    data = rsa.to_pem()
    fp = open("./private.key", 'wb')
    fp.write(data)
    fp.close()

    exit(0)

if __name__ == "__main__":
   main(sys.argv[1:])
