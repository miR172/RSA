import rsa

# Create Entity for each person

Trent = rsa.Certificate()

Alice = rsa.Certificate(name="Alice", print_trace=True)

Bob = rsa.Certificate(name="Bob")

# Trent Certificates Alice
a = Trent.certificate(Alice)

# Bob Generates Random Number
k = 2
while k <=2 :
  k=len(format(Alice.getN(), "b").lstrip("0"))-1

rd = rsa.randomN(k-1)[:k]

# -----------------------------------
# This part simply produces output
print "line206: Bob Generate Random Number\n k = %d u = %d\n"%(k, int(rd, 2))
tmp1 = rsa.padding(rd, 32)
print "line208: Bob Generated Random Number 32-bits\n u = "+rsa.padding(rd, 32)+"\n"
#------------------------------------


# Alice Sign the Number from Bob
reply = Alice.sign(rd)

# Bob Check the Signature of Alice
check = Bob.encrypt(reply, Alice.publicKey(), Alice.getN())


# -----------------------------------
# This part simply produces output
tmp2 = rsa.myhash(tmp1)
print "line215: Bob Identifies Alice (bits)\n u = "+tmp1+"\n h(u) = "+tmp2+"\n v = "+reply+"\n E(e, v) = "+check+"\n"

rsa.exponential(int(reply,2), Alice.publicKey(), Alice.getN(), True)
#------------------------------------

# Bob Verify that It Is Alice
print "\nIs it Alice?", Bob.verify(rd, check)
