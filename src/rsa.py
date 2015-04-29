import random

random.seed() #initialize with time

# xor for string
def xor(a, b):
  i, s= 0, ''
  while i < len(a):
    if int(a[i])+int(b[i])==1: s+='1'
    else: s+='0'
    i += 1
  return s

# one-way hash
def myhash(s):
  seed, i = s[:8], 8
  while i < len(s):
      seed = xor(seed, s[i:i+8])
      i += 8
  return seed

# find Square Root of n using Newton's method
def root(n):
  a = n
  b = (a+1)//2
  while b < a:
    a = b
    b = (a+n // a) // 2
  return a


# find Greates Common Divisor of a and b
def gcd(a, b):
  if a < b: return gcd(b, a)
  while b != 0: a, b  = b, a%b
  return a


# Extended Euclidean: Find Relative Inverse of a In b
def inverse(a, b):
  # index: q, r1, r2, r3, s, t
  q, r1, r2, r3, s, t = b/a, b, a, b%a, 1, 0
  set1 = [q, r1, r2, r3, s, t]
  # print set1
  set2 = [r2/r3, r2, r3, r2%r3, 0, 1]
  # print set2
  while set2[2] != 1:
    q, r1, r2, r3 = set2[2]/set2[3], set2[2], set2[3], set2[2]%set2[3] 
    s = set1[-2]-set1[0]*set2[-2]
    t = set1[-1]-set1[0]*set2[-1]
    set1 = set2
    set2 = [q, r1, r2, r3, s, t]
    # print set2
  t = set1[-1]-set1[0]*set2[-1]
  return t%b


# given base(int), exp(int), modular(int), return:
# base ^ exp in modular (int)

def exponential(base, exp, mod, print_trace=False):
  msg = "line219: Get base = %d to %d in mod = %d"%(base, exp, mod)
  s = format(exp, 'b')
  msg += "\n exponent in bin is "+s+"\n exp[0] = 1 start squaring..."
  k,y = 1, base
  while k < len(s):
    msg += "\n exp[%d] = "%k+s[k]+" result ==> "
    y = y*y %mod
    msg += "%d"%y
    if s[k] == '1':
      y = y*base %mod
      msg += "*base ==> %d"%y
    k += 1
  if print_trace: print msg
  return y

  
# test if n is prime
# given a positive <=n, e = n-1

def PossiblePrime(base, e, n):
  s = format(e, 'b')
  k, y = 1, base
  
  while k < len(s):
    root = y
    y = y*y % n

    if y==1 and root != 1 and root != n-1: return False

    if s[k] == '1': y = (y*base)%n
    k += 1

  if y != 1: return False
  return True


# generate random integer in the form: 1+lbits+1

def randomN(l=5, print_trace=False):
  n = '1'
  msg = "line104: Generating Random %d Bits \n from [0.0, 1.0) get random float "%l

  i = 0
  while i < l:
    r = random.random() #next float number [0.0, 1.0).
    msg += "\n %.4f... "%r
    r = 0 if r < 0.5 else 1
    n += '%d'%r
    i += 1

    if r == 0: msg += " <  0.5 ==> bit = 0"
    else: msg += " >= 0.5 ==> bit = 1"
    msg += " random number = "+ n + "."*(5-i)+"1"

  if print_trace: print msg+"\n" 
  n += '1'

  return n


def randomPrime(print_trace, l=5):

  possible_prime = False
  while not possible_prime:

    msg = ""
    N = 1
    while N <= 1:
      N = int(randomN(l, print_trace), 2)

    times = 20
    while times > 0:
      a = 1
      while a <= 1: a = int(random.random()*N)

      possible_prime = PossiblePrime(a, N-1, N)
      if not possible_prime:
        msg += "line119: Not Prime\n n = %d with a = %d\n"%(N, a)
        if print_trace: print msg
        break
      else:
        msg += "line123: Possible Prime\n n = %d with a = %d\n"%(N, a)
        times -= 1   
    
  if print_trace: print msg

  return N
  

def iniRSA(print_trace, name, l1=5, l2=5):
  msg = "\nline142: Generating RSA Public/Private Key Pair for "+name
  p = randomPrime(print_trace,l1)
  q = p
  while q == p:
    q = randomPrime(print_trace,l2)
  n = p*q
  phI = (p-1)*(q-1)

  e, d = 3, 0
  while e < root(phI)+1:
    msg += "\n e = %d"%e
    div = gcd(e, phI)
    if div == 1:
      msg += " can be a public key, looking for its inverse..."
      d = inverse(e, phI)
      msg += "\n\nline152: Inverse(private key) Found\n d = %d\n"%d
      break
    e += 1
  if d == 0: return iniRSA(print_trace, name, l1, l2)

  msg += "\nline156: "+name+"'s RSA Key Set"
  msg += "\n p = %d (bits) "%p+ format(p, 'b')
  msg += "\n q = %d (bits) "%q+ format(q, 'b')
  msg += "\n n = %d (bits) "%n+ format(n, 'b')
  msg += "\n e = %d (bits) "%e+ format(e, 'b')
  msg += "\n d = %d (bits) "%d+ format(d, 'b')

  if print_trace: print msg+"\n"

  return n, e, d, p, q


def padding(s, want, fill='0'):
  if len(s) >= want: return s[:want]
  return fill*(want-len(s))+s

class Certificate:
  def __init__(self, name="Trent", hashf=myhash, print_trace=False):
    rsa = iniRSA(print_trace, name)
    self.name = name
    self.N = rsa[0]
    self.public_key = rsa[1]
    self.__private_key = rsa[2]
    self.setHash(hashf)

  def setHash(self, f):
    self.hash = f

  def publicKey(self):
    return self.public_key

  def getN(self):
    return self.N

  def sign(self, m):
    padn = len(m) if len(m)%8==0 else 8-len(m)%8+len(m)
    return self.__decrypt(self.hash(padding(m, padn)))

  def __decrypt(self, m):
    return format(exponential(int(m, 2), self.__private_key, self.N), 'b')
    
  def encrypt(self, m, key, n):
    return format(int(m, 2)**key%n, 'b')

  def verify(self, m, v):
    padn = len(m) if len(m)%8==0 else 8-len(m)%8+len(m)
    return self.hash(padding(m, padn)) == padding(v, 8)

  def certificate(self, client):
    r = "".join(padding(format(ord(c), 'b'), 8) for c in client.name)
    r = padding(r, 6*8)
    r += padding(format(client.getN(), 'b'), 32)
    r += padding(format(client.publicKey(), 'b'), 32)

    # the following purely produce trace output

    tmp1 = self.hash(r)
    tmp2 = self.sign(r)
    print "line185: Trent Certificates "+client.name+"(bits)\n r = "+ r + "\n h(r) = " + tmp1 + "\n s = "+tmp2+"\n"
    print "line187: Certificate of "+client.name+"(int)\n h(r) = %d"%int(tmp1,2) +  "\n s = %d"%int(tmp2,2)+"\n"

    # end of output

    return r, self.sign(r)


