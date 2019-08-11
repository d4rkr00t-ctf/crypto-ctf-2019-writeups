# crypto-ctf-2019-writeups

## Time Capsule
We are given two files `time_capsule.py` and `time_capsule.txt`
```
$ cat time_capsule.txt
(30263951492003430418944035844723976843761515320480688994488846431636782360488888188067655841720110193942081554547272176290791213962513701884837856823209432209367951673301622535940395295826053396595886942990258678430777333636450042181585837395671842878310404080487115827773100028876775230121509570227303374672524063165714509957850966189605469484201028704363052317830254920108664916139026741331552127849056897534960886647382429202269846392809641322613341548025760209280611758326300214885296175538901366986310471066687700879304860668964595202268317011117634615297226602309205086105573924029744405559823548638486054634428L, 16801166465109052984956796702219479136700692152603640001472470493600002617002298302681832215942994746974878002533318970006820414971818787350153626339308150944829424332670924459749331062287393811934457789103209090873472485865328414154574392274611574654819495894137917800304580119452390318440601827273834522783696472257727329819952363099498446006266115011271978143149347765073211516486037823196033938908784720042927986421555211961923200006343296692217770693318701970436618066568854673260978968978974409802211538011638213976732286150311971354861300195440286582255769421094876667270445809991401456443444265323573485901383L, 6039738711082505929, 13991757597132156574040593242062545731003627107933800388678432418251474177745394167528325524552592875014173967690166427876430087295180152485599151947856471802414472083299904768768434074446565880773029215057131908495627123103779932128807797869164409662146821626628200600678966223382354752280901657213357146668056525234446747959642220954294230018094612469738051942026463767172625588865125393400027831917763819584423585903587577154729283694206436985549513217882666427997109549686825235958909428605247221998366006018410026392446064720747424287400728961283471932279824049509228058334419865822774654587977497006575152095818L)

$ cat time_capsule.py
#!/usr/bin/python

from Crypto.Util.number import *
from secret import flag, n, t, z

def encrypt_time_capsule(msg, n, t, z):
	m = bytes_to_long(msg)
	l = pow(2, pow(2, t), n)
	c = l ^ z ^ m
	return (c, n, t, z)

print encrypt_time_capsule(flag, n, t, z)
```
From `(msg, n, t, z)`, we get `(flag, n, t, z)` where `(n, t, z)` remain constant. And as `l` depends on `n` and `t`, it also remains constant for every encryption.

`flag_enc = l ^ z ^ m` where `m` is our flag. We can compute m as `flag_enc ^ l ^ z = l ^ z ^ m ^ l ^ z = m`. (Why? => xor is commutative, `a ^ a = 0`, `a ^ 0 = a`)

Now, the challenge is to calculate l.

2<sup>2<sup>t</sup></sup> mod n = 2<sup>2<sup>t</sup> mod phi(n)</sup> mod n

As n is very large, we can't compute phi(n) directly. But we can use the property, if `n = a * b`, then `phi(n) = phi(a) * phi(b)`

Using this [script](./fetch_factors.py)
```
from fetch_factors import get_factors
from Crypto.Util.number import long_to_bytes

with open("time_capsule.txt", "r") as f: flag_enc, n, t, z = map(int, f.read().strip().replace("L", "")[1:-1].split(", "))
phi = 1
for factor in map(int, get_factors(str(n))): phi *= (factor - 1)
l = pow(2, pow(2, t, phi), n)

print(long_to_bytes(c ^ l ^ z))
# CCTF{_______________________________________________Happy_Birthday_LCS______________________________________________}
```

## Clever Girl
We are given two files `clever_girl.py` and `enc.txt`.
```
$ cat enc.txt
Fraction(p, p+1) + Fraction(q+1, q) = Fraction(2*s - 153801856029563198525204130558738800846256680799373350925981555360388985602786501362501554433635610131437376183630577217917787342621398264625389914280509, s + 8086061902465799210233863613232941060876437002894022994953293934963170056653232109405937694010696299303888742108631749969054117542816358078039478109426)
n = 161010103536746712075112156042553283066813155993777943981946663919051986586388748662616958741697621238654724628406094469789970509959159343108847331259823125490271091357244742345403096394500947202321339572876147277506789731024810289354756781901338337411136794489136638411531539112369520980466458615878975406339
c = 64166146958225113130966383399465462600516627646827654061505253681784027524205938322376396685421354659091159523153346321216052274404398431369574383580893610370389016662302880230566394277969479472339696624461863666891731292801506958051383432113998695237733732222591191217365300789670291769876292466495287189494

$ cat clever_girl.py
#!/usr/bin/env python

import gmpy2
from fractions import Fraction
from secret import p, q, s, X, Y
from flag import flag

assert gmpy2.is_prime(p) * gmpy2.is_prime(q) > 0
assert Fraction(p, p+1) + Fraction(q+1, q) == Fraction(2*s - X, s + Y)
print 'Fraction(p, p+1) + Fraction(q+1, q) = Fraction(2*s - %s, s + %s)' % (X, Y)

n = p * q
c = pow(int(flag.encode('hex'), 16), 0x20002, n)
print 'n =', n
print 'c =', c
```

Let's look at the equation and simplify.

![e1](https://latex.codecogs.com/gif.latex?%5Cfrac%7Bp%7D%7Bp%20&plus;%201%7D%20&plus;%20%5Cfrac%7Bq%20&plus;%201%7D%7Bq%7D%20%3D%20%5Cfrac%7B2s%20-%20x%7D%7Bs%20&plus;%20y%7D)

![e2](https://latex.codecogs.com/gif.latex?%5Cfrac%7B2n%20&plus;%20p%20&plus;%20q%20&plus;%201%7D%7Bn%20&plus;%20q%7D%20%3D%20%5Cfrac%7B2s%20-%20x%7D%7Bs%20&plus;%20y%7D)

Breaking into two equations
`2n + p + q + 1 = 2s - x`, `n + q = s + y`. Eliminating s gives `q = p + 1 + x + 2y`.

Since n = pq, n = p<sup>2</sup> + p(1 + x + 2y)
Alright, a quadratic equation for p, and as we have all the variables (x, y, n), solving it gives
```
p = 12604273285023995463340817959574344558787108098986028639834181397979984443923512555395852711753996829630650627741178073792454428457548575860120924352450409
q = 12774247264858490260286489817359549241755117653791190036750069541210299769639605520977166141575653832360695781409025914510310324035255606840902393222949771
```

Now, we can solve our RSA.
```
>>> import gmpy2

>>> phi = (p - 1) * (q - 1)
>>> d = gmpy2.invert(e, phi)
ZeroDivisionError: invert() no inverse exists
```
So, for RSA e and phi must be co-prime, which isn't the case here. Let's fix this.
```
g = gmpy2.gcd(e, phi)
e //= g
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
m, _ = gmpy2.iroot(m, g)
print(hex(x)[2:-1].decode("hex"))
# CCTF{4Ll___G1rL5___Are__T4len73E__:P}
```

## Alone In The Dark
```
$ cat alone_in_the_dark.py
#!/usr/bin/env python

import gmpy2
from hashlib import sha256
from secret import u, v, x, y

assert ((u+1)**2 + u**2 - v**2)**2 + ((x+1)**3 - x**3 - y**2)**4 + (gmpy2.is_prime(v) + 1)**6 + (gmpy2.is_prime(y) - 1)**8 + (len(bin(u)[2:]) - 664)**10 + (len(bin(x)[2:]) - 600)**12 == 664 - 600

flag = 'CCTF{' + sha256(str(u) + str(v) + str(x) + str(y)).hexdigest() + '}'
```
So we have an assert statement of form a<sup>2</sup> + b<sup>4</sup> + c<sup>6</sup> + d<sup>8</sup> + e<sup>10</sup> + f<sup>12</sup> == 64

Making all zero but one gives us the upper bound for all the variables, ie, `a < 9, b < 3, c < 3, d < 2, e < 2, f < 2`. These constraints can be easily bruteforces to find solutions.
```
for a in range(9):
    for b in range(3):
        for c in range(3):
            for d in range(2):
                for e in range(2):
                    for f in range(2):
                        if a**2 + b**4 + c**6 + d**8 + e**10 + f**12 == 64: print(a, b, c, d, e, f)

(0, 0, 2, 0, 0, 0)
(8, 0, 0, 0, 0, 0)
```
c can be either 1<sup>6</sup> or 2<sup>6</sup>, so first tuple is our desired solution. d = 0 => y is prime. Let's break down and write all the simplifications.
```
(u+1)**2 + u**2 = v**2 -- (1)
v is prime
len(bin(u)[2:]) = 664

(x+1)**3 - x**3 = y**2 -- (2)
y is prime
len(bin(x)[2:]) = 600
```
Both equations `(1) and (2)` can be transformed to Pell's equations and solved.

![e3](https://latex.codecogs.com/gif.latex?%28u%20&plus;%201%29%5E2%20&plus;%20u%5E2%20%3D%20v%5E2%5C%5C%202u%5E2%20&plus;%202u%20&plus;%201%20-%20v%5E2%20%3D%200%5C%5C%204u%5E2%20&plus;%204u%20&plus;%202%20-%202v%5E2%20%3D%200%5C%5C%20%282u%20&plus;%201%29%5E2%20-%202v%5E2%20%3D%20-1%5C%5C%20u%27%5E2%20-%202v%27%5E2%20%3D%20-1)
where `u = (u' - 1) / 2` and `v = v'`

![e4](https://latex.codecogs.com/gif.latex?%28x%20&plus;%201%29%5E3%20-%20x%5E3%20%3D%20y%5E2%5C%5C%203x%5E2%20&plus;%203x%20&plus;%201%20%3D%20y%5E2%5C%5C%20y%5E2%20-%203%28x%5E2%20&plus;%20x%29%20%3D%201%5C%5C%204y%5E2%20-%203%284x%5E2%20&plus;%204x%29%20%3D%204%5C%5C%204y%5E2%20-%203%284x%5E2%20&plus;%204x%20&plus;%201%20-%201%29%20%3D%204%5C%5C%204y%5E2%20-%203%282x%20&plus;%201%29%5E2%20%3D%201%5C%5C%20y%27%5E2%20-%203x%27%5E2%20%3D%201)
where `x = (x' - 1) / 2` and `y = y' / 2`
```
import gmpy2

u1, v1 = 1, 1
while 1:
    uk, vk = u1 + 2 * v1, u1 + v1
    if uk % 2 == 1:
        u, v = (uk - 1) // 2, vk
        if len(bin(u)[2:]) == 664 and gmpy2.is_prime(v):
            break
    if len(bin(uk)[2:]) > 664:
        print("not found")
        break
    u1, v1 = uk, vk

x1, y1 = 1, 2
while 1:
    xk, yk = 2 * x1 + y1, 3 * x1 + 2 * y1
    if xk % 2 == 1 and yk % 2 == 0:
        x, y = (xk - 1) // 2, yk // 2
        if len(bin(x)[2:]) == 600 and gmpy2.is_prime(y):
            break
    if len(bin(xk)[2:]) > 600:
        print("not found")
        break
    x1, y1 = xk, yk
```
`Flag = CCTF{07f594e5fb8f6d5f82e5cce06e2a2c74c1bffce370cd904821fdd71027faa084}`
