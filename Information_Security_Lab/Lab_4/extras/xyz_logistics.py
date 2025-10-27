"""XYZ Logistics - Demonstration of RSA key generation vulnerabilities and attacks.

This script provides several educational attacks that an insider (Eve)
could use against a vulnerable RSA deployment where primes or private
exponent are weak or partially leaked. It includes:

- Trial-division factoring for tiny primes (bad RNG / tiny key sizes).
- Fermat factorization for primes that are too close.
- GCD-based attack when two moduli share a prime factor (bad RNG reuse).
- Wiener's attack to recover small private exponent d.

Each attack function demonstrates recovering private information from
the public modulus n and public exponent e (and in some cases multiple
public moduli). The script also prints mitigation recommendations.

Note: This is educational code for lab use only. Do not use against
real systems you don't own.
"""
from Crypto.Util import number
import math
import random
from fractions import Fraction


def generate_rsa(bits=512, close_primes=False, small_d=False, shared_prime=None):
	"""Generate an RSA key pair with optional weaknesses for demonstration.

	- close_primes: make p and q close to each other (Fermat attack viable)
	- small_d: choose a small private exponent d (vulnerable to Wiener's attack)
	- shared_prime: if provided as int, reuse this prime as p to produce shared factor across moduli
	Returns (n, e, d, p, q)
	"""
	if shared_prime:
		p = shared_prime
		q = number.getPrime(bits // 2)
	else:
		if close_primes:
			# generate a random p, then set q = p + small
			p = number.getPrime(bits // 2)
			gap = 2 ** (bits // 4 - 2)
			# make q close to p
			q = p + random.randrange(1, gap)
			# ensure q is prime
			while not number.isPrime(q):
				q = p + random.randrange(1, gap)
		else:
			p = number.getPrime(bits // 2)
			q = number.getPrime(bits // 2)
			while q == p:
				q = number.getPrime(bits // 2)

	n = p * q
	phi = (p - 1) * (q - 1)
	e = 65537

	if small_d:
		# choose small d and compute e as inverse mod phi
		# pick d small like n**0.25 / 3 (but integer)
		target = max(3, int(pow(n, 0.25) // 3))
		d = random.randrange(2, target)
		while math.gcd(d, phi) != 1:
			d = random.randrange(2, target)
		e = number.inverse(d, phi)
	else:
		# standard e and compute d
		if math.gcd(e, phi) != 1:
			# fallback: pick another e
			e = 3
			while math.gcd(e, phi) != 1:
				e = number.getPrime(16)
		d = number.inverse(e, phi)

	return n, e, d, p, q


def trial_division_factor(n, limit=1000000):
	"""Factor n by trial division up to `limit`.
	Returns a factor or None."""
	if n % 2 == 0:
		return 2
	i = 3
	while i <= limit and i * i <= n:
		if n % i == 0:
			return i
		i += 2
	return None


def fermat_factor(n):
	"""Fermat factorization: effective when p and q are close."""
	a = math.isqrt(n)
	if a * a < n:
		a += 1
	while True:
		b2 = a * a - n
		if b2 < 0:
			a += 1
			continue
		b = math.isqrt(b2)
		if b * b == b2:
			return a - b
		a += 1


def gcd_shared_factor(ns):
	"""Given a list of moduli, return any common prime factor via gcd.
	Returns tuple (i, j, factor) if found else None."""
	length = len(ns)
	for i in range(length):
		for j in range(i + 1, length):
			g = math.gcd(ns[i], ns[j])
			if g != 1 and g != ns[i] and g != ns[j]:
				return i, j, g
	return None


def continued_fraction(numer, denom):
	cf = []
	while denom:
		a = numer // denom
		cf.append(a)
		numer, denom = denom, numer - a * denom
	return cf


def convergents_from_cf(cf):
	# yields (k, d) convergents for continued fraction cf
	convs = []
	for i in range(len(cf)):
		num, den = 1, 0
		for c in cf[:i+1][::-1]:
			num, den = den + num * c, num
		convs.append((num, den))
	return convs


def is_perfect_square(n):
	t = math.isqrt(n)
	return t * t == n


def wiener_attack(e, n):
	"""Attempt to recover d using Wiener's attack for small d."""
	cf = continued_fraction(e, n)
	convs = convergents_from_cf(cf)
	for k, d in convs:
		if k == 0:
			continue
		# check if d is candidate private exponent
		if (e * d - 1) % k != 0:
			continue
		phi_candidate = (e * d - 1) // k
		# solve for roots of x^2 - (n - phi + 1)x + n = 0
		s = n - phi_candidate + 1
		disc = s * s - 4 * n
		if disc >= 0 and is_perfect_square(disc):
			t = math.isqrt(disc)
			p = (s + t) // 2
			q = (s - t) // 2
			if p * q == n:
				return d
	return None


def demo_small_primes():
	print('Demo: small primes (trial division)')
	n, e, d, p, q = generate_rsa(bits=256)  # tiny; only for demo
	print('Generated n bits:', n.bit_length())
	f = trial_division_factor(n, limit=10000)
	if f:
		print('Found small factor via trial division:', f)
		print('Recovered keys: p=', f, 'q=', n//f)
	else:
		print('No small factor found')


def demo_close_primes():
	print('\nDemo: close primes (Fermat factorization)')
	n, e, d, p, q = generate_rsa(bits=512, close_primes=True)
	print('n bitlen:', n.bit_length())
	f = fermat_factor(n)
	print('Fermat found factor p=', f)
	print('Recovered q=', n//f)


def demo_shared_prime():
	print('\nDemo: shared prime across moduli (GCD attack)')
	# generate a shared prime
	p = number.getPrime(128)
	n1, e1, d1, p1, q1 = generate_rsa(bits=256, shared_prime=p)
	n2, e2, d2, p2, q2 = generate_rsa(bits=256, shared_prime=p)
	print('n1 bits:', n1.bit_length(), 'n2 bits:', n2.bit_length())
	res = gcd_shared_factor([n1, n2])
	if res:
		i, j, factor = res
		print(f'GCD attack found shared factor between n{i} and n{j}:', factor)
	else:
		print('No shared factor found')


def demo_wiener():
	print('\nDemo: small private exponent (Wiener attack)')
	n, e, d, p, q = generate_rsa(bits=512, small_d=True)
	print('Generated (n bits, e, small d):', n.bit_length(), e, d)
	recovered = wiener_attack(e, n)
	if recovered:
		print('Wiener recovered d =', recovered)
	else:
		print('Wiener failed to recover d')


def mitigations_text():
	print('\nMitigations:')
	print('- Use sufficiently large key sizes: at least 2048 bits for RSA (longer is better).')
	print('- Ensure primes are generated with a cryptographically secure RNG and are unpredictable.')
	print('- Avoid reuse of primes across keypairs; ensure proper entropy and independent generation.')
	print('- Do not use extremely small private exponents; follow standard key generation (e.g., e=65537).')
	print('- Use constant-time and vetted cryptographic libraries; avoid home-grown key generation code.')
	print('- Monitor for weak keys using GCD scans across issued certificates/keys to detect shared factors.')


def main():
	demo_small_primes()
	demo_close_primes()
	demo_shared_prime()
	demo_wiener()
	mitigations_text()


if __name__ == '__main__':
	main()

