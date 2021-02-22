#!/usr/bin/env python3
from hashlib import sha256
from Crypto.Util.number import *

DEBUG = False
# DEBUG = True

def get_keys():
	p = getPrime(1024)
	q = getPrime(1024)
	n = p*q
	e = 65537

	phi = (p-1)*(q-1)
	d = inverse(e, phi)
	
	return (e, n, d)

def sign(msg, d, n) -> 'Hex Signature':
	h = sha256(msg.encode()).hexdigest()
	h = int(h, 16)
	S = pow(h, d, n)
	S = hex(S)[2:]
	return S

def verify(msg, S, e, n):
	S = int(S, 16)
	s = pow(S, e, n)
	sign_hash = hex(s)[2:]

	msg_hash = sha256(msg.encode()).hexdigest()

	# ignore DEBUG if it's set to False(0)
	if DEBUG:
		print("\n========== RSA Signature Verification ==========\n")
		print(f"[+] Original msg\n{msg}")
		print(f"\nMessage hash:\n{msg_hash}")
		print(f"\nHash from Sign:\n{sign_hash}")
		print("\n================================================\n")

	# assert msg_hash == sign_hash
	if msg_hash == sign_hash:
		return True

	return False

def test():
	# Alice
	alice_msg = "Hi Bob! How are you?"
	m1 = bytes_to_long(alice_msg.encode())
	e1, n1, d1 = get_keys()
	
	# Bob
	e2, n2, d2 = get_keys()
	
	# Alice encrypts her msg with Bob's public keys(e2, n2)
	c1 = pow(m1, e2, n2)

	# Alice Sign's her msg
	S1 = sign(alice_msg, d1, n1)
	
	
	# Bob decrypts Alice's msg with his own private key(d2)
	a_dec = pow(c1, d2, n2)

	assert a_dec == m1

	a_dec = long_to_bytes(a_dec).decode()
	
	
	# ignore DEBUG if it's set to False(0)
	if DEBUG:
		print("====================================================")
		print("=============== D E B U G    M O D E ===============")
		print("====================================================")
		print("\n========== Alice ==========")
		print(f"Alice's msg\n{alice_msg}\n")
		print("e1:", e1)
		print("n1:", n1)
		print("d1:", d1)
		print(f"\n[+] Alice's Signature:\n{S1}")
		print("\n========== Bob ==========")
		print("e2:", e2)
		print("n2:", n2)
		print("d2:", d2)
		print(f"\n[+] Bob's intercepted msg\n{a_dec}")


	# Bob verifies Alice's msg
	print(f"[+] Signature valid:", verify(a_dec, S1, e1, n1))

	# Eve(The Attacker) tries to tamper data
	tmp = "Hi Bob! How are you?x"	# tampered msg
	print(f"[+] Signature valid:", verify(tmp, S1, e1, n1))
	
if __name__ == '__main__':
	"""
	Function Details:
	-----------------
	test() - Tests the RSA Sign/Verify Concept
	"""

	test()
