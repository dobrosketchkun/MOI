from Crypto.PublicKey import ECC, RSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from nacl.encoding import HexEncoder as benc
from nacl.public import PrivateKey, PublicKey, Box
from Crypto.Protocol.KDF import PBKDF2
import getpass


def sha000(password, circles = 1):
	'''
	Some defence from rainbow tables
	'''
	for times in range(circles):
		cond = 1
		counter = 0
		while cond:
			sha256 = str(SHA256.new(password.encode()).hexdigest())
			if sha256[0:4] == '0000':
				cond = 0	
				result = sha256 
			else:
				password = sha256
				counter += 1
		password = result	
	return result

def make_rsa_keys(password, size = 2048, key_amount = 1):
	'''
	Make RSA key pairs from any string.
	Returns a list
	'''
	password = sha000(password, 5)
	keys = []
	sha256 = str(SHA256.new(password.encode()).digest())	

	def my_rand(n):
		my_rand.counter += 1
		return PBKDF2(master_key, "my_rand:%d" % my_rand.counter, dkLen=n, count=1)

	my_rand.counter = 0
	for tymes in range(key_amount):
		master_key = PBKDF2(password, salt = sha256, count=10000) 
		keys.append(RSA.generate(size, randfunc=my_rand)) #rsa_key.export_key('PEM')
		password = keys[-1].export_key('PEM').decode()
	return keys

def make_p256_keys_pbkdf2(password, key_amount = 1):
	'''
	Make P-256 multiple key pairs at once from any string
	Returns a list
	'''
	password = sha000(password, 5)
	salt = SHA256.new(password.encode()).digest()
	#print('salt',benc.encode(salt))
	count = int(str(int(benc.encode(salt),16))[0:5])

	master_key = PBKDF2(password, salt = str(salt), count=count) 
	
	def my_rand(n):
		my_rand.counter += 1
		return PBKDF2(master_key, "my_rand:%d" % my_rand.counter, dkLen=n, count=1)
	my_rand.counter = 0
	
	keys = []
	for tymes in range(key_amount):

		key = PBKDF2(password, salt = str(salt), count = count)
		keys.append(ECC.generate(curve = 'P-256', randfunc=my_rand))
		password = key
	return keys

	
def make_curve25519_keys_pbkdf2(password, key_amount = 1):
	'''
	Make multiple key pairs at once, eather P-256 or curve25519 from any string
	Returns a list
	'''
	password = sha000(password, 5)
	salt = SHA256.new(password.encode()).digest()
	#print('salt',benc.encode(salt))
	count = int(str(int(benc.encode(salt),16))[0:5])

	dkLen = 32
	
	keys = []
	for tymes in range(key_amount):
		#sha256 = SHA256.new(password)
		#count = int(str(int(benc.encode(sha256.digest()),16))[0:5])
		key = PBKDF2(password, salt = str(salt), dkLen = dkLen, count = count)
		keys.append(PrivateKey(benc.encode(key), encoder=benc))
		password = key
	return keys
	

	

def make_me_keys(password, type, key_amount = 1, size_rsa = 2048):
	'''
	Make key pairs for RSA, P-256 or curve25519 in amounts from any string
	Returns a list
	'''
	if type == 'P-256':
		return make_p256_keys_pbkdf2(password, key_amount = key_amount)
	elif type == 'curve25519':
		return make_curve25519_keys_pbkdf2(password, key_amount = key_amount)
	elif type == 'RSA':
		return make_rsa_keys(password, size = size_rsa, key_amount = key_amount)
	else:
		print('type:', type,'\n')
		raise ValueError('Only P-256, curve25519 or RSA types are allowed.')	
	


if __name__ == '__main__':
	while True:
		#password = getpass.getpass('Please enter your password (type exit to close):\n')
		password = input('\nPlease enter your password (type exit to close):\n')
		if password == 'exit':
			quit()
		else:
			print('')
			p256 = make_me_keys(password, 'P-256')[0]
			sec_pem = p256.export_key(format='PEM')
			sec_der = p256.export_key(format='DER')
			print(sec_pem)
			print('')

			pub_pem = p256._export_public_pem(compress = 0) #PEM
			pub_der = p256._export_subjectPublicKeyInfo(compress = 0) #DER
			print(pub_pem)
			print('')


			curve25519 = make_me_keys(password, 'curve25519')[0]
			pub19 = benc.encode(curve25519.public_key.__bytes__())
			sec19 = benc.encode(curve25519.__bytes__())
			print(pub19)
			print(sec19)
			print('')
			
			rsa_key = make_me_keys(password, 'RSA')[0]
			print(rsa_key.export_key('PEM').decode())
			print('')			
