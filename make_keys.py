from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from nacl.encoding import HexEncoder as benc
from nacl.public import PrivateKey, PublicKey, Box
import getpass


def make_keys(password, type):
	'''
	Make a key pair to eather P-256 or curve25519 from any string
	'''
	sha256 = SHA256.new(password.encode())	
	
	if type == 'P-256':
		sha = sha256.digest()
		int1 = int.from_bytes(sha, byteorder='little')
		int2 = abs(int.from_bytes(sha, byteorder='big', signed=True))
		d = abs(int1 - int2)
		try:
			return ECC.construct(curve = 'P-256', d = d)
		except:
			d = d/2
			return ECC.construct(curve = 'P-256', d = d)
			
	if type == 'curve25519':
		sha = sha256.hexdigest()
		return PrivateKey(sha, encoder=benc)
	else:
		raise ValueError('Only P-256 or curve25519 types are allowed.')
		
		
		
def make_keys_pbkdf2(password, type, key_amount = 1):
	'''
	Make a multiple key pairs at once, eather P-256 or curve25519 from any string
	'''
	if type == 'P-256':
		dkLen = 31
	elif type == 'curve25519':
		dkLen = 32
	else:
		print('type:', type,'\n')
		raise ValueError('Only P-256 or curve25519 types are allowed.')
		
	keys = []
	for tymes in range(key_amount):
		sha256 = SHA256.new(password)
		count = int(str(int(benc.encode(sha256.digest()),16))[0:5])
		key = PBKDF2(password, salt = str(sha256), dkLen = dkLen, count = count)
		if type == 'P-256':
			d = int(benc.encode(key),16)
			keys.append(ECC.construct(curve = 'P-256', d = d))
		else:
			keys.append(PrivateKey(benc.encode(key), encoder=benc))
		key = password
	return keys



if __name__ == '__main__':
	while True:
		#password = getpass.getpass('Please enter your password (type exit to close):\n')
		password = input('\nPlease enter your password (type exit to close):\n')
		if password == 'exit':
			quit()
		else:
			print('')
			p256 = make_keys(password, 'P-256')
			sec_pem = p256.export_key(format='PEM')
			#sec_der = p256.export_key(format='DER')
			print(sec_pem)
			print('')

			pub_pem = p256._export_public_pem(compress = 0) #PEM
			#pub_der = p256._export_subjectPublicKeyInfo(compress = 0) #DER
			print(pub_pem)
			print('')


			curve25519 = make_keys(password, 'curve25519')
			pub19 = benc.encode(curve25519.public_key.__bytes__())
			sec19 = benc.encode(curve25519.__bytes__())
			print(pub19)
			print(sec19)
