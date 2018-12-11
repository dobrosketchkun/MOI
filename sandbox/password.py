from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
import secrets as s
import string

from nacl.encoding import HexEncoder as benc

def password_gen(type, length):
	'''
	Generate character password or XKCD type https://xkcd.com/936/
	Dictionary 'eff_long' is from https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
	'''
	if type == 'words':
		with open('eff_long') as f:
			words = [word.strip() for word in f]
			password = ' '.join(s.choice(words) for i in range(length))
		return password

	if type == 'char':
		listd = ['{' , '}' , '(' , ')' , '[' , ']' , '#' , ',' \
		, ':' , ';' , '^' , '.' , '?' , '!' , '|' , '&' , '_' \
		, '`' , '~' , '@' , '$' , '%' , '//' , '\\' , '=' , '+' \
		, '-' , '*','\'','"' ]
		alphabet = string.ascii_letters + string.digits + ''.join(listd)
		while True:
			password = ''.join(s.choice(alphabet) for i in range(length))
			if (any(c.islower() for c in password)
					and any(c.isupper() for c in password)
					and sum(c.isdigit() for c in password) >= 3):
				break
			
		return password
	else:
		print('type:', type,'\n')
		raise ValueError('Only "words" or "char" types are allowed.')	

password = password_gen('words', 6)
print(password)
#print(password_gen('char', 25))


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
			#if sha256[0] == '0':
				cond = 0	
				result = sha256 
				
					
			else:
				password = sha256
				counter += 1
		password = result	
	return result


def make_aes_key(password, length):
	password = sha000(password, 5)	
	return PBKDF2(password, salt = (str(sha000(password, 2))), dkLen = length, count = 10000)

key = make_aes_key(password, 32)
cipher = AES.new(key, AES.MODE_EAX)
print(benc.encode(key))

