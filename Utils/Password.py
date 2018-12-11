from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
try:
	from .Sup import sha000
except:
	from Sup import sha000
try:
	from .eff_long import words
except:	
	from eff_long import words
import secrets as s
import string


from nacl.encoding import HexEncoder as benc

def password_gen(type, length):
	'''
	Generate character password or XKCD type https://xkcd.com/936/
	Dictionary 'eff_long' is from https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
	'''
	if type == 'words':
		#with open('eff_long') as f:
			#words = [word.strip() for word in f]
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


def make_aes_key(password, length):
	password = sha000(password, 5)	
	return PBKDF2(password, salt = (str(sha000(password, 2))), dkLen = length, count = 10000)


if __name__ == '__main__':	
	password = password_gen('words', 6)
	print(password)
	#print(password_gen('char', 25))	
	key = make_aes_key(password, 32)
	cipher = AES.new(key, AES.MODE_EAX)
	print(benc.encode(key))

