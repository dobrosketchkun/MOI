import secrets as s
import string

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


print(password_gen('words', 6))
print(password_gen('char', 25))