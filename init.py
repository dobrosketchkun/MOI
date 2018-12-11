from Utils.Password import password_gen, make_aes_key
from Utils.Keys import make_me_keys
from Utils.Sup import printed, clear
from nacl.encoding import HexEncoder as benc
from Crypto.Cipher import AES
import getpass
import time
import pickle 
# answ_new_password = input('Would you like yo use your password or newly generated one? (mine/new)')
# if answ_new_password == 'mine':
	# pass
# elif answ_new_password == 'new':
	# pass
	# else:
		# printed('type:', type,'\n')
		# raise ValueError('Only "mine" or "new" types are allowed.')


printed('\nNow you will see a set of ten six-word newly generated password. Please, choose one.')
print('\n')

for i in [password_gen('words', 6) for pswd in range(10)]:
	printed(i, 0.01)
	print('\r')

ps = 1
while ps:	
	printed('\nPlease type down a choosen one.\n')
	#new_pass_first = input('')
	new_pass_first = getpass.getpass('')
	printed('\nPlease type it again.\n')
	#new_pass_second = input('')
	new_pass_second = getpass.getpass('')
	if new_pass_first == new_pass_second:
		ps = 0
	else:
		printed('Passwords are not the same. Try again.\n')

yn = 1
while yn:		
	printed('\nDid you write down or remember your password? (y/n)\n')
	answ = input('')
	if answ in ['y','yes','yeap','yeah'] :
		clear()
		yn = 0
	else:
		printed('\nThen, do it right now.\n')
	
printed('Generating AES key...\n')
aes_key = make_aes_key(new_pass_first, 32)
printed('Done.\n')


printed('\nPlease enter your number list for branches, separated by coma.\nLike this number1,number2,number3,nubmer4,...,numberX (the number can be more than one digit long):\n')
branches = input('')
printed('\nGenerating key pairs...\n')
curve25519 = make_me_keys(new_pass_first, type = 'curve25519', key_amount = 1000, branches = branches)
p256 = make_me_keys(new_pass_first, type = 'P-256', key_amount = 500, branches = branches)
printed('Done.\n')

keys = {}
keys['curve25519'] = curve25519
keys['p256'] = p256

cipher = AES.new(aes_key, AES.MODE_EAX)
nonce = cipher.nonce

ciphertext, tag = cipher.encrypt_and_digest(pickle.dumps(keys))
printed('\nWriting key file...\n')
with open(benc.encode(tag).decode() +'@' + benc.encode(nonce).decode() + "_keys.aes", "wb") as f:
    f.write(ciphertext)
printed('Done.\n')	