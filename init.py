from Utils.Password import password_gen, make_aes_key
from Utils.Keys import make_me_keys
from Utils.Sup import printed, clear, initial_structure, pretty_json
from nacl.encoding import HexEncoder as benc
from Crypto.Cipher import AES
import getpass
import time
import pickle 
import sys


#Turn traceback off (0) or on (1)
sys.tracebacklimit = 1




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
	printed('\nPlease type down your own or a choosen one.\n')
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

print('\n')
time.sleep(0.2)
print('\n')
printed('Generating AES key...\n')
aes_key = make_aes_key(new_pass_first, 32)
printed('Done.\n')


printed('\nPlease enter your number list for branches, separated by coma (and remeber them).\nLike this number1,number2,number3,nubmer4,...,numberX (the number can be more than one digit long):\n')
branches = input('')

printed('\nGenerating key pairs...\n')
curve25519 = make_me_keys(new_pass_first, type = 'curve25519', key_amount = 10, branches = branches)
p256 = make_me_keys(new_pass_first, type = 'P-256', key_amount = 5, branches = branches)
printed('Done.\n')

keys = {}
keys['curve25519'] = curve25519
keys['p256'] = p256

cipher = AES.new(aes_key, AES.MODE_EAX)
nonce = cipher.nonce

ciphertext, tag = cipher.encrypt_and_digest(pickle.dumps(keys))

DB = {}
DB['Keys'] = {}
DB['Keys']['Data'] = ciphertext
DB['Keys']['Tag'] = tag
DB['Keys']['Nonce'] = nonce

printed('\nWriting database file...\n')
# with open(benc.encode(tag).decode() +'@' + benc.encode(nonce).decode() + "_keys.aes", "wb") as f:
    # f.write(ciphertext)

with open('yourdata.aesed', 'wb') as f:
    pickle.dump(DB, f, pickle.HIGHEST_PROTOCOL)	
	
printed('Done.\n')	


kn = 1
while kn:
	printed('\nWhat key do you want to use to encrypt/decrypt messages? (number in order)\n') #add restrains
	c_number = input('')
	printed('\nYour choice:\n')
	c_choice = [key for key in keys['curve25519'] if key[0] == int(c_number)]
	с_text = benc.encode(c_choice[0][1].public_key.__bytes__()).decode()
	printed(с_text, 0.01)
	print('\n')
	printed('\nWhat key do you want to use to sign messages? (number in order)\n')
	p_number = input('')
	printed('\nYour choice:\n')
	p_choice = [key for key in keys['p256'] if key[0] == int(p_number)]
	p_text = benc.encode(p_choice[0][1].export_key(format='DER')).decode()
	printed(p_text, 0.01)

	printed('\nAre you happy with your choice?\n')
	answ = input('')
	if answ in ['y','yes','yeap','yeah'] :
		clear()
		kn = 0
	else:
		printed('\nLet\'s try again\n')

your_struncture = initial_structure #wrting initial node dict
your_struncture['Public_encryption'] = с_text
your_struncture['Public_signing'] = p_text
#your_struncture['Messages'] = {}
#your_struncture[''Points''] = []
#pretty_json(your_struncture, 'w')

#ipns your_struncture