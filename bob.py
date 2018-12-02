from Crypto.Cipher import AES
from nacl.encoding import HexEncoder as benc
from Crypto.Random import get_random_bytes
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder as benc64
#import hashlib
import pickle
import ipfsapi
import urllib.request
import os

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS


DEBUG = 1
def printt(x, *kargs):
    if DEBUG == 1:
        print(x, *kargs, '\n')


  


###########################################################################
##############################  Bob  ######################################
###########################################################################
pub_alice = b'0a3c097a82338f0ce7361998b81890a48077cb259030ad418ebc3763f818b35c'
sec_alice = b'8a25b17e61530ed22b553bcdeff1915dd3e75ff6aaa9cad3663f940bcc45f039'

pub_bob =b'4ac97e5171c6ca9a4cb9d908188646716fc3881c307a9daefb5553853ce79823'
sec_bob =b'356e694054e09f3b79af8ecf152bbf880091329bc9d95a9831d81b68853af452'

# alice_sec_sign = '''-----BEGIN PRIVATE KEY-----
# MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAy0MTbwfArNtRBHo
# HWaNUXxBmuhC22clQWsVOQqLabmhRANCAAQkW9Fi+7Z4T7Yn8OmJy7adTq6+jfBJ
# XG3JOfr12fTvpWTzWZNg2Q3JdyIwnmN5oaZ7CUPAtZqpUAJb8m1XAnij
# -----END PRIVATE KEY-----'''

alice_pub_sign = '''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJFvRYvu2eE+2J/Dpicu2nU6uvo3w
SVxtyTn69dn076Vk81mTYNkNyXciMJ5jeaGmewlDwLWaqVACW/JtVwJ4ow==
-----END PUBLIC KEY-----'''

bob_sec_sign = '''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeoFgEDXuaM3PGCLs
vgS+fpdWUGH6x3mwhZpQ0+8mM1ehRANCAAQJWFF99MqTPA+u7Mnmwid+8Q7VXowi
4/27VBqG5JUGq3znOsEfEVTSHTvqMikk2MbxsdbtOfqi2og2qZjKKgyK
-----END PRIVATE KEY-----'''

bob_pub_sign = '''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECVhRffTKkzwPruzJ5sInfvEO1V6M
IuP9u1QahuSVBqt85zrBHxFU0h076jIpJNjG8bHW7Tn6otqINqmYyioMig==
-----END PUBLIC KEY-----'''

#pub_alice = b'0c6bd6e1ee00929b5b1d6a5540bc3d3b9bd4e2e5d4ed1dc2e319a5da41f58678'
#sec_alice = b'9c8625645d3db8da9eaceb39575e212d6f3bb24b4e5526955593240c54928669'

#pub_bob = b'b7d9feea1a2d1014316d7dd3640bf00e2a38381cd72d18d1e723b2b05eaf2457'
#sec_bob = b'd2058addad504f4c88ae81fa1c76d7aa76d494a9e6bd646e715e9ce204b7e2af'

alice_ipns = 'QmWbCUq6Js42xe7PLr8fT88htYrYViTV1erBNT6dxfzT1x'

def encrypte(message, sec_alice, pub_bob):

	seckey_alice = PrivateKey(sec_alice, encoder=benc)
	pubkey_bob = PublicKey(pub_bob, encoder=benc)

	box = Box(seckey_alice, pubkey_bob)
	#message = b"Kill all humans"
	encrypted = box.encrypt(message)
	return encrypted

def decrypte(encrypted, sec_bob, pub_alice):

	pubkey_alice = PublicKey(pub_alice, encoder=benc)
	seckey_bob = PrivateKey(sec_bob, encoder=benc)
	
	box = Box(seckey_bob, pubkey_alice)
	decrypted = box.decrypt(encrypted)

	return decrypted

def sign_it(message, sec_key):
	##########SIGN################
	#message = b'I give my permission to order #4355'
	#key = ECC.import_key(open('privkey.der').read())
	key = ECC.import_key(sec_key)
	h = SHA256.new(message)
	printt('hash', h.hexdigest())
	signer = DSS.new(key, 'fips-186-3')
	signature = signer.sign(h)
	printt('signature', benc.encode(signature))
	return signature

def verify_it(received_message, signature, pub_key):
	#########VERIFY###############
	#received_message = b'I give my permission to order #4355'
	key = ECC.import_key(pub_key)
	h = SHA256.new(received_message)
	verifier = DSS.new(key, 'fips-186-3')

	try:
		verifier.verify(h, signature)
		#printt ("The message is authentic.")
		return 1
		
	except ValueError:
		#printt ("The message is not authentic.")
		return 0

def get_ipns_pyobj(hash):
	url = 'http://127.0.0.1:8080/ipns/' + hash
	response = urllib.request.urlopen(url)
	return pickle.loads(response.read())    
	

def test_easy_address(address, seckey_bob, pubkey_alice, data_text):

	box = Box(seckey_bob, pubkey_alice)
	message = box.decrypt(benc64.decode(address))
	dev_mess = message.decode().split('@')
	print('dev_mess',dev_mess)
	if dev_mess[1] in data_text.decode():
		printt('Yes, it\'s my address!')
		return 1
	else:
		printt('No, it\'s not my address!')
		return 0
	
	
api = ipfsapi.connect("127.0.0.1", 5001)
#printt(decrypte(encrypte(b'test', sec_alice, pub_bob), sec_bob, pub_alice))

def crypto_uncon(hash, sec_bob = sec_bob, pub_alice = pub_alice, alice_pub_sign = alice_pub_sign, path = '', mess_id = ''):

	ipfs_crypto = api.get_pyobj(hash)
	crypto = api.get_pyobj(ipfs_crypto['Filehash'])

	#with open('crypto.p', 'rb') as f:
	 #   crypto = pickle.load(f)

	#pub_alice = crypto['PubKey'] 
		
	key = decrypte(crypto['Key'], sec_bob, pub_alice)
	printt('key', benc.encode(key), len(key))
		
	cipher = AES.new(key, AES.MODE_EAX, crypto['Nonce'])
	plaintext = cipher.decrypt(crypto['Ciphertext'])

	
	filename = decrypte(ipfs_crypto['Name'], sec_bob, pub_alice)
	if verify_it(plaintext, crypto['Signature'], alice_pub_sign):
		printt('The file ' + filename.decode() + ' is authentic')	
	if not os.path.exists(path):
		os.mkdir(path)
	if not os.path.exists(path + '/' + mess_id):
		os.mkdir(path + '/' + mess_id)		

	with open('./' + path + '/' + mess_id + '/' + filename.decode('utf-8'), 'wb') as file:
		data = file.write(plaintext)

	try:
		cipher.verify(crypto['Tag'])
		printt("The message is not corrupted")
		#printt(plaintext)
	except ValueError:
		printt("Key incorrect or message corrupted")





alice_point_dic = get_ipns_pyobj(alice_ipns)

sec_bob = sec_bob
pub_bob = pub_bob
seckey_bob = PrivateKey(sec_bob, encoder=benc)
pubkey_alice = PublicKey(pub_alice, encoder=benc)
pub_alice = alice_point_dic['Public_encryption']
alice_pub_sign = alice_point_dic['Public_signing']

alice_messages = list(alice_point_dic['Message'])
for mess in alice_messages:
	if test_easy_address(alice_point_dic['Message'][mess]['Address'], seckey_bob, pubkey_alice, pub_bob):
		for hash in alice_point_dic['Message'][mess]['Files']:
			crypto_uncon(hash, sec_bob, pub_alice, alice_pub_sign, alice_ipns, mess)

