from Crypto.Cipher import AES
from nacl.encoding import HexEncoder as benc
from Crypto.Random import get_random_bytes
from nacl.public import PrivateKey, PublicKey, Box

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

#import hashlib
import pickle
import ipfsapi


DEBUG = 1
def printt(x, *kargs):
    if DEBUG == 1:
        print(x, *kargs, '\n')


###########################################################################
################################  Alice  ##################################
###########################################################################
pub_alice = b'0a3c097a82338f0ce7361998b81890a48077cb259030ad418ebc3763f818b35c'
sec_alice = b'8a25b17e61530ed22b553bcdeff1915dd3e75ff6aaa9cad3663f940bcc45f039'

pub_bob =b'4ac97e5171c6ca9a4cb9d908188646716fc3881c307a9daefb5553853ce79823'
sec_bob =b'356e694054e09f3b79af8ecf152bbf880091329bc9d95a9831d81b68853af452'

alice_sec_sign = '''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAy0MTbwfArNtRBHo
HWaNUXxBmuhC22clQWsVOQqLabmhRANCAAQkW9Fi+7Z4T7Yn8OmJy7adTq6+jfBJ
XG3JOfr12fTvpWTzWZNg2Q3JdyIwnmN5oaZ7CUPAtZqpUAJb8m1XAnij
-----END PRIVATE KEY-----'''

alice_pub_sign = '''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJFvRYvu2eE+2J/Dpicu2nU6uvo3w
SVxtyTn69dn076Vk81mTYNkNyXciMJ5jeaGmewlDwLWaqVACW/JtVwJ4ow==
-----END PUBLIC KEY-----'''

# bob_sec_sign = '''-----BEGIN PRIVATE KEY-----
# MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeoFgEDXuaM3PGCLs
# vgS+fpdWUGH6x3mwhZpQ0+8mM1ehRANCAAQJWFF99MqTPA+u7Mnmwid+8Q7VXowi
# 4/27VBqG5JUGq3znOsEfEVTSHTvqMikk2MbxsdbtOfqi2og2qZjKKgyK
# -----END PRIVATE KEY-----'''

bob_pub_sign = '''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECVhRffTKkzwPruzJ5sInfvEO1V6M
IuP9u1QahuSVBqt85zrBHxFU0h076jIpJNjG8bHW7Tn6otqINqmYyioMig==
-----END PUBLIC KEY-----'''

#pub_alice = b'0c6bd6e1ee00929b5b1d6a5540bc3d3b9bd4e2e5d4ed1dc2e319a5da41f58678'
#sec_alice = b'9c8625645d3db8da9eaceb39575e212d6f3bb24b4e5526955593240c54928669'

#pub_bob = b'b7d9feea1a2d1014316d7dd3640bf00e2a38381cd72d18d1e723b2b05eaf2457'
#sec_bob = b'd2058addad504f4c88ae81fa1c76d7aa76d494a9e6bd646e715e9ce204b7e2af'


def encrypte(message, sec_alice, pub_bob):

	seckey_alice = PrivateKey(sec_alice, encoder=benc)
	pubkey_bob = PublicKey(pub_bob, encoder=benc)

	box = Box(seckey_alice, pubkey_bob)
	#message = b"Kill all humans"
	encrypted = box.encrypt(message)
	return encrypted

def decrypte(encrypted, sec_bob, pub_alice):

	pubkey_alice = PublicKey(pub1, encoder=benc)
	seckey_bob = PrivateKey(sec1, encoder=benc)
	
	box = Box(seckey_bob, pubkey_alice)
	decrypted = box2.decrypt(encrypted)

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
		printt ("The message is authentic.")
		return 1
		
	except ValueError:
		printt ("The message is not authentic.")
		return 0

def crypto_cont(file, sec_alice = sec_alice, pub_bob = pub_bob, alice_sec_sign = alice_sec_sign, aes_key_size = 32):
	
	with open(file, 'rb') as f:
		data = f.read()
	#crypto_dic['PubKey'] = pub_alice
	#key = hashlib.sha256("another awesome password".encode()).digest()
	

	key = get_random_bytes(aes_key_size)
	


	cipher = AES.new(key, AES.MODE_EAX)

	nonce = cipher.nonce
	printt('nonce', benc.encode(nonce))
	ciphertext, tag = cipher.encrypt_and_digest(data)
	
	signature = sign_it(data, alice_sec_sign)
	
	crypto_dic = {}	
	crypto_dic['Key'] = encrypte(key, sec_alice, pub_bob)
	crypto_dic['Nonce'] = nonce	
	crypto_dic['Ciphertext'] = ciphertext
	crypto_dic['Tag'] = tag
	crypto_dic['Signature'] = signature
	
	printt('key', benc.encode(key), len(key))
	printt('key', benc.encode(crypto_dic['Key']), len(crypto_dic['Key']))
	printt('ciphertext', benc.encode(ciphertext))
	printt('tag', benc.encode(tag))
	
	filehash =  api.add_pyobj(crypto_dic)
	return api.add_pyobj({'Filehash':filehash, 'Name': encrypte(file.encode(), sec_alice, pub_bob)})


api = ipfsapi.connect("127.0.0.1", 5001)	
	
file_list = ['img1.jpg','img2.webp','text.txt']	

ipfs_files = [crypto_cont(files) for files in file_list]	
	
printt(ipfs_files)


bob_address = 'e6jB08WPeBjoPS4Lb4CFRVW/TAWSrGq7MD5OG8NVA794z4GwhlXz7vov1i2w6GLWYkY2vjhCgtux5vUuE+sKC97yMd9X9xhf5V8='

point_dic = {}
point_dic['Public_encryption'] = b'0a3c097a82338f0ce7361998b81890a48077cb259030ad418ebc3763f818b35c'
point_dic['Public_signing'] = '''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJFvRYvu2eE+2J/Dpicu2nU6uvo3w
SVxtyTn69dn076Vk81mTYNkNyXciMJ5jeaGmewlDwLWaqVACW/JtVwJ4ow==
-----END PUBLIC KEY-----'''
id_name = 'message_id_' + SHA256.new(get_random_bytes(256)).hexdigest()
#printt('id_name', id_name.hexdigest())
id_dic = {}
id_dic['Address'] = bob_address
id_dic['Files'] = ipfs_files
point_dic['Message'] = {}
point_dic['Message'][id_name] = id_dic
point_dic['Points'] = [] #list with other nodes ipns

printt(point_dic)
ipfs_point =  api.add_pyobj(point_dic)
ipns_point = api.name_publish('/ipfs/' + ipfs_point)
printt(ipns_point)


#for files in file_list:
#		ipfs_files.append(crypto_cont(files),)

#with open('crypto.p', 'wb') as f:
#    pickle.dump(crypto_dic, f, pickle.HIGHEST_PROTOCOL)
