from nacl.encoding import Base64Encoder as benc64
from nacl.encoding import HexEncoder as benc
from nacl.public import PrivateKey, PublicKey, Box
from Crypto.Random import get_random_bytes
import pickle

key_alice = PrivateKey.generate()
pub_alice = benc.encode(key_alice.public_key.__bytes__())
sec_alice = benc.encode(key_alice.__bytes__())

key_bob = PrivateKey.generate()
pub_bob = benc.encode(key_bob.public_key.__bytes__())
sec_bob = benc.encode(key_bob.__bytes__())

print('pub_alice',pub_alice)
print('pub_bob',pub_bob,'\n')

def make_alice_address(pub_bob = pub_bob, sec_alice = sec_alice):
	'''
	Make an address for someone and give they your public key/address if you know they public address (pub_bob) 
	Resulting address looks like 6acda026<...>ed6039001155_@_Wjc21HaPyxG/9xGzcAxLoWQD<...>YTRi87mLautJnZ5UX1qjlrjg+j/OJkg=
	The frst part before '_@_' is functionaly a public key for a single-use key pair. You need it to decode  due to peculiarity of curve25519.
	The second is just encoded nonce with your public key and public key of addressee.
	'''
	nonce = get_random_bytes(16)
	seckey_alice = PrivateKey.generate()
	pub_alice = benc.encode(seckey_alice.public_key.__bytes__())
	pubkey_alice = PublicKey(pub_alice, encoder=benc)
	pubkey_bob = PublicKey(pub_bob, encoder=benc)
	
	box = Box(seckey_alice, pubkey_bob)
	data = [pub_bob, pub_alice]	
	message = benc64.encode(nonce).decode() + '@' + benc64.encode(pickle.dumps(data)).decode() 
		
	print('message',message,'\n')
	encrypted = pub_alice.decode('utf-8') + '_@_' + benc64.encode(box.encrypt(message.encode())).decode('utf-8')
	return {'Address':encrypted,'Length':len(encrypted)}


def test_address(address, pub_bob = pub_bob, sec_bob = sec_bob):
	'''
	Test if this address is yours. You need both your private and public keys (sec_bob and pub_bob)
	'''
	addr_split = address.split('_@_')
	pub_alice = addr_split[0]
	pubkey_alice = PublicKey(pub_alice, encoder=benc)
	seckey_bob = PrivateKey(sec_bob, encoder=benc)
	box = Box(seckey_bob, pubkey_alice)
	#pickle.loads(data)
	addr = addr_split[1]
	
	message = box.decrypt(benc64.decode(addr))
	dev_mess = message.decode().split('@')
	key_list = pickle.loads(benc64.decode(dev_mess[1]))
	print('dev_mess',key_list,'\n')
	if key_list[0].decode() in pub_bob.decode():
		print('Yes, it\'s my address!')
		return key_list
	else:
		print('No, it\'s not my address!')
		#print(key_list[0].decode())
		#print(pub_bob.decode())
		return 0

		

test = make_alice_address()
print('Address', test,'\n')
print(test_address(test['Address']),'\n')
