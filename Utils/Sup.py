import hashlib
import argon2
import sys
from time import sleep
import subprocess
import platform
import json

def sha000(password, circles = 1, type = 'argon2'):
	'''
	Some defence from rainbow tables. Argon2 is preferable.
	'''
	
	if type == 'argon2':
		arg = argon2.low_level.hash_secret(
				password.encode(), hashlib.sha256(password.encode()).digest(),
				time_cost=1*circles, memory_cost=502400, parallelism=1, hash_len=64, 
				type=argon2.low_level.Type.ID)
		return hashlib.sha256(arg).hexdigest()
	else:
		for times in range(circles):
			cond = 1
			counter = 0
			while cond:
				sha256 = str(hashlib.sha256(password.encode()).hexdigest())
				if sha256[0:4] == '0000':
					cond = 0
					result = sha256 
				else:
					password = sha256
					counter += 1
			password = result
		return result


def printed(text, time =0.02):
	'''
	Make a cool typing effect
	'''
	for char in text:
		sleep(time)
		sys.stdout.write(char)
		sys.stdout.flush()
	
def clear():
    subprocess.Popen( "cls" if platform.system() == "Windows" else "clear", shell=True)


def pretty_json(your_json = None, operation_type = None, path = 'config.json'):
	'''
	Make a stored version of json (config or not) human-readable.
	'''
	if operation_type == 'r':
		with open(path, 'r') as f:
			return json.loads(f.read())
	elif operation_type == 'w':
		try:
			with open(path, 'w') as f:
				f.write(str(json.dumps(your_json, indent=2, sort_keys=True)))
		except:
			print('You need a json to write one down.')
			exit()
	else:
		print('operation type:', operation_type,'\n')
		raise ValueError('Only "r" - read or "w" - write types are allowed.')


initial_structure = \
{
'Public_encryption': None, 
'Public_signing': None, 
'Messages': {1: None},
'Points': None
}
