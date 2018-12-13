from Crypto.Hash import SHA256
import sys
from time import sleep
import subprocess
import platform
import json

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
		#print(counter)
	return result


def printed(text, time =0.02):
	'''
	Make a neet typing effect
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