from Crypto.Hash import SHA256
import sys
from time import sleep
import subprocess
import platform


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

def printed(text, time =0.02):
	for char in text:
		sleep(time)
		sys.stdout.write(char)
		sys.stdout.flush()
	


def clear():
    subprocess.Popen( "cls" if platform.system() == "Windows" else "clear", shell=True)

