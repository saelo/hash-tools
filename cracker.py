#!/usr/bin/env python
#
# simple hash cracker using multiprocessing
# 

from hashlib import sha1
from multiprocessing import Pool, Array

#
# config
#
WORDLIST = ""
HASHFILE = ""	# must be in format hash:salt

#
# global vars
#
words = None

'''
 hash function
 override as needed
'''
def gethash(salt, passwd):
	return sha1(salt + sha1(salt + sha1(passwd).hexdigest()).hexdigest()).hexdigest()


'''
 try to crack given tuple of hash and salt
'''
def crack(hashv, salt):
	global words
	word = ""
	for char in words:
		if char == "\n":
			if hashv == gethash(salt, word.strip()).lower():
				print("[!] found %s for %s" % (word.strip(), hashv))
				return (word.strip(), hashv)
			word = ""
			
		word += char

'''
 thread entry point
 args:
 [0] : hash
 [1] : salt
'''
def entry(args):
	hashv = args[0]
	salt = args[1]

	return crack(hashv, salt)




'''
 main - reads input files and manages worker threads
'''
def main():
	#
	# open files
	#
	print("[*] parsing wordlist...")
	global WORDLIST, HASHFILE, words, result
	wordlist = open(WORDLIST, 'r')
	words = Array('c', wordlist.read(), lock=False)
	wordlist.close()
	print("[*] reading hashes...")
	hashes = open(HASHFILE, 'r').read().split("\n")
	hashlist = []

	#
	# crack
	#
	print("[*] beginning cracking")
	pool = Pool(processes=8)

	for hash in hashes:
		data = hash.split(":")
		if len(data) > 1:
			hashv = data[0].strip()
			salt = data[1].strip()
			hashlist.append((hashv, salt))


	pool.map(entry, hashlist)

	print("[*] shutting down")


if __name__ == "__main__":
	main()
