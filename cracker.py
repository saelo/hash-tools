#!/usr/bin/env python
#
# simple hash cracker using multiprocessing
# 

from hashlib import sha1
from multiprocessing import Pool, Array, Value

#
# config
#
WORDLIST = "./cracklist.txt"
HASHFILE = "./hashes.txt"	# must be in format hash:salt

#
# global vars
#
words = None	# shared memory segment containing the wordlist
curr  = None	# shared variable containing the current total count of processed words and hashes
total = None	# shared variable containing the total count of words times hashes


'''
 hash function
 override as needed, currently sha1(salt + sha1(salt + sha1(password))) (as used in e.g. wcf)
'''
def gethash(salt, passwd):
	return sha1(salt + sha1(salt + sha1(passwd).hexdigest()).hexdigest()).hexdigest()


'''
 try to crack given tuple of hash and salt
'''
def crack(hashv, salt):
	global words, curr, total
	count = 0
	word = ""
	for char in words:
		if char == "\n":
			count += 1
			if count % 100000 == 0:
				curr.value += 100000
				print("[%] %f" % (curr.value / total.value))
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
	# process files
	#
	print("[*] parsing wordlist...")
	global WORDLIST, HASHFILE, words, result, curr, total
	wordlist = open(WORDLIST, 'r')
	wordsstr = wordlist.read()
	# load wordlist in shared memory segment
	words = Array('c', wordsstr, lock=False)

	print("[*] reading hashes...")
	hashes = open(HASHFILE, 'r').read().split("\n")
	hashlist = []
	for hash in hashes:
		data = hash.split(":")
		if len(data) > 1:
			hashv = data[0].strip()
			salt = data[1].strip()
			hashlist.append((hashv, salt))

	total = Value('i', len(wordsstr.split("\n")))
	curr = Value('d', 0.0)

	wordlist.close()

	#
	# crack
	#
	print("[*] beginning cracking")
	pool = Pool(processes=8)
	pool.map(entry, hashlist)

	print("[*] shutting down")


if __name__ == "__main__":
	main()
