#!/usr/bin/env python

import hashlib
from multiprocessing import Pool

#
# config
#
WORDLIST = ""
HASHFILE = ""	# must be in format hash:salt

#
# global vars
#
words = []
hashes = []

#
# helper functions
#
def genHash(salt, passwd):
	return mkhash(salt + mkhash(salt + mkhash(passwd)))

def mkhash(value):
	return hashlib.sha1(value).hexdigest()

def crack(hstuple):
	global words, results
	hashv = hstuple[0] 
	salt = hstuple[1]
	for word in words:
		if hashv == genHash(salt, word.strip()).lower():
			print("Found %s for %s" % (word.strip(), hashv))
			break



def main():
	#
	# open files
	#
	global WORDLIST, HASHFILE, words, hashes, result
	wordlist = open(WORDLIST, 'r')
	words = wordlist.read().split('\n')
	wordlist.close()
	hashes = open(HASHFILE, 'r').read().split("\n")

	#
	# crack
	#
	hstuplelist = []
	for hash in hashes:
		data = hash.split(":")
		if len(data) > 1:
			hashv = data[0].strip()
			salt = data[1].strip()
			hstuplelist.append((hashv, salt))

	pool = Pool(processes=8, maxtasksperchild=1)
	pool.map(crack, hstuplelist)


if __name__ == "__main__":
	main()
