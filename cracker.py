#!/usr/bin/env python
#
# simple hash cracker using multiprocessing
# 

from hashlib import sha1
from multiprocessing import Pool, Array, Value
from multiprocessing.sharedctypes import RawArray

#
# config
#
WORDLIST 	 = ""
HASHFILE         = ""	# must be in format hash:salt
NUM_PROCESSES    = 8
PERC_GRANULARITY = 500000	# number of processed words after which to update percentage
SHARED_MEM_SIZE  = 100000000   # number of bytes to allocate for the shared memory segment

#
# global vars
#
words     = None	# shared memory segment containing the wordlist
num_words = 0
curr_words = None	# shared variable containing current number of words
curr      = None	# shared variable containing the current total count of processed words and hashes
total     = 0		# total count of words times hashes


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
	global PERC_GRANULARITY, words, curr, total, curr_words
	count = 0
	word  = ""
	res   = None

	for char in words:
		if char == "\n":
			word = word.strip()
			count += 1
			if count % PERC_GRANULARITY == 0:
				curr.value += PERC_GRANULARITY
				print("[%%] %.02f" % ((float(curr.value) / total) * 100))
			if hashv == gethash(salt, word).lower():
				res = (word, hashv)
				print("[!]")
				print("[!] found %s for %s" % res)
				print("[!]")
				break		# done
			word = ""
		else:		
			word += char


	curr.value += curr_words.value - (count / PERC_GRANULARITY) * PERC_GRANULARITY  	# add reminder to current value
	print("[%%] %.02f" % ((float(curr.value) / total) * 100))
	return res

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
	global WORDLIST, HASHFILE, words, result, curr, total, num_words, curr_words

	#
	# process files
	#

	print("[*] reading hashes...")
	hashes = open(HASHFILE, 'r')
	hashlist = []
	for line in hashes:
		data = line.split(":")
		if len(data) > 1:
			hashv = data[0].strip()
			salt = data[1].strip()
			hashlist.append((hashv, salt))
	hashes.close() 


	print("[*] parsing wordlist...")
	words = Array('c', SHARED_MEM_SIZE, lock=False)		# allocate shared memory segment
	# get line count
	wordlist_file = open(WORDLIST, 'r')
	lines = 0
	for line in wordlist_file:
		lines += 1
	
	total = lines * len(hashlist)
	curr = Value('i', 0)
	curr_words = Value('i', 0)
	wordlist_file.seek(0)	# get back to beginning



	#
	# crack
	#
	print("[*] beginning cracking")
	pool = Pool(processes=NUM_PROCESSES)
	results = []

	current_char_count = 0
	words_raw = ""
	for line in wordlist_file:
		length = len(line)
		if length + current_char_count < SHARED_MEM_SIZE:
			words_raw += line
			current_char_count += length
		else:
			print("[*] next round")
			curr_words.value = len(words_raw.split("\n"))
			words.raw = words_raw + (SHARED_MEM_SIZE - len(words_raw)) * '0'	# clear space
			words_raw = line
			current_char_count = length

			# let workers do work!
			results.extend(pool.map(entry, hashlist))

			# remove cracked hashes
			# TODO

	print("[*] final round")
	curr_words.value = len(words_raw.split("\n"))
	words.raw = words_raw + (SHARED_MEM_SIZE - len(words_raw)) * '0'
	results.extend(pool.map(entry, hashlist))

	print("[*] done")

	for result in results:
		if result is not None:
			print("%s:%s" % (result))


if __name__ == "__main__":
	main()
