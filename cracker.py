#!/usr/bin/env python
#
# simple hash cracker using multiprocessing
# 

from hashlib import sha1
from multiprocessing import Pool, Array, Value

#
# config
#
WORDLIST         = "./cracklist.txt"
HASHFILE         = "./hashes.txt"	# must be in format hash:salt
NUM_PROCESSES    = 8
PERC_GRANULARITY = 50000	# number of processed words after which to update percentage

#
# global vars
#
words     = None	# shared memory segment containing the wordlist
num_words = 0
curr      = None	# shared variable containing the current total count of processed words and hashes
total     = None	# shared variable containing the total count of words times hashes


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
	global PERC_GRANULARITY, words, curr, total
	count = 0
	word = ""
	res = None

	for char in words:
		if char == "\n":
			word = word.strip()
			count += 1
			if count % PERC_GRANULARITY == 0:
				curr.value += PERC_GRANULARITY
				print("[%%] %.02f" % ((float(curr.value) / total.value) * 100))
			if hashv == gethash(salt, word).lower():
				res = (word, hashv)
				print("[!] found %s for %s" % res)
				break		# done
			word = ""
			
		word += char
	
	curr.value += num_words - (count / PERC_GRANULARITY) * PERC_GRANULARITY if count != num_words else count % PERC_GRANULARITY	 	# add reminder to current value
	print("[%%] %.02f" % ((float(curr.value) / total.value) * 100))
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
	#
	# process files
	#
	print("[*] parsing wordlist...")
	global WORDLIST, HASHFILE, words, result, curr, total, num_words
	wordlist_file = open(WORDLIST, 'r')
	wordlist = wordlist_file.read()
	num_words = len(wordlist.split("\n"))
	# load wordlist in shared memory segment
	words = Array('c', wordlist, lock=False)

	print("[*] reading hashes...")
	hashes = open(HASHFILE, 'r')
	hashlist = []
	for line in hashes:
		data = line.split(":")
		if len(data) > 1:
			hashv = data[0].strip()
			salt = data[1].strip()
			hashlist.append((hashv, salt))

	total = Value('i', num_words * len(hashlist))
	curr = Value('i', 0)

	# 
	# free resources
	#
	wordlist_file.close()
	del wordlist		# takes up quite a bit of memory, so lets free it
	hashes.close()

	#
	# crack
	#
	print("[*] beginning cracking")
	pool = Pool(processes=NUM_PROCESSES)
	results = pool.map(entry, hashlist)

	print("[*] done")

	for result in results:
		if result is not None:
			print("%s:%s" % (result))


if __name__ == "__main__":
	main()
