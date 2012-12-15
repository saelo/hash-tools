#!/usr/bin/env python
#
# hashgen.py - generate a hash from a salt and password
#	       using the algorithm implemented in cracker.py
#

import cracker

passwd = raw_input("password: ")
salt = raw_input("salt: ")

print(cracker.gethash(salt, passwd))
