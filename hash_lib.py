import hashlib

# Calculate MD5 hash of data
def md5(data) :
	return hashlib.md5(data).hexdigest().upper()
	
# Calculate SHA-1 hash of data
def sha_1(data) :
	return hashlib.sha1(data).hexdigest().upper()
	
# Calculate SHA-256 hash of data
def sha_256(data) :
	return hashlib.sha256(data).hexdigest().upper()
	
# Calculate SHA-384 hash of data
def sha_384(data) :
	return hashlib.sha384(data).hexdigest().upper()

# Get Hash of data, digest size based
def get_hash(data, hash_size) :
	if hash_size == 0x10 : return md5(data)
	elif hash_size == 0x14 : return sha_1(data)
	elif hash_size == 0x20 : return sha_256(data)
	elif hash_size == 0x30 : return sha_384(data)
	else : return sha_384(data)
	
