import os

from lib import *
from col_lib import *

# Set dependencies paths
db_path = os.path.join(mea_dir, 'MEA.dat')

# Check if dependencies exist
depend_db = os.path.isfile(db_path)

# Detect DB Revision
def mea_hdr_init() :
	db_rev = col_r + 'Unknown' + col_e
	
	try :
		fw_db = db_open()
		for line in fw_db :
			if 'Revision' in line :
				db_line = line.split()
				db_rev = col_y + db_line[2] + col_e
		fw_db.close()
	except :
		pass
	
	return db_rev

# Open MEA database
def db_open() :
	fw_db = open(db_path, 'r', encoding = 'utf-8')
	return fw_db

# Check DB for latest version
def check_upd(key) :
	upd_key_found = False
	vlp = [0]*4
	fw_db = db_open()
	for line in fw_db :
		if key in line :
			upd_key_found = True
			wlp = line.strip().split('__') # whole line parts
			vlp = wlp[1].strip().split('.') # version line parts
			for i in range(len(vlp)) :
				# noinspection PyTypeChecker
				vlp[i] = int(vlp[i])
			break
	fw_db.close()
	if upd_key_found : return vlp[0],vlp[1],vlp[2],vlp[3]
	else : return 0,0,0,0

# Get Database Revision
db_rev = mea_hdr_init()
