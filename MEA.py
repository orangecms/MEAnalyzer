#!/usr/bin/env python3

"""
ME Analyzer
Intel Engine Firmware Analysis Tool
Copyright (C) 2014-2019 Plato Mavropoulos
"""

title = 'ME Analyzer v1.98.0'

import os
import re
import sys
import lzma
import zlib
import json
import struct
import ctypes
import shutil
import hashlib
import crccheck
import itertools
import traceback

import BPDT
from CPD import *
from CSE import *
from FPT import *
import FTBL
import MFS
import MME
from MN2 import *
from PMC import *
from SKU import *

from db import *

from struct_types import char, uint8_t, uint16_t, uint32_t, uint64_t

from col_lib import *
from cse_lib import *
from tbl_lib import *

# Detect OS platform
mea_os = sys.platform
if mea_os == 'win32' :
	cl_wipe = 'cls'
elif mea_os.startswith('linux') or mea_os.startswith('freebsd') or mea_os == 'darwin' :
	cl_wipe = 'clear'
else :
	print(col_r + '\nError: Unsupported platform "%s"!\n' % mea_os + col_e)
	if '-exit' not in sys.argv : input('Press enter to exit')
	colorama.deinit()
	sys.exit(1)

# Detect Python version
mea_py = sys.version_info
try :
	assert mea_py >= (3,7)
except :
	print(col_r + '\nError: Python >= 3.7 required, not %d.%d!\n' % (mea_py[0],mea_py[1]) + col_e)
	if '-exit' not in sys.argv : input('Press enter to exit')
	colorama.deinit()
	sys.exit(1)
	
# Fix Windows Unicode console redirection
if mea_os == 'win32' : sys.stdout.reconfigure(encoding='utf-8')

# Print MEA Help screen
def mea_help() :
	
	text = "\nUsage: MEA [FilePath] {Options}\n\n{Options}\n\n"
	text += "-?, -h  : Displays help & usage screen\n"
	text += "-skip   : Skips welcome & options screen\n"
	text += "-exit   : Skips Press enter to exit prompt\n"
	text += "-mass   : Scans all files of a given directory\n"
	text += "-pdb    : Writes input file DB entry to text file\n"
	text += "-dbname : Renames input file based on unique DB name\n"
	text += "-dfpt   : Shows $FPT, BPDT and/or CSE Layout Table headers\n"
	text += "-unp86  : Unpacks all CSE Converged Security Engine firmware\n"
	text += "-bug86  : Enables pausing on error during CSE unpacking\n"
	text += "-ver86  : Enables full verbose output during CSE unpacking\n"
	text += "-html   : Writes parsable HTML files during MEA operation\n"
	text += "-json   : Writes parsable JSON files during MEA operation"
	
	print(text)
	mea_exit(0)

# Process MEA Parameters
class MEA_Param :

	def __init__(self, mea_os, source) :
	
		self.all = ['-?','-h','--help','-skip','-extr','-msg','-unp86','-ver86','-bug86','-html','-json','-pdb','-dbname','-mass','-dfpt','-exit','-ftbl']
		self.win = ['-extr','-msg'] # Windows only
		
		if mea_os == 'win32' : self.val = self.all
		else : self.val = [item for item in self.all if item not in self.win]
		
		self.help_scr = False
		self.skip_intro = False
		self.extr_mea = False
		self.print_msg = False
		self.me11_mod_extr = False
		self.me11_mod_ext = False
		self.me11_mod_bug = False
		self.fpt_disp = False
		self.db_print_new = False
		self.give_db_name = False
		self.mass_scan = False
		self.skip_pause = False
		self.write_html = False
		self.write_json = False
		self.mfs_ftbl = False
		
		for i in source :
			if i == '-?' : self.help_scr = True
			if i == '-h' : self.help_scr = True
			if i == '--help' : self.help_scr = True
			if i == '-skip' : self.skip_intro = True
			if i == '-unp86' : self.me11_mod_extr = True
			if i == '-ver86' : self.me11_mod_ext = True
			if i == '-bug86' : self.me11_mod_bug = True
			if i == '-pdb' : self.db_print_new = True
			if i == '-dbname' : self.give_db_name = True
			if i == '-mass' : self.mass_scan = True
			if i == '-dfpt' : self.fpt_disp = True
			if i == '-exit' : self.skip_pause = True
			if i == '-html' : self.write_html = True
			if i == '-json' : self.write_json = True
			if i == '-ftbl' : self.mfs_ftbl = True # Hidden
			
			# Windows only options
			if mea_os == 'win32' :
				if i == '-extr' : self.extr_mea = True # Hidden
				if i == '-msg' : self.print_msg = True # Hidden
			
		if self.extr_mea or self.print_msg or self.mass_scan or self.db_print_new : self.skip_intro = True
		
# Engine Structures

# noinspection PyTypeChecker
class MCP_Header(ctypes.LittleEndianStructure) : # Multi Chip Package
	_pack_ = 1
	_fields_ = [
		("Tag",				char*4),		# 0x00
		("HeaderSize",		uint32_t),		# 0x04 dwords
		("CodeSize",		uint32_t),		# 0x08
		("Offset_Code_MN2",	uint32_t),		# 0x0C Code start from $MN2
		("Offset_Part_FPT",	uint32_t),  	# 0x10 Partition start from $FPT
		("Hash",			uint8_t*32),	# 0x14
		("Unknown34_38", 	uint32_t),  	# 0x34
		("Unknown38_3C", 	uint32_t),  	# 0x38 ME8-10
		("Unknown3C_40", 	uint32_t),  	# 0x3C ME8-10
		("Unknown40_44", 	uint32_t),  	# 0x40 ME8-10
		# 0x38 ME7, 0x44 ME8-10
	]

		
# noinspection PyTypeChecker
class UTFL_Header(ctypes.LittleEndianStructure) : # Unlock Token Flags (DebugTokenSubPartition)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('DelayedAuthMode',	uint8_t),		# 0x04
		('Reserved',		uint8_t*27),	# 0x05
		# 0x20 (End of 8KB UTOK/STKN)
	]
	
	def hdr_print(self) :
		Reserved = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Unlock Token Flags' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Delayed Authentication Mode', ['No','Yes'][self.DelayedAuthMode]])
		pt.add_row(['Reserved', '0x0' if Reserved in ('00' * 27,'FF' * 27) else Reserved])
		
		return pt

# noinspection PyTypeChecker
class RBE_PM_Metadata(ctypes.LittleEndianStructure) : # R1 - RBEP > rbe or FTPR > pm Module "Metadata"
	_pack_ = 1
	_fields_ = [
		('Unknown0',		uint32_t),		# 0x00
		('DEV_ID',			uint16_t),		# 0x04
		('VEN_ID',			uint16_t),		# 0x06 8086
		('SizeUncomp',		uint32_t),		# 0x08
		('SizeComp',		uint32_t),		# 0x0C
		('BSSSize',			uint32_t),		# 0x10
		('CodeSizeUncomp',	uint32_t),		# 0x14
		('CodeBaseAddress',	uint32_t),		# 0x18
		('MainThreadEntry',	uint32_t),		# 0x1C
		('Unknown1',		uint32_t),		# 0x20
		('Unknown2',		uint32_t),		# 0x24
		('Hash',			uint32_t*8),	# 0x28 SHA-256 LE
		# 0x48
	]
	
	def mod_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'RBE/PM Module "Metadata"' + col_e
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Device ID', '0x%X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['BSS Size', '0x%X' % self.BSSSize])
		pt.add_row(['Code Size Uncompressed', '0x%X' % self.CodeSizeUncomp])
		pt.add_row(['Code Base Address', '0x%X' % self.CodeBaseAddress])
		pt.add_row(['Main Thread Entry', '0x%X' % self.MainThreadEntry])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Unknown 2', '0x%X' % self.Unknown2])
		pt.add_row(['Hash', Hash])
		
		return pt
		
# noinspection PyTypeChecker
class RBE_PM_Metadata_R2(ctypes.LittleEndianStructure) : # R2 - RBEP > rbe or FTPR > pm Module "Metadata"
	_pack_ = 1
	_fields_ = [
		('Unknown0',		uint32_t),		# 0x00
		('DEV_ID',			uint16_t),		# 0x04
		('VEN_ID',			uint16_t),		# 0x06 8086
		('SizeUncomp',		uint32_t),		# 0x08
		('SizeComp',		uint32_t),		# 0x0C
		('BSSSize',			uint32_t),		# 0x10
		('CodeSizeUncomp',	uint32_t),		# 0x14
		('CodeBaseAddress',	uint32_t),		# 0x18
		('MainThreadEntry',	uint32_t),		# 0x1C
		('Unknown1',		uint32_t),		# 0x20
		('Unknown2',		uint32_t),		# 0x24
		('Hash',			uint32_t*12),	# 0x28 SHA-384 LE
		# 0x58
	]
	
	def mod_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'RBE/PM Module "Metadata"' + col_e
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Device ID', '0x%X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['BSS Size', '0x%X' % self.BSSSize])
		pt.add_row(['Code Size Uncompressed', '0x%X' % self.CodeSizeUncomp])
		pt.add_row(['Code Base Address', '0x%X' % self.CodeBaseAddress])
		pt.add_row(['Main Thread Entry', '0x%X' % self.MainThreadEntry])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Unknown 2', '0x%X' % self.Unknown2])
		pt.add_row(['Hash', Hash])
		
		return pt
	
# Unpack Engine CSE firmware
# noinspection PyUnusedLocal
# noinspection PyTypeChecker
def cse_unpack(variant, fpt_part_all, bpdt_part_all, file_end, fpt_start, fpt_chk_fail) :
	print()
	rbe_pm_data_d = b''
	mfs_parsed_idx = None
	fpt_hdr_0_print = None
	intel_cfg_hash_mfs = None
	cpd_match_ranges = []
	rbe_pm_met_valid = []
	rbe_pm_met_hashes = []
	len_fpt_part_all = len(fpt_part_all)
	len_bpdt_part_all = len(bpdt_part_all)
	huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, 'error') # Load Huffman Dictionaries for rbe/pm Decompression
	
	# Create main Firmware Extraction Directory
	fw_name = 'Unpacked_' + os.path.basename(file_in)
	if os.path.isdir(os.path.join(mea_dir, fw_name, '')) : shutil.rmtree(os.path.join(mea_dir, fw_name, ''))
	os.mkdir(os.path.join(mea_dir, fw_name, ''))
	
	# Show & Store CSE Layout Table info
	if cse_lt_exist :
		cse_lt_info = cse_lt.hdr_print()
		cse_lt_fname = os.path.join(mea_dir, fw_name, 'CSE LT [0x%0.6X]' % cse_lt_off)
		
		print('%s\n' % cse_lt_info)
		
		print(col_m + 'CSE Layout Table Checksum is UNKNOWN\n' + col_e) # Not used yet (?)
		
		with open(cse_lt_fname + '.bin', 'w+b') as cse_lt_file : cse_lt_file.write(reading[cse_lt_off:cse_lt_off + cse_lt_size])
		with open(cse_lt_fname + '.txt', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write(ansi_escape.sub('', '\n%s' % cse_lt_info))
		if param.write_html :
			with open(cse_lt_fname + '.html', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n<br/>\n%s' % pt_html(cse_lt_info))
		if param.write_json :
			with open(cse_lt_fname + '.json', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n%s' % pt_json(cse_lt_info))
		
		pt_dcselt.title = col_y + 'Detected %d Partition(s) at CSE LT [0x%0.6X]' % (len(cse_lt_part_all), cse_lt_off) + col_e
		print('%s\n' % pt_dcselt) # Local copy with different title for cse_unpack function
		
		cse_lt_hdr = ansi_escape.sub('', str(pt_dcselt))
		with open(cse_lt_fname + '.txt', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n%s' % cse_lt_hdr)
		if param.write_html :
			with open(cse_lt_fname + '.html', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n<br/>\n%s' % pt_html(pt_dcselt))
		if param.write_json :
			with open(cse_lt_fname + '.json', 'a', encoding = 'utf-8') as cse_lt_file : cse_lt_file.write('\n%s' % pt_json(pt_dcselt))
		
		print(col_y + '--> Stored CSE Layout Table [0x%0.6X - 0x%0.6X]\n' % (cse_lt_off, cse_lt_off + cse_lt_size) + col_e)
		
		for part in cse_lt_part_all :
			part_name = part[0]
			part_start = part[1]
			part_size = part[2]
			part_end = part[3]
			part_empty = part[4]
			
			if not part_empty : # Skip Empty Partitions
				file_name = os.path.join(fw_name, 'CSE LT ' + part_name + ' [0x%0.6X].bin' % part_start) # Start offset covers any cases with duplicate name entries (CSE_Layout_Table_17)
				mod_fname = os.path.join(mea_dir, file_name)
				
				with open(mod_fname, 'w+b') as part_file : part_file.write(reading[part_start:part_end])
			
				print(col_y + '--> Stored CSE LT Partition "%s" [0x%0.6X - 0x%0.6X]\n' % (part[0], part_start, part_end) + col_e)
	
	# Parse all Flash Partition Table ($FPT) entries
	if len_fpt_part_all :
		if reading[fpt_start:fpt_start + 0x4] == b'$FPT' :
			fpt_romb_exist = False
			fpt_hdr_1 = get_struct(reading, fpt_start, get_fpt(reading, fpt_start), file_end)
		else :
			fpt_romb_exist = True
			fpt_hdr_1 = get_struct(reading, fpt_start + 0x10, get_fpt(reading, fpt_start + 0x10), file_end)
		
		if fpt_romb_exist :
			fpt_hdr_0 = get_struct(reading, fpt_start, FPT_Pre_Header, file_end)
			fpt_hdr_0_print = fpt_hdr_0.hdr_print_cse()
			print('%s\n' % fpt_hdr_0_print)
		
		fpt_hdr_1_print = fpt_hdr_1.hdr_print_cse()
		print('%s' % fpt_hdr_1_print)
		
		if not fpt_chk_fail : print(col_g + '\nFlash Partition Table Checksum is VALID\n' + col_e)
		else :
			if param.me11_mod_bug :
				input(col_r + '\nFlash Partition Table Checksum is INVALID\n' + col_e) # Debug
			else :
				print(col_r + '\nFlash Partition Table Checksum is INVALID\n' + col_e)
		
		pt = ext_table([col_y + 'Name' + col_e, col_y + 'Start' + col_e, col_y + 'End' + col_e, col_y + 'ID' + col_e, col_y + 'Type' + col_e,
		                col_y + 'Valid' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt.title = col_y + 'Detected %d Partition(s) at $FPT [0x%0.6X]' % (len_fpt_part_all, fpt_start) + col_e
		
		for part in fpt_part_all :
			pt.add_row([part[0].decode('utf-8'), '0x%0.6X' % part[1], '0x%0.6X' % part[2], '%0.4X' % part[3], part[4], part[5], part[6]]) # Store Partition details
		
		print(pt) # Show Partition details
		
		if cse_lt_exist : fpt_fname = os.path.join(mea_dir, fw_name, 'CSE LT Data [0x%0.6X]' % fpt_start)
		else : fpt_fname = os.path.join(mea_dir, fw_name, 'FPT [0x%0.6X]' % fpt_start)
		
		# Store Flash Partition Table ($FPT) Data
		if not cse_lt_exist : # Stored at CSE LT section too
			with open(fpt_fname + '.bin', 'w+b') as fpt_file : fpt_file.write(reading[fpt_start:fpt_start + 0x1000]) # $FPT size is 4K
			
			print(col_y + '\n--> Stored Flash Partition Table [0x%0.6X - 0x%0.6X]' % (fpt_start, fpt_start + 0x1000) + col_e)
		
		# Store Flash Partition Table ($FPT) Info
		# Ignore Colorama ANSI Escape Character Sequences
		if fpt_romb_exist :
			fpt_hdr_romb = ansi_escape.sub('', str(fpt_hdr_0_print))
			with open(fpt_fname + '.txt', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n%s' % fpt_hdr_romb)
			if param.write_html :
				with open(fpt_fname + '.html', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n<br/>\n%s' % pt_html(fpt_hdr_0_print))
			if param.write_json :
				with open(fpt_fname + '.json', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n%s' % pt_json(fpt_hdr_0_print))
		
		fpt_hdr_main = ansi_escape.sub('', str(fpt_hdr_1_print))
		fpt_hdr_part = ansi_escape.sub('', str(pt))
		with open(fpt_fname + '.txt', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n%s\n%s' % (fpt_hdr_main, fpt_hdr_part))
		if param.write_html :
			with open(fpt_fname + '.html', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n<br/>\n%s\n<br/>\n%s' % (pt_html(fpt_hdr_1_print), pt_html(pt)))
		if param.write_json :
			with open(fpt_fname + '.json', 'a', encoding = 'utf-8') as fpt_file : fpt_file.write('\n%s\n%s' % (pt_json(fpt_hdr_1_print), pt_json(pt)))
		
		# Place MFS first to validate FTPR > FTPR.man > 0x00 > Intel Configuration Hash
		for i in range(len(fpt_part_all)) :
			if fpt_part_all[i][0] in [b'MFS',b'AFSP',b'MFSB'] :
				fpt_part_all.insert(0, fpt_part_all.pop(i))
				break
		
		# Charted Partitions include fpt_start, Uncharted do not (RGN only, non-SPI)
		for part in fpt_part_all :
			part_name = part[0].decode('utf-8')
			part_start = part[1]
			part_end = part[2]
			part_inid = part[3]
			part_type = part[4]
			part_empty = part[6]
			
			if not part_empty : # Skip Empty Partitions
				part_name += ' %0.4X' % part_inid
				
				mod_f_path = os.path.join(mea_dir, fw_name, part_name + ' [0x%0.6X].bin' % part_start) # Start offset covers any cases with duplicate name entries (Joule_C0-X64-Release)
				
				with open(mod_f_path, 'w+b') as part_file : part_file.write(reading[part_start:part_end])
			
				print(col_y + '\n--> Stored $FPT %s Partition "%s" [0x%0.6X - 0x%0.6X]' % (part_type, part_name, part_start, part_end) + col_e)
				
				if part[0] in [b'UTOK',b'STKN'] :
					ext_print = ext_anl(reading[part_start:part_end], '$MN2', 0x1B, file_end, [variant,major,minor,hotfix,build], part_name, [[],''], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor) # Retrieve & Store UTOK/STKN Extension Info
					
					# Print Manifest/Metadata/Key Extension Info
					for index in range(0, len(ext_print), 2) : # Only Name (index), skip Info (index + 1)
						if str(ext_print[index]).startswith(part_name) :
							if param.me11_mod_ext : print() # Print Manifest/Metadata/Key Extension Info
							for ext in ext_print[index + 1] :
								ext_str = ansi_escape.sub('', str(ext))
								with open(mod_f_path + '.txt', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % ext_str)
								if param.write_html :
									with open(mod_f_path + '.html', 'a', encoding = 'utf-8') as text_file : text_file.write('\n<br/>\n%s' % pt_html(ext))
								if param.write_json :
									with open(mod_f_path + '.json', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % pt_json(ext))
								if param.me11_mod_ext : print(ext) # Print Manifest/Metadata/Key Extension Info
							break
							
				if part[0] in [b'MFS',b'AFSP',b'MFSB'] :
					mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final = mfs_anl(os.path.join(mod_f_path[:-4], ''), part_start, part_end, variant) # Parse MFS
					for pt in mfs_info : mfs_txt(pt, os.path.join(mod_f_path[:-4], ''), mod_f_path[:-4], 'a', False) # Print MFS Structure Info
					
				# Store RBEP > rbe and FTPR > pm "Metadata" within Module for Module w/o Metadata Hash validation
				if part[0] in [b'FTPR',b'RBEP'] :
					x0,rbe_pm_mod_attr,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14 = ext_anl(reading, '$CPD', part_start, file_end, [variant,major,minor,hotfix,build], None, [mfs_parsed_idx,intel_cfg_hash_mfs], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
					
					for mod in rbe_pm_mod_attr :
						if mod[0] in ['rbe','pm'] :
							rbe_pm_data = reading[mod[3]:mod[3] + mod[4]] # Store RBEP > rbe or FTPR > pm Module Compressed Huffman data
							try : rbe_pm_data_d, huff_error = cse_huffman_decompress(rbe_pm_data, mod[4], mod[5], huff_shape, huff_sym, huff_unk, 'none') # Huffman Decompress
							except : rbe_pm_data_d = rbe_pm_data
					
					rbe_pm_met_hashes = get_rbe_pm_met(rbe_pm_data_d, rbe_pm_met_hashes)
	
	# Parse all Boot Partition Description Table (BPDT/IFWI) entries
	if len_bpdt_part_all :
		[print('\n%s' % hdr) for hdr in bpdt_hdr_all]
		
		pt = ext_table([col_y + 'Name' + col_e, col_y + 'Type' + col_e, col_y + 'Partition' + col_e, col_y + 'ID' + col_e, col_y + 'Start' + col_e, col_y + 'End' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt.title = col_y + 'Detected %d Partition(s) at %d BPDT(s)' % (len_bpdt_part_all, len(bpdt_hdr_all)) + col_e
		
		for part in bpdt_part_all :
			pt.add_row([part[0], '%0.2d' % part[3], part[5], '%0.4X' % part[6], '0x%0.6X' % part[1], '0x%0.6X' % part[2], part[4]]) # Store Entry details
		
		print('\n%s' % pt) # Show Entry details
		
		if cse_lt_exist : bpdt_fname = os.path.join(mea_dir, fw_name, 'CSE LT Boot x [%d]' % len(bpdt_hdr_all))
		else : bpdt_fname = os.path.join(mea_dir, fw_name, 'BPDT [%d]' % len(bpdt_hdr_all))
		
		# Store Boot Partition Description Table (BPDT/IFWI) Info in TXT
		with open(bpdt_fname + '.txt', 'a', encoding = 'utf-8') as bpdt_file :
			for hdr in bpdt_hdr_all : bpdt_file.write('\n%s' % ansi_escape.sub('', str(hdr)))
			bpdt_file.write('\n%s' % ansi_escape.sub('', str(pt)))
			
		# Store Boot Partition Description Table (BPDT/IFWI) Info in HTML
		if param.write_html :
			with open(bpdt_fname + '.html', 'a', encoding = 'utf-8') as bpdt_file :
				for hdr in bpdt_hdr_all : bpdt_file.write('\n<br/>\n%s' % pt_html(hdr))
				bpdt_file.write('\n<br/>\n%s' % pt_html(pt))
				
		# Store Boot Partition Description Table (BPDT/IFWI) Info in JSON
		if param.write_json :
			with open(bpdt_fname + '.json', 'a', encoding = 'utf-8') as bpdt_file :
				for hdr in bpdt_hdr_all : bpdt_file.write('\n%s' % pt_json(hdr))
				bpdt_file.write('\n%s' % pt_json(pt))
		
		# Store Boot Partition Descriptor Table (BPDT/IFWI) Data
		if not cse_lt_exist : # Stored at CSE LT section too
			with open(bpdt_fname + '.bin', 'w+b') as bpdt_file :
				for bpdt in bpdt_data_all : bpdt_file.write(bpdt)
				
			print(col_y + '\n--> Stored Boot Partition Descriptor Table(s) [%d]' % len(bpdt_hdr_all) + col_e)
		
		# Place MFS first to validate FTPR > FTPR.man > 0x00 > Intel Configuration Hash
		for i in range(len(bpdt_part_all)) :
			if bpdt_part_all[i][0] in ['MFS','AFSP','MFSB'] :
				bpdt_part_all.insert(0, bpdt_part_all.pop(i))
				break
		
		for part in bpdt_part_all :
			part_name = part[0]
			part_start = part[1]
			part_end = part[2]
			part_empty = part[4]
			part_order = part[5]
			part_inid = part[6]
			
			if not part_empty : # Skip Empty Partitions
				part_name += ' %0.4X' % part_inid
				
				mod_f_path = os.path.join(mea_dir, fw_name, part_name + ' [0x%0.6X].bin' % part_start) # Start offset covers any cases with duplicate name entries ("Unknown" etc)
				
				with open(mod_f_path, 'w+b') as part_file : part_file.write(reading[part_start:part_end])
				
				print(col_y + '\n--> Stored BPDT %s Partition "%s" [0x%0.6X - 0x%0.6X]' % (part_order, part_name, part_start, part_end) + col_e)
				
				if part[0] in ['UTOK'] :
					ext_print = ext_anl(reading[part_start:part_end], '$MN2', 0x1B, file_end, [variant,major,minor,hotfix,build], part_name, [[],''], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor) # Retrieve & Store UTOK/STKN Extension Info
					
					# Print Manifest/Metadata/Key Extension Info
					for index in range(0, len(ext_print), 2) : # Only Name (index), skip Info (index + 1)
						if str(ext_print[index]).startswith(part_name) :
							if param.me11_mod_ext : print() # Print Manifest/Metadata/Key Extension Info
							for ext in ext_print[index + 1] :
								ext_str = ansi_escape.sub('', str(ext))
								with open(mod_f_path + '.txt', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % ext_str)
								if param.write_html :
									with open(mod_f_path + '.html', 'a', encoding = 'utf-8') as text_file : text_file.write('\n<br/>\n%s' % pt_html(ext))
								if param.write_json :
									with open(mod_f_path + '.json', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % pt_json(ext))
								if param.me11_mod_ext : print(ext) # Print Manifest/Metadata/Key Extension Info
							break
							
				if part[0] in ['MFS','AFSP','MFSB'] :
					mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final = mfs_anl(os.path.join(mod_f_path[:-4], ''), part_start, part_end, variant) # Parse MFS
					for pt in mfs_info : mfs_txt(pt, os.path.join(mod_f_path[:-4], ''), mod_f_path[:-4], 'a', False) # Print MFS Structure Info
					
				# Store RBEP > rbe and FTPR > pm "Metadata" within Module for Module w/o Metadata Hash validation
				if part[0] in ['FTPR','RBEP'] :
					x0,rbe_pm_mod_attr,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14 = ext_anl(reading, '$CPD', part_start, file_end, [variant,major,minor,hotfix,build], None, [mfs_parsed_idx,intel_cfg_hash_mfs], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
					
					for mod in rbe_pm_mod_attr :
						if mod[0] in ['rbe','pm'] :
							rbe_pm_data = reading[mod[3]:mod[3] + mod[4]] # Store RBEP > rbe or FTPR > pm Module Compressed Huffman data
							try : rbe_pm_data_d, huff_error = cse_huffman_decompress(rbe_pm_data, mod[4], mod[5], huff_shape, huff_sym, huff_unk, 'none') # Huffman Decompress
							except : rbe_pm_data_d = rbe_pm_data
					
					rbe_pm_met_hashes = get_rbe_pm_met(rbe_pm_data_d, rbe_pm_met_hashes)
	
	# Parse all Code Partition Directory ($CPD) entries
	# Better to separate $CPD from $FPT/BPDT to avoid duplicate FTUP/NFTP ($FPT) issue
	cpd_pat = re.compile(br'\x24\x43\x50\x44.\x00\x00\x00[\x01\x02]\x01[\x10\x14]', re.DOTALL) # $CPD detection
	cpd_match_store = list(cpd_pat.finditer(reading))
	
	# Store all Code Partition Directory ranges
	if len(cpd_match_store) :
		for cpd in cpd_match_store : cpd_match_ranges.append(cpd)
	
	# Parse all Code Partition Directory entries
	for cpdrange in cpd_match_ranges :
		(start_cpd_emod, end_cpd_emod) = cpdrange.span()
		
		cpd_offset_e,cpd_mod_attr_e,cpd_ext_attr_e,x3,ext12_info,ext_print,x6,x7,ext_phval,ext_dnx_val,x10,x11,x12,ext_iunit_val,x14 \
		= ext_anl(reading, '$CPD', start_cpd_emod, file_end, [variant, major, minor, hotfix, build], None, [mfs_parsed_idx,intel_cfg_hash_mfs], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
		
		rbe_pm_met_valid = mod_anl(cpd_offset_e, cpd_mod_attr_e, cpd_ext_attr_e, fw_name, ext_print, ext_phval, ext_dnx_val, ext_iunit_val, rbe_pm_met_hashes, rbe_pm_met_valid, ext12_info)
		
	# Store all RBEP > rbe and FTPR > pm "Metadata" leftover Hashes for Huffman symbol reversing
	# The leftover Hashes for Huffman symbol reversing should be n+1 if NFTP > pavp is encrypted
	rbe_pm_met_leftovers = [l_hash for l_hash in rbe_pm_met_hashes if l_hash not in rbe_pm_met_valid] # Debug/Research
	#for l_hash in rbe_pm_met_leftovers : print(l_hash)

##### SPLIT ###
	
	
# Get RBEP > rbe and/or FTPR > pm Module "Metadata"
def get_rbe_pm_met(rbe_pm_data_d, rbe_pm_met_hashes) :
	rbe_pm_patt_256 = re.compile(br'\x86\x80.{70}\x86\x80.{70}\x86\x80', re.DOTALL).search(rbe_pm_data_d) # Find SHA-256 "Metadata" pattern
	rbe_pm_patt_384 = re.compile(br'\x86\x80.{86}\x86\x80.{86}\x86\x80', re.DOTALL).search(rbe_pm_data_d) # Find SHA-384 "Metadata" pattern
	
	if rbe_pm_patt_256 :
		rbe_pm_patt_start = rbe_pm_patt_256.start()
		rbe_pm_struct_name = RBE_PM_Metadata
		rbe_pm_struct_size = ctypes.sizeof(RBE_PM_Metadata)
	elif rbe_pm_patt_384 :
		rbe_pm_patt_start = rbe_pm_patt_384.start()
		rbe_pm_struct_name = RBE_PM_Metadata_R2
		rbe_pm_struct_size = ctypes.sizeof(RBE_PM_Metadata_R2)
	else :
		return rbe_pm_met_hashes
	
	rbe_pm_met_start = rbe_pm_patt_start - 0x6 # "Metadata" entry starts 0x6 before VEN_ID 8086
	rbe_pm_met_end = rbe_pm_met_start # Initialize "Metadata" entries end
	while rbe_pm_data_d[rbe_pm_met_end + 0x6:rbe_pm_met_end + 0x8] == b'\x86\x80' : rbe_pm_met_end += rbe_pm_struct_size # Find end of "Metadata" entries
	rbe_pm_met_data = bytes(rbe_pm_data_d[rbe_pm_met_start:rbe_pm_met_end]) # Store "Metadata" entries
	rbe_pm_met_count = divmod(len(rbe_pm_met_data), rbe_pm_struct_size)[0] # Count "Metadata" entries
	
	for i in range(rbe_pm_met_count) :
		rbe_pm_met = get_struct(rbe_pm_met_data, i * rbe_pm_struct_size, rbe_pm_struct_name, file_end) # Parse "Metadata" entries
		rbe_pm_met_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(rbe_pm_met.Hash)) # Get "Metadata" entry Hash
		rbe_pm_met_hashes.append(rbe_pm_met_hash) # Store each "Metadata" entry Hash for Modules w/o Metadata Hash validation
			
	return rbe_pm_met_hashes
	
# Print MEA Header
def mea_hdr(db_rev) :
	hdr_pt = ext_table([], False, 1)
	hdr_pt.add_row([col_y + '        %s' % title + col_e + ' %s        ' % db_rev])
	print(hdr_pt)

# https://stackoverflow.com/a/781074
def show_exception_and_exit(exc_type, exc_value, tb) :
	if exc_type is KeyboardInterrupt :
		print('\n')
	else :
		print(col_r + '\nError: ME Analyzer crashed, please report the following:\n')
		traceback.print_exception(exc_type, exc_value, tb)
		print(col_e)
	if not param.skip_pause : input('Press enter to exit')
	colorama.deinit() # Stop Colorama
	sys.exit(1)

# Execute final actions
def mea_exit(code=0) :
	colorama.deinit() # Stop Colorama
	if param.extr_mea or param.print_msg : sys.exit(code)
	if not param.skip_pause : input("\nPress enter to exit")
	sys.exit(code)

# Validate CPU Microcode Checksum
def mc_chk32(data) :
	chk32 = 0
	
	for idx in range(0, len(data), 4) : # Move 4 bytes at a time
		chkbt = int.from_bytes(data[idx:idx + 4], 'little') # Convert to int, MSB at the end (LE)
		chk32 = chk32 + chkbt
	
	return -chk32 & 0xFFFFFFFF # Return 0
	
def adler32(data) :
	return zlib.adler32(data) & 0xFFFFFFFF
	
# Copy input file if there are worthy Notes, Warnings or Errors
# Must be called at the end of analysis to gather any generated messages
def copy_on_msg() :
	copy = False
	
	# Detect if any copy-worthy generated message exists
	for message in (err_stor + warn_stor + note_stor) :
		if message[1] : copy = True
	
	#if err_stor or warn_stor or note_stor : copy = True # Copy on any message (Debug/Research)
	
	# At least one message needs a file copy
	if copy :
		file_name = os.path.basename(file_in)
		check_dir = os.path.join(mea_dir, '__CHECK__', '')
		check_name = os.path.join(check_dir, file_name)
		
		if not os.path.isdir(check_dir) : os.mkdir(check_dir)
		
		# Check if same file already exists
		if os.path.isfile(check_name) :
			with open(check_name, 'br') as file :
				if adler32(file.read()) == adler32(reading) : return
			
			check_name += '_%d' % cur_count
		
		shutil.copyfile(file_in, check_name)


# Detect Intel Flash Descriptor
def spi_fd_init() :
	# Search for Flash Descriptor pattern (PCH/ICH)
	fd_match = list(re.compile(br'\x5A\xA5\xF0\x0F.{172}\xFF{16}', re.DOTALL).finditer(reading)) # Z¥π. + [0xAC] + 0xFF * 16 detection
	fd_count = len(fd_match)
	
	# Detected Flash Descriptor, use first but notify if more exist
	if fd_match :
		# Platform Controller Hub (PCH)
		if (fd_match[0].start() == 0x10 or reading[fd_match[0].start() - 0x4:fd_match[0].start()] == b'\xFF' * 4) \
		and reading[fd_match[0].start() + 0x4] in [3,2] and reading[fd_match[0].start() + 0x6] == 4 :
			start_substruct = 0x10
			end_substruct = 0xBC # 0xBC for [0xAC] + 0xFF * 16 sanity check
		# I/O Controller Hub (ICH)
		else :
			start_substruct = 0x0
			end_substruct = 0xBC - 0x10 # 0xBC for [0xAC] + 0xFF * 16 sanity check, 0x10 extra before ICH FD Regions
		
		# Do not notify for OEM Backup Flash Descriptors within the chosen/first Flash Descriptor
		for match in fd_match[1:] :
			if fd_match[0].start() < match.start() <= fd_match[0].start() + 0x1000 : fd_count -= 1
		
		return True, fd_match[0].start() - start_substruct, fd_match[0].end() - end_substruct, fd_count
	
	else :
		return False, 0, 0, 0

# Analyze Intel Flash Descriptor (FD)
def spi_fd(action,start_fd_match,end_fd_match) :
	fd_reg_exist = [] # BIOS/IAFW + Engine
	
	if action == 'region' :
		bios_fd_base = int.from_bytes(reading[end_fd_match + 0x30:end_fd_match + 0x32], 'little')
		bios_fd_limit = int.from_bytes(reading[end_fd_match + 0x32:end_fd_match + 0x34], 'little')
		me_fd_base = int.from_bytes(reading[end_fd_match + 0x34:end_fd_match + 0x36], 'little')
		me_fd_limit = int.from_bytes(reading[end_fd_match + 0x36:end_fd_match + 0x38], 'little')
		devexp_fd_base = int.from_bytes(reading[end_fd_match + 0x40:end_fd_match + 0x42], 'little')
		devexp_fd_limit = int.from_bytes(reading[end_fd_match + 0x42:end_fd_match + 0x44], 'little')
		
		if bios_fd_limit != 0 :
			bios_fd_start = bios_fd_base * 0x1000 + start_fd_match # fd_match required in case FD is not at the start of image
			bios_fd_size = (bios_fd_limit + 1 - bios_fd_base) * 0x1000 # The +1 is required to include last Region byte
			fd_reg_exist.extend((True,bios_fd_start,bios_fd_size)) # BIOS/IAFW Region exists
		else :
			fd_reg_exist.extend((False,0,0)) # BIOS/IAFW Region missing
			
		if me_fd_limit != 0 :
			me_fd_start = me_fd_base * 0x1000 + start_fd_match
			me_fd_size = (me_fd_limit + 1 - me_fd_base) * 0x1000
			fd_reg_exist.extend((True,me_fd_start,me_fd_size)) # Engine Region exists
		else :
			fd_reg_exist.extend((False,0,0)) # Engine Region missing
			
		if devexp_fd_limit != 0 :
			devexp_fd_start = devexp_fd_base * 0x1000 + start_fd_match
			devexp_fd_size = (devexp_fd_limit + 1 - devexp_fd_base) * 0x1000
			fd_reg_exist.extend((True,devexp_fd_start,devexp_fd_size)) # Device Expansion Region exists
		else :
			fd_reg_exist.extend((False,0,0)) # Device Expansion Region missing
			
		return fd_reg_exist
	
# Format firmware version
def fw_ver(major,minor,hotfix,build) :
	if variant in ['SPS','CSSPS'] :
		version = '%s.%s.%s.%s' % ('{0:02d}'.format(major), '{0:02d}'.format(minor), '{0:02d}'.format(hotfix), '{0:03d}'.format(build)) # xx.xx.xx.xxx
	elif variant.startswith(('PMCAPL','PMCBXT','PMCGLK')) :
		version = '%s.%s.%s.%s' % (major, minor, hotfix, build)
	elif variant.startswith('PMCCNP') and (major < 130 or major == 3232) :
		version = '%s.%s.%s.%s' % ('{0:02d}'.format(major), minor, hotfix, build)
	elif variant.startswith('PMC') :
		version = '%s.%s.%s.%s' % (major, minor, '{0:02d}'.format(hotfix), build)
	else :
		version = '%s.%s.%s.%s' % (major, minor, hotfix, build)
	
	return version

# Detect Fujitsu Compressed ME Region
def fuj_umem_ver(me_fd_start) :
	version = 'NaN'
	
	if reading[me_fd_start:me_fd_start + 0x4] == b'\x55\x4D\xC9\x4D' : # UMEM
		major = int.from_bytes(reading[me_fd_start + 0xB:me_fd_start + 0xD], 'little')
		minor = int.from_bytes(reading[me_fd_start + 0xD:me_fd_start + 0xF], 'little')
		hotfix = int.from_bytes(reading[me_fd_start + 0xF:me_fd_start + 0x11], 'little')
		build = int.from_bytes(reading[me_fd_start + 0x11:me_fd_start + 0x13], 'little')
		version = '%s.%s.%s.%s' % (major, minor, hotfix, build)
	
	return version
	
# Check if Fixed Offset Variables (FOVD/NVKR) partition is dirty
def fovd_clean(fovdtype) :
	fovd_start = -1
	fovd_empty = 'N/A'
	
	for part in fpt_part_all :
		if (fovdtype,part[0]) in [('new',b'FOVD'),('old',b'NVKR')] :
			fovd_start = part[1]
			fovd_empty = part[6]
	
	if (fovd_start,fovd_empty) != (-1,'N/A') :
		if fovdtype == 'new' :
			return fovd_empty # Empty = Clean
		elif fovdtype == 'old' :
			if fovd_empty :
				return True
			else :
				nvkr_size = int.from_bytes(reading[fovd_start + 0x19:fovd_start + 0x1C], 'little')
				nvkr_data = reading[fovd_start + 0x1C:fovd_start + 0x1C + nvkr_size]
				
				if nvkr_data == b'\xFF' * nvkr_size : return True
				else : return False
	else :
		return True

# Create Firmware Type Database Entry
def fw_types(fw_type) :
	type_db = 'NaN'
	
	if variant in ['SPS','CSSPS'] and fw_type in ['Region','Region, Stock','Region, Extracted'] : # SPS --> Region (EXTR at DB)
		fw_type = 'Region'
		type_db = 'EXTR'
	elif fw_type == 'Region, Extracted' : type_db = 'EXTR'
	elif fw_type == 'Region, Stock' or fw_type == 'Region' : type_db = 'RGN'
	elif fw_type == 'Update' : type_db = 'UPD'
	elif fw_type == 'Operational' : type_db = 'OPR'
	elif fw_type == 'Recovery' : type_db = 'REC'
	elif fw_type == 'Independent' and variant.startswith('PMC') : type_db = 'PMC'
	elif fw_type == 'Unknown' : type_db = 'UNK'
	
	return fw_type, type_db
	
# Validate Manifest RSA Signature
# TODO: Add RSA SSA-PSS Signature validation
def rsa_sig_val(man_hdr_struct, input_stream, check_start) :
	man_tag = man_hdr_struct.Tag.decode('utf-8')
	man_size = man_hdr_struct.Size * 4
	man_hdr_size = man_hdr_struct.HeaderLength * 4
	man_key_size = man_hdr_struct.PublicKeySize * 4
	man_pexp = man_hdr_struct.RSAExponent
	man_pkey = int.from_bytes(man_hdr_struct.RSAPublicKey, 'little')
	man_sign = int.from_bytes(man_hdr_struct.RSASignature, 'little')
	
	# return [RSA Sig isValid, RSA Sig Decr Hash, RSA Sig Data Hash, RSA Validation isCrashed, $MN2 Offset, $MN2 Struct Object]
	
	try :
		dec_sign = '%X' % pow(man_sign, man_pexp, man_pkey) # Decrypted Signature
		
		if (man_tag,man_key_size) == ('$MAN',0x100) : # SHA-1
			rsa_hash = hashlib.sha1()
			dec_hash = dec_sign[-40:] # 160-bit
		elif (man_tag,man_key_size) == ('$MN2',0x100) : # SHA-256
			rsa_hash = hashlib.sha256()
			dec_hash = dec_sign[-64:] # 256-bit
		elif (man_tag,man_key_size) == ('$MN2',0x180) : # SHA-384
			rsa_hash = hashlib.sha384()
			dec_hash = dec_sign[-96:] # 384-bit
		else :
			rsa_hash = hashlib.sha384()
			dec_hash = dec_sign[-96:] # 384-bit
	
		rsa_hash.update(input_stream[check_start:check_start + 0x80]) # First 0x80 before RSA area
		rsa_hash.update(input_stream[check_start + man_hdr_size:check_start + man_size]) # Manifest protected data
		rsa_hash = rsa_hash.hexdigest().upper() # Data SHA-1, SHA-256 or SHA-384 Hash
		
		return [dec_hash == rsa_hash, dec_hash, rsa_hash, False, check_start, man_hdr_struct] # RSA block validation check OK
	except :
		if (man_pexp,man_pkey,man_sign) == (0,0,0) :
			return [True, 0, 0, False, check_start, man_hdr_struct] # "Valid"/Empty RSA block, no validation crash
		else :
			return [False, 0, 0, True, check_start, man_hdr_struct] # RSA block validation check crashed, debugging required
	
# Search DB for manual CSE SKU values
def get_cse_db(variant) :
	db_sku_chk = 'NaN'
	sku = 'NaN'
	sku_stp = 'NaN'
	sku_pdm = 'UPDM'
	
	fw_db = db_open()
	for line in fw_db :
		if rsa_sig_hash in line :
			line_parts = line.strip().split('_')
			if variant == 'CSME' :
				db_sku_chk = line_parts[2] # Store the SKU from DB for latter use
				sku = sku_init + " " + line_parts[2] # Cell 2 is SKU
				if line_parts[3] not in ('X','XX') : sku_stp = line_parts[3] # Cell 3 is PCH/SoC Stepping
				if 'YPDM' in line_parts[4] or 'NPDM' in line_parts[4] or 'UPDM' in line_parts[4] : sku_pdm = line_parts[4] # Cell 4 is PDM
			elif variant == 'CSTXE' :
				if line_parts[1] not in ('X','XX') : sku_stp = line_parts[1] # Cell 1 is PCH/SoC Stepping
			elif variant == 'CSSPS' :
				if line_parts[-1] == 'EXTR' and line_parts[3] not in ('X','XX') : sku_stp = line_parts[3] # Cell 3 is PCH/SoC Stepping
			break # Break loop at 1st rsa_sig_hash match
	fw_db.close()

	return db_sku_chk, sku, sku_stp, sku_pdm

# Get CSME 12+ Final SKU, SKU Platform, SKU Stepping
def get_csme_sku(sku_init, fw_0C_sku0, fw_0C_list, sku, sku_stp, db_sku_chk, pos_sku_tbl, pos_sku_ext, pch_init_final) :
	# Detect SKU Platform, prefer DB over Extension
	if sku != 'NaN' :
		sku_result = db_sku_chk # SKU Platform retrieved from DB (Override)
	elif pos_sku_tbl != 'Unknown' :
		sku_result = pos_sku_tbl # SKU Platform retrieved from MFS (Best)
	else :
		sku_result = pos_sku_ext # SKU Platform "retrieved" from Extension 12 (Worst, always 0/H, STOP regressing Intel!)
		
		# Since Extension 12 is completely unreliable (thx Intel), try to manually guess based on SKU Capabilities
		if sku_result == 'H' :
			sku_result = fw_0C_list[int('{0:032b}'.format(fw_0C_sku0)[22:24], 2)]
			warn_stor.append([col_m + 'Warning: The detected SKU Platform may be unreliable!' + col_e, True])
	
	sku = sku_init + ' ' + sku_result
	
	# Set PCH/SoC Stepping, if not found at DB
	if sku_stp == 'NaN' and pch_init_final : sku_stp = pch_init_final[-1][1]
	
	return sku, sku_result, sku_stp

# Get CSE DB SKU and check for Latest status
def sku_db_upd_cse(sku_type, sku_plat, sku_stp, upd_found, stp_only = False) :
	if sku_stp == 'NaN' : sku_db = '%s%sX' % (sku_type if stp_only else sku_type + '_', sku_plat if stp_only else sku_plat + '_')
	else : sku_db = '%s%s' % (sku_type if stp_only else sku_type + '_', sku_plat if stp_only else sku_plat + '_') + sku_stp
	
	db_maj,db_min,db_hot,db_bld = check_upd(('Latest_%s_%s%s_%s%s' % (variant, major, minor, sku_type, sku_plat)))
	if hotfix < db_hot or (hotfix == db_hot and build < db_bld) : upd_found = True
	
	return sku_db, upd_found

# Detect Variant/Family
def get_variant() :
	variant = 'Unknown'
	variant_p = 'Unknown'
	var_rsa_db = True
	
	# Detect Variant by unique DB RSA Public Key
	fw_db = db_open()
	for line in fw_db :
		if rsa_key_hash in line :
			line_parts = line.strip().split('_')
			variant = line_parts[1] # Store the Variant
			break # Break loop at 1st match
	fw_db.close()
	
	# Variant DB RSA Public Key not found, manual known correction
	if variant == 'TBD4' and major in (300,3232) : variant = 'PMCCNP'
	elif variant == 'TBD4' and major == 140 : variant = 'PMCCMP'
	elif variant == 'TBD3' and major in (12,13,14) : variant = 'CSME'
	elif variant == 'TBD3' and major in (400,130) : variant = 'PMCICP'
	elif variant == 'TBD3' and major in (3,4) : variant = 'CSTXE'
	elif variant == 'TBD1' and major == 11 : variant = 'CSME'
	elif variant == 'TBD1' and 6 <= major <= 10 : variant = 'ME'
	elif variant == 'TBD1' and 0 <= major <= 2 : variant = 'TXE'
	
	# Manual known variant correction failed, targeted detection
	if variant in ['Unknown','TBD1','TBD2','TBD3'] :
		if variant == 'Unknown' : var_rsa_db = False # TBDx are multi-platform RSA Public Keys
		
		# Get CSE $CPD Module Names only for targeted variant detection via special ext_anl _Stage1 mode
		cpd_mod_names,fptemp_info = ext_anl(reading, '$MN2_Stage1', start_man_match, file_end, ['CSME', major, minor, hotfix, build], None, [[],''], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
		
		# Remember to also adjust pmc_anl for PMC Variants
		
		if cpd_mod_names :
			for mod in cpd_mod_names :
				if mod == 'fwupdate' :
					variant = 'CSME'
					break
				elif mod in ['bup_rcv', 'sku_mgr'] :
					variant = 'CSSPS'
					break
				elif mod == 'PMCC000' and (major in (300,3232) or major < 130) : # 0 CNP
					variant = 'PMCCNP'
					break
				elif mod == 'PMCC000' and major in (400,130) : # 0 ICP
					variant = 'PMCICP'
					break
				elif mod == 'PMCC000' and major == 140 : # 0 CMP
					variant = 'PMCCMP'
					break
				elif mod == 'PMCC002' : # 2 APL A
					variant = 'PMCAPLA'
					break
				elif mod == 'PMCC003' : # 3 APL B
					variant = 'PMCAPLB'
					break
				elif mod == 'PMCC004' : # 4 GLK A
					variant = 'PMCGLKA'
					break
				elif mod == 'PMCC005' : # 5 BXT C (Joule)
					variant = 'PMCBXTC'
					break
				elif mod == 'PMCC006' : # 6 GLK B
					variant = 'PMCGLKB'
					break
				else :
					variant = 'CSTXE' # CSE fallback, no CSME/CSSPS/PMC detected
		
		elif reading[end_man_match + 0x270 + 0x80:end_man_match + 0x270 + 0x84].decode('utf-8', 'ignore') == '$MME' :
			# $MME: ME2-5/SPS1 = 0x50, ME6-10/SPS2-3 = 0x60, TXE1-2 = 0x80
			variant = 'TXE'
		
		elif re.compile(br'\x24\x53\x4B\x55\x03\x00\x00\x00\x2F\xE4\x01\x00').search(reading) or \
		re.compile(br'\x24\x53\x4B\x55\x03\x00\x00\x00\x08\x00\x00\x00').search(reading) :
			variant = 'SPS'
		
		else :
			variant = 'ME' # Default fallback, no CSE/TXE/SPS/PMC detected
	
	# Create Variant display-friendly text
	if variant == 'CSME' : variant_p = 'CSE ME'
	elif variant == 'CSTXE' : variant_p = 'CSE TXE'
	elif variant == 'CSSPS' : variant_p = 'CSE SPS'
	elif variant.startswith('PMC') : variant_p = 'PMC'
	elif variant in ['ME','TXE','SPS'] : variant_p = variant
	
	return variant, variant_p, var_rsa_db

# Scan all files of a given directory
def mass_scan(f_path) :
	mass_files = []
	for root, dirs, files in os.walk(f_path):
		for name in files :
			mass_files.append(os.path.join(root, name))
			
	input('\nFound %s file(s)\n\nPress enter to start' % len(mass_files))
	
	return mass_files

	
# Get MEA Parameters from input
param = MEA_Param(mea_os, sys.argv)

# Actions for MEA but not UEFIStrip
if not param.extr_mea and not param.print_msg :
	# Pause after any unexpected python exception
	sys.excepthook = show_exception_and_exit
	
	# Set console/shell window title
	if mea_os == 'win32' : ctypes.windll.kernel32.SetConsoleTitleW(title)
	elif mea_os.startswith('linux') or mea_os == 'darwin' : sys.stdout.write('\x1b]2;' + title + '\x07')
	
# Enumerate parameter input
arg_num = len(sys.argv)

if not param.skip_intro :
	mea_hdr(db_rev)

	print("\nWelcome to Intel Engine Firmware Analysis Tool\n")
	
	if arg_num == 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFile:       " + col_g + "%s" % os.path.basename(sys.argv[1]) + col_e)
	elif arg_num > 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFiles:       " + col_y + "Multiple" + col_e)
	else :
		print('Input a file name/path or press Enter to list options\n')
		print("\nFile:       " + col_m + "None" + col_e)

	input_var = input('\nOption(s):  ')
	
	# Anything quoted ("") is taken as one (file paths etc)
	input_var = re.split(''' (?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', input_var.strip())
	
	# Get MEA Parameters based on given Options
	param = MEA_Param(mea_os, input_var)
	
	# Non valid parameters are treated as files
	if input_var[0] != "" :
		for i in input_var:
			if i not in param.val :
				sys.argv.append(i.strip('"'))
	
	# Re-enumerate parameter input
	arg_num = len(sys.argv)
	
	os.system(cl_wipe)
	
	mea_hdr(db_rev)
	
elif not param.extr_mea and not param.print_msg :
	mea_hdr(db_rev)
	
if (arg_num < 2 and not param.help_scr and not param.mass_scan) or param.help_scr :
	mea_help()

if param.mass_scan :
	in_path = input('\nEnter the full folder path : ')
	source = mass_scan(in_path)
else :
	source = sys.argv[1:] # Skip script/executable

# Verify that DB exists
if not depend_db :
	print(col_r + '\nError: MEA.dat file is missing!' + col_e)
	mea_exit(1)
	
# Initialize file input
cur_count = 0
in_count = len(source)
for arg in source :
	if arg in param.val : in_count -= 1

for file_in in source :
	
	# Variable Initialization
	fw_type = ''
	upd_rslt = ''
	me2_type_fix = ''
	me2_type_exp = ''
	sku = 'NaN'
	sku_db = 'NaN'
	rel_db = 'NaN'
	type_db = 'NaN'
	sku_stp = 'NaN'
	txe_sub = 'NaN'
	platform = 'NaN'
	sku_init = 'NaN'
	pdm_status = 'NaN'
	txe_sub_db = 'NaN'
	fuj_version = 'NaN'
	no_man_text = 'NaN'
	variant = 'Unknown'
	variant_p = 'Unknown'
	sku_result = 'Unknown'
	pmc_date = 'Unknown'
	me7_blist_1 = 'Empty'
	me7_blist_2 = 'Empty'
	cse_in_id_str = '0000'
	pos_sku_ker = 'Invalid'
	pos_sku_ext = 'Unknown'
	pos_sku_tbl = 'Unknown'
	pmc_pch_sku = 'Unknown'
	pmc_pch_rev = 'Unknown'
	pmc_platform = 'Unknown'
	pmc_mn2_signed = 'Unknown'
	fwu_iup_result = 'Unknown'
	mfs_state = 'Unconfigured'
	cse_lt = None
	pt_dfpt = None
	fpt_hdr = None
	bpdt_hdr = None
	byp_match = None
	pmc_mn2_ver = None
	pmc_mod_attr = None
	fpt_pre_hdr = None
	mfs_parsed_idx = None
	intel_cfg_hash_mfs = None
	var_rsa_db = True
	mfs_found = False
	upd_found = False
	rgn_exist = False
	pmcp_found = False
	ifwi_exist = False
	utok_found = False
	oemp_found = False
	wcod_found = False
	fw_type_fix = False
	is_patsburg = False
	can_search_db = True
	fpt_chk_fail = False
	cse_lt_exist = False
	sps_opr_found = False
	fwu_iup_exist = False
	fpt_romb_found = False
	fitc_ver_found = False
	pmcp_fwu_found = False
	pmcp_upd_found = False
	fw_in_db_found = False
	fd_me_rgn_exist = False
	fd_bios_rgn_exist = False
	fd_devexp_rgn_exist = False
	rgn_over_extr_found = False
	mfs_info = []
	err_stor = []
	note_stor = []
	warn_stor = []
	s_bpdt_all = []
	fpt_ranges = []
	fpt_matches = []
	p_store_all = []
	fpt_part_all = []
	bpdt_matches = []
	bpdt_hdr_all = []
	bpdt_data_all = []
	bpdt_part_all = []
	pch_init_final = []
	cse_lt_part_all = []
	cse_lt_hdr_info = []
	man_match_ranges = []
	init_man_match = [0,0]
	eng_size_text = ['', False]
	msg_dict = {}
	msg_entries = {}
	ftbl_blob_dict = {}
	ftbl_entry_dict = {}
	vcn = -1
	svn = -1
	pvbit = -1
	sku_me = -1
	pmc_svn = -1
	pmc_vcn = -1
	arb_svn = -1
	pmc_pvbit = -1
	mod_size = 0
	fw_0C_lbg = 0
	sku_type = -1
	sku_size = -1
	sku_slim = 0
	fd_count = 0
	fpt_count = 0
	mod_align = 0
	cse_in_id = 0
	fpt_start = -1
	mfs_start = -1
	mfs_size = 0
	pmcp_size = 0
	oem_signed = 0
	fpt_length = -1
	fpt_version = -1
	pmc_fw_ver = -1
	pmc_arb_svn = -1
	fitc_major = -1
	fitc_minor = -1
	fitc_build = -1
	fitc_hotfix = -1
	p_end_last = 0
	mod_end_max = 0
	cse_lt_off = -1
	cse_lt_size = 0
	fpt_num_diff = 0
	mod_size_all = 0
	cpd_end_last = 0
	fpt_chk_file = 0
	fpt_chk_calc = 0
	fpt_num_file = 0
	fpt_num_calc = 0
	me_fd_start = -1
	me_fd_size = -1
	pmc_fw_rel = -1
	pmc_pch_gen = -1
	fpt_part_num = -1
	fpt_chk_byte = -1
	fpt_chk_start = -1
	p_offset_last = 0
	rec_rgn_start = 0
	sps3_chk16_file = 0
	sps3_chk16_calc = 0
	cpd_offset_last = 0
	p_end_last_cont = 0
	devexp_fd_start = -1
	uncharted_start = -1
	p_end_last_back = -1
	mod_end = 0xFFFFFFFF
	p_max_size = 0xFFFFFFFF
	eng_fw_end = 0xFFFFFFFF
	cur_count += 1
	
	if not os.path.isfile(file_in) :
		if any(p in file_in for p in param.val) : continue # Next input file
		
		print(col_r + '\nError: File %s was not found!' % file_in + col_e)
		
		if not param.mass_scan : mea_exit(1)
		else : continue
	
	with open(file_in, 'rb') as in_file : reading = in_file.read()
	file_end = len(reading)
	
	# Detect if file has Engine firmware
	man_pat = re.compile(br'\x86\x80.........\x00\x24\x4D((\x4E\x32)|(\x41\x4E))', re.DOTALL) # .$MN2 or .$MAN detection
	
	for man_range in list(man_pat.finditer(reading)) :
		(start_man_match, end_man_match) = man_range.span()
		start_man_match += 0xB # Add 8680.{9} sanity check before .$MN2 or .$MAN
		
		pr_man_0 = (reading[end_man_match + 0x374:end_man_match + 0x378]) # FTPR,OPR (CSME 15 +, CSTXE 5 +, CSSPS 6 +)
		pr_man_1 = (reading[end_man_match + 0x274:end_man_match + 0x278]) # FTPR,OPR (CSME 11 - 13, CSTXE 3 - 4, CSSPS 4 - 5.0.3)
		pr_man_2 = (reading[end_man_match + 0x264:end_man_match + 0x266]) # FT,OP (ME 6 - 10 Part 1, TXE 0 - 2 Part 1, SPS 2 - 3 Part 1)
		pr_man_3 = (reading[end_man_match + 0x266:end_man_match + 0x268]) # PR,xx (ME 6 - 10 Part 2, TXE 0 - 2 Part 2)
		pr_man_4 = (reading[end_man_match + 0x28C:end_man_match + 0x293]) # BRINGUP (ME 2 - 5)
		pr_man_5 = (reading[end_man_match + 0x2DC:end_man_match + 0x2E7]) # EpsRecovery,EpsFirmware (SPS 1)
		pr_man_6 = (reading[end_man_match + 0x270:end_man_match + 0x277]) # $MMEBUP (ME 6 BYP Part 1, SPS 2 - 3 Part 2)
		pr_man_7 = (reading[end_man_match + 0x33C:end_man_match + 0x340]) # $MMX (ME 6 BYP Part 2)
		pr_man_8 = (re.compile(br'\x24\x43\x50\x44.\x00\x00\x00[\x01\x02]\x01[\x10\x14].\x4C\x4F\x43\x4C', re.DOTALL)).search(reading[:0x10]) # $CPD LOCL detection
		pr_man_9 = (re.compile(br'\x24\x4D\x4D\x45\x57\x43\x4F\x44\x5F')).search(reading[0x290:0x299]) # $MMEWCOD_ detection
		pr_man_10 = (re.compile(br'\x24\x43\x50\x44.\x00\x00\x00[\x01\x02]\x01[\x10\x14].\x50\x4D\x43\x50', re.DOTALL)).search(reading[:0x10]) # $CPD PMCP detection
		pr_man_11 = (reading[end_man_match - 0x38:end_man_match - 0x31]) # bup_rcv (CSSPS 5.0.3 +)
		
		#break # Force MEA to accept any $MAN/$MN2 (Debug/Research)
		
		if any(p in (pr_man_0, pr_man_1, pr_man_2 + pr_man_3, pr_man_2 + pr_man_6 + pr_man_7, pr_man_4, pr_man_5, pr_man_6 + pr_man_7, pr_man_11) \
		for p in (b'FTPR', b'OPR\x00', b'BRINGUP', b'EpsRecovery', b'EpsFirmware', b'OP$MMEBUP\x00\x00\x00\x00', b'$MMEBUP$MMX', b'bup_rcv')) \
		or pr_man_8 or pr_man_9 or pr_man_10 :
			# Recovery Manifest found
			break
	else :
		# Recovery Manifest not found (for > finish)
		
		# Parse MFS File Table Blob
		if param.mfs_ftbl :
			ftbl = get_struct(reading, 0, FTBL_Header, file_end)
			
			for i in range(ftbl.TableCount) :
				tbl = get_struct(reading, i * 0x10 + 0x10, FTBL_Table, file_end)
				
				tbl_data = reading[tbl.Offset:tbl.Offset + tbl.Size]
				
				ftbl_pt = ext_table(['Path','File ID','Unknown 0','User ID','Group ID','Unknown 1','Rights','Access','Options'], True, 1)
				ftbl_pt.title = 'FTBL Table ' + '%0.2X' % tbl.Dictionary
				
				for j in range(tbl.EntryCount) :
					entry_data = tbl_data[j * 0x44:j * 0x44 + 0x44]
					
					entry = get_struct(entry_data, 0, FTBL_Entry, file_end)
					
					f1,f2,f3 = entry.get_flags()
					
					path = entry.Path.decode('utf-8')
					file_id = '0x%0.8X' % entry.FileID
					unknown_0 = '0x%0.4X' % entry.Unknown0
					group_id = '0x%0.4X' % entry.GroudID
					user_id = '0x%0.4X' % entry.UserID
					unknown_1 = '0x%0.4X' % entry.Unknown1
					rights = ''.join(map(str, entry.get_rights(f1)))
					access = '{0:023b}b'.format(f2)
					options = '{0:032b}b'.format(f3)
					
					ftbl_entry_dict['%0.8X' % entry.FileID] = path # Create File Table Entries Dictionary
			
					ftbl_pt.add_row([path,file_id,unknown_0,user_id,group_id,unknown_1,rights,access,options])
					
				ftbl_blob_dict['%0.2X' % tbl.Dictionary] = ftbl_entry_dict # Create File Table Blob Dictionary
					
				with open('FileTable_%s_%0.2X.txt' % (os.path.basename(file_in), tbl.Dictionary), 'w', encoding='utf-8') as o : o.write(str(ftbl_pt))
				if param.write_html :
					with open('FileTable_%s_%0.2X.html' % (os.path.basename(file_in), tbl.Dictionary), 'w', encoding='utf-8') as o : o.write(pt_html(ftbl_pt))
				if param.write_json :
					with open('FileTable_%s_%0.2X.json' % (os.path.basename(file_in), tbl.Dictionary), 'w', encoding='utf-8') as o : o.write(pt_json(ftbl_pt))
		
			o_dict = json.dumps(ftbl_blob_dict, indent=4, sort_keys=True)
			with open('FileTable_%s.dat' % os.path.basename(file_in), 'w') as o : o.write(o_dict)
			
			mea_exit(0)
		
		# Determine if FD exists and if Engine Region is present
		fd_exist,start_fd_match,end_fd_match,fd_count = spi_fd_init()
		if fd_exist :
			fd_bios_rgn_exist,bios_fd_start,bios_fd_size,fd_me_rgn_exist,me_fd_start,me_fd_size,fd_devexp_rgn_exist,devexp_fd_start,devexp_fd_size \
			= spi_fd('region',start_fd_match,end_fd_match)
		
		# Engine Region exists but cannot be identified
		if fd_me_rgn_exist :
			fuj_version = fuj_umem_ver(me_fd_start) # Check if ME Region is Fujitsu UMEM compressed
			
			# ME Region is Fujitsu UMEM compressed
			if fuj_version != 'NaN' :
				no_man_text = 'Found' + col_y + ' Fujitsu Compressed ' + col_e + ('Intel Engine firmware v%s' % fuj_version)
				
				if param.extr_mea : no_man_text = 'NaN %s_NaN_UMEM %s NaN NaN' % (fuj_version, fuj_version)
			
			# ME Region is X58 ROMB Test
			elif reading[me_fd_start:me_fd_start + 0x8] == b'\xD0\x3F\xDA\x00\xC8\xB9\xB2\x00' :
				no_man_text = 'Found' + col_y + ' X58 ROMB Test ' + col_e + 'Intel Engine firmware'
				
				if param.extr_mea : no_man_text = 'NaN NaN_NaN_X58 NaN NaN NaN'
			
			# ME Region is Unknown
			else :
				no_man_text = 'Found' + col_y + ' unidentifiable ' + col_e + 'Intel Engine firmware'
				
				if param.extr_mea : no_man_text = 'NaN NaN_NaN_UNK NaN NaN NaN' # For UEFI Strip (-extr)
		
		# Engine Region does not exist
		else :
			fuj_version = fuj_umem_ver(0) # Check if ME Region is Fujitsu UMEM compressed (me_fd_start is 0x0, no SPI FD)
			fw_start_match = (re.compile(br'\x24\x46\x50\x54.\x00\x00\x00', re.DOTALL)).search(reading) # $FPT detection
			
			# Image is ME Fujitsu UMEM compressed
			if fuj_version != 'NaN' :
				no_man_text = 'Found' + col_y + ' Fujitsu Compressed ' + col_e + ('Intel Engine firmware v%s' % fuj_version)
				
				if param.extr_mea : no_man_text = 'NaN %s_NaN_UMEM %s NaN NaN' % (fuj_version, fuj_version)
			
			# Image is X58 ROMB Test
			elif reading[:0x8] == b'\xD0\x3F\xDA\x00\xC8\xB9\xB2\x00' :
				no_man_text = 'Found' + col_y + ' X58 ROMB Test ' + col_e + 'Intel Engine firmware'
				
				if param.extr_mea : no_man_text = "NaN NaN_NaN_X58 NaN NaN NaN"
			
			# Image contains some Engine Flash Partition Table ($FPT)
			elif fw_start_match is not None :
				(start_fw_start_match, end_fw_start_match) = fw_start_match.span()
				fpt_hdr = get_struct(reading, start_fw_start_match, get_fpt(reading, start_fw_start_match), file_end)
				hdr_print = fpt_hdr.hdr_print_cse()
				print('\n%s' % hdr_print) # Show details
				
				if fpt_hdr.FitBuild != 0 and fpt_hdr.FitBuild != 65535 :
					fitc_ver = '%s.%s.%s.%s' % (fpt_hdr.FitMajor, fpt_hdr.FitMinor, fpt_hdr.FitHotfix, fpt_hdr.FitBuild)
					no_man_text = 'Found' + col_y + ' Unknown ' + col_e + ('Intel Engine Flash Partition Table v%s' % fitc_ver)
					
					if param.extr_mea : no_man_text = 'NaN %s_NaN_FPT %s NaN NaN' % (fitc_ver, fitc_ver) # For UEFI Strip (-extr)
				
				else :
					no_man_text = 'Found' + col_y + ' Unknown ' + col_e + 'Intel Engine Flash Partition Table'
					
					if param.extr_mea : no_man_text = 'NaN NaN_NaN_FPT NaN NaN NaN' # For UEFI Strip (-extr)
				
			# Image does not contain any kind of Intel Engine firmware
			else :
				no_man_text = 'File does not contain Intel Engine firmware'

		# Print filename when not in UEFIStrip mode
		if not param.extr_mea and not param.print_msg :
			print()
			msg_pt = ext_table([], False, 1)
			msg_pt.add_row([col_c + '%s (%d/%d)' % (os.path.basename(file_in)[:45], cur_count, in_count) + col_e])
			print(msg_pt)
		
		if param.extr_mea :
			if no_man_text != 'NaN' : print(no_man_text)
			else : pass
		elif param.print_msg :
			print('MEA: %s\n' % no_man_text) # UEFIStrip, one empty line at the beginning
		else :
			print('\n%s' % no_man_text)
			
		if not param.extr_mea : copy_on_msg() # Close input and copy it in case of messages
		
		continue # Next input file

	# Engine firmware found (for > break), Manifest analysis
	
	# Detect Intel Flash Descriptor
	fd_exist,start_fd_match,end_fd_match,fd_count = spi_fd_init()
	if fd_exist :
		fd_bios_rgn_exist,bios_fd_start,bios_fd_size,fd_me_rgn_exist,me_fd_start,me_fd_size,fd_devexp_rgn_exist,devexp_fd_start,devexp_fd_size \
		= spi_fd('region',start_fd_match,end_fd_match)
	
	# Detect all $FPT and/or BPDT starting offsets (both allowed/needed)
	if fd_me_rgn_exist :
		# $FPT detection based on FD with Engine region (limits false positives from IE or CSTXE Engine/ROMB & DevExp1/Init)
		fpt_matches = list((re.compile(br'\x24\x46\x50\x54.\x00\x00\x00', re.DOTALL)).finditer(reading[me_fd_start:me_fd_start + me_fd_size]))
	else :
		# FD with Engine region not found or multiple FD detected, scan entire file (could lead to false positives)
		fpt_matches_init = list((re.compile(br'\x24\x46\x50\x54.\x00\x00\x00', re.DOTALL)).finditer(reading))
		
		# No Variant known yet but, if possible, get CSE Stage 1 Info for false positive removal via special ext_anl _Stage1 mode
		man_mod_names,fptemp_info = ext_anl(reading, '$MN2_Stage1', start_man_match, file_end, ['CSME', 0, 0, 0, 0], None, [[],''], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
		fptemp_exists = True if man_mod_names and man_mod_names[0] == 'FTPR.man' and fptemp_info[0] else False # Detect if CSE FTPR > fptemp module exists
		
		# Adjust $FPT matches, ignore known CSE false positives
		for fpt_match in fpt_matches_init :
			if fptemp_exists and fptemp_info[2] > fpt_match.start() >= fptemp_info[1] : pass # CSE FTPR > fptemp
			else : fpt_matches.append(fpt_match)
	
	# Store Initial Manifest Offset for CSSPS EXTR RSA Signatures Hash
	init_man_match = [start_man_match,end_man_match]
	
	# Detect $FPT Firmware Starting Offset
	if len(fpt_matches) :
		rgn_exist = True # Set $FPT detection boolean
		
		for r in fpt_matches:
			fpt_ranges.append(r.span()) # Store all $FPT ranges
			fpt_count += 1 # Count $FPT ranges
		
		# Store ranges and start from 1st $FPT by default
		(start_fw_start_match, end_fw_start_match) = fpt_ranges[0]
		
		# Adjust $FPT offset if FD with Engine region exists
		if fd_me_rgn_exist :
			start_fw_start_match += me_fd_start
			end_fw_start_match += me_fd_start
		
		# Detect if $FPT is proceeded by CSE Layout Table
		cse_lt_off = start_fw_start_match - 0x1000 # CSE LT size is 0x1000
		cse_lt_test_fpt_16 = cse_lt_off + int.from_bytes(reading[cse_lt_off + 0x10:cse_lt_off + 0x14], 'little') # Is Data v1.6/v2.0 ($FPT)
		cse_lt_test_bp1_16 = cse_lt_off + int.from_bytes(reading[cse_lt_off + 0x18:cse_lt_off + 0x1C], 'little') # Is BP1 v1.6/v2.0 (BPDT)
		cse_lt_test_bp2_16 = cse_lt_off + int.from_bytes(reading[cse_lt_off + 0x20:cse_lt_off + 0x24], 'little') # Is BP2 v1.6/v2.0 (BPDT)
		cse_lt_test_fpt_17 = cse_lt_off + int.from_bytes(reading[cse_lt_off + 0x18:cse_lt_off + 0x1C], 'little') # Is Data v1.7 ($FPT)
		cse_lt_test_bp1_17 = cse_lt_off + int.from_bytes(reading[cse_lt_off + 0x20:cse_lt_off + 0x24], 'little') # Is BP1 v1.7 (BPDT)
		cse_lt_test_bp2_17 = cse_lt_off + int.from_bytes(reading[cse_lt_off + 0x28:cse_lt_off + 0x2C], 'little') # Is BP2 v1.7 (BPDT)
		
		if start_fw_start_match == cse_lt_test_fpt_16 and reading[cse_lt_test_bp1_16:cse_lt_test_bp1_16 + 0x4] in [b'\xAA\x55\x00\x00',b'\xAA\x55\xAA\x00'] \
		and reading[cse_lt_test_bp2_16:cse_lt_test_bp2_16 + 0x4] in [b'\xAA\x55\x00\x00',b'\xAA\x55\xAA\x00'] :
			cse_lt_exist = True
			cse_lt = get_struct(reading, cse_lt_off, CSE_Layout_Table_16, file_end) # IFWI 1.6 & 2.0
		elif start_fw_start_match == cse_lt_test_fpt_17 and reading[cse_lt_test_bp1_17:cse_lt_test_bp1_17 + 0x4] in [b'\xAA\x55\x00\x00',b'\xAA\x55\xAA\x00'] \
		and reading[cse_lt_test_bp2_17:cse_lt_test_bp2_17 + 0x4] in [b'\xAA\x55\x00\x00',b'\xAA\x55\xAA\x00'] :
			cse_lt_exist = True
			cse_lt = get_struct(reading, cse_lt_off, CSE_Layout_Table_17, file_end) # IFWI 1.7
			
		# Analyze CSE Layout Table
		if cse_lt_exist :
			cse_lt_size = 0x1000
			NA = [0,0xFFFFFFFF]
			
			cse_lt_hdr_info = [['Data',cse_lt.DataOffset,cse_lt.DataSize],['Boot 1',cse_lt.BP1Offset,cse_lt.BP1Size],['Boot 2',cse_lt.BP2Offset,cse_lt.BP2Size],
								['Boot 3',cse_lt.BP3Offset,cse_lt.BP3Size],['Boot 4',cse_lt.BP4Offset,cse_lt.BP4Size],['Boot 5',cse_lt.BP5Offset,cse_lt.BP5Size]]	
			
			# Store CSE LT partition details
			for entry in cse_lt_hdr_info :
				cse_lt_entry_name = entry[0]
				cse_lt_entry_off = entry[1]
				cse_lt_entry_size = entry[2]
				cse_lt_entry_spi = cse_lt_off + cse_lt_entry_off
				cse_lt_entry_end = cse_lt_entry_spi + cse_lt_entry_size
				cse_lt_entry_data = reading[cse_lt_entry_spi:cse_lt_entry_end]
				cse_lt_entry_empty = True if (cse_lt_entry_off in NA or cse_lt_entry_size in NA or cse_lt_entry_data in [b'\x00' * cse_lt_entry_size,b'\xFF' * cse_lt_entry_size]) else False
				cse_lt_part_all.append([cse_lt_entry_name,cse_lt_entry_spi,cse_lt_entry_size,cse_lt_entry_end,cse_lt_entry_empty])

			pt_dcselt = ext_table([col_y + 'Name' + col_e, col_y + 'Start' + col_e, col_y + 'Size' + col_e, col_y + 'End' + col_e, col_y + 'Empty' + col_e], True, 1)
			pt_dcselt.title = col_y + 'CSE Partition Layout Table' + col_e		
			
			# Detect CSE LT partition overlaps
			for part in cse_lt_part_all :
				pt_dcselt.add_row([part[0],'0x%0.6X' % part[1],'0x%0.6X' % part[2],'0x%0.6X' % part[3],part[4]]) # For -dfpt
				for all_part in cse_lt_part_all :
					# Partition A starts before B but ends after B start
					# Ignore partitions which have empty offset or size
					if not part[4] and not all_part[4] and not any(s in [0,0xFFFFFFFF] for s in (part[1],part[2],all_part[1],all_part[2])) and (part[1] < all_part[1] < part[2]) :
						err_stor.append([col_r + 'Error: CSE LT partition %s (0x%0.6X - 0x%0.6X) overlaps with %s (0x%0.6X - 0x%0.6X)' % \
										(part[0],part[1],part[2],all_part[0],all_part[1],all_part[2]) + col_e, True])
						
			# Show CSE LT partition info on demand (-dfpt)
			if param.fpt_disp : print('%s\n' % pt_dcselt)
		
		# Analyze $FPT header
		pt_dfpt = ext_table([col_y + 'Name' + col_e, col_y + 'Owner' + col_e, col_y + 'Start' + col_e, col_y + 'Size' + col_e, col_y + 'End' + col_e,
				  col_y + 'Type' + col_e, col_y + 'ID' + col_e, col_y + 'Valid' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt_dfpt.title = col_y + 'Flash Partition Table' + col_e
		
		fpt_hdr = get_struct(reading, start_fw_start_match, get_fpt(reading, start_fw_start_match), file_end)
		
		fpt_part_num = fpt_hdr.NumPartitions
		fpt_version = fpt_hdr.HeaderVersion
		fpt_length = fpt_hdr.HeaderLength
		
		fpt_pre_hdr = None
		fpt_chk_start = 0x0
		fpt_start = start_fw_start_match - 0x10
		fpt_chk_byte = reading[start_fw_start_match + 0xB]
		
		if (cse_lt_exist or (fd_devexp_rgn_exist and reading[devexp_fd_start:devexp_fd_start + 0x4] == b'$FPT')) \
		and fpt_version in [0x20,0x21] and fpt_length == 0x20 :
			fpt_start = start_fw_start_match
		elif fpt_version in [0x20,0x21] and fpt_length == 0x30 :
			fpt_pre_hdr = get_struct(reading, fpt_start, FPT_Pre_Header, file_end)
		elif fpt_version in [0x20,0x21] and fpt_length == 0x20 :
			fpt_chk_start = 0x10 # ROMB instructions excluded
			fpt_pre_hdr = get_struct(reading, fpt_start, FPT_Pre_Header, file_end)
		elif fpt_version == 0x10 and fpt_length == 0x20 :
			fpt_start = start_fw_start_match
		
		fpt_step = start_fw_start_match + 0x20 # 0x20 $FPT entry size
		
		for i in range(0, fpt_part_num):
			cse_in_id = 0
			cse_in_id_str = '0000'
			
			fpt_entry = get_struct(reading, fpt_step, FPT_Entry, file_end)
			
			p_type,p_dram,p_reserved0,p_bwl0,p_bwl1,p_reserved1,p_valid = fpt_entry.get_flags()
			
			p_name = fpt_entry.Name
			p_owner = fpt_entry.Owner
			p_offset = fpt_entry.Offset
			p_offset_spi = fpt_start + fpt_entry.Offset
			p_size = fpt_entry.Size
			p_valid_print = False if p_valid == 0xFF else True
			p_type_values = {0: 'Code', 1: 'Data', 2: 'NVRAM', 3: 'Generic', 4: 'EFFS', 5: 'ROM'} # Only 0 & 1 for CSE
			p_type_print = p_type_values[p_type] if p_type in p_type_values else 'Unknown'
			
			if p_offset in (0xFFFFFFFF, 0) or p_size == 0 or p_size != 0xFFFFFFFF and reading[p_offset_spi:p_offset_spi + p_size] in (b'', p_size * b'\xFF') :
				p_empty = True
			else :
				p_empty = False
			
			if not p_empty and p_offset_spi < file_end :
				# Get CSE Partition Instance ID
				cse_in_id,x1,x2 = cse_part_inid(reading, p_offset_spi, ext_dict, file_end, variant)
				cse_in_id_str = '%0.4X' % cse_in_id
				
				# Get ME LOCL/WCOD Partition Instance ID
				mn2_hdr = get_struct(reading, p_offset_spi, get_manifest(reading, p_offset_spi, variant), file_end)
				if mn2_hdr.Tag in [b'$MN2',b'$MAN'] : # Sanity check
					mn2_len = mn2_hdr.HeaderLength * 4
					mod_name = reading[p_offset_spi + mn2_len:p_offset_spi + mn2_len + 0x8].strip(b'\x00').decode('utf-8')
					if mod_name in ['LOCL','WCOD'] :
						cse_in_id = reading[p_offset_spi + mn2_len + 0x15:p_offset_spi + mn2_len + 0x15 + 0xB].strip(b'\x00').decode('utf-8')
						cse_in_id_str = cse_in_id
			
			fpt_part_all.append([p_name, p_offset_spi, p_offset_spi + p_size, cse_in_id, p_type_print, p_valid_print, p_empty])
			
			if p_name in [b'\xFF\xFF\xFF\xFF', b''] :
				p_name = '' # If appears, wrong NumPartitions
				fpt_num_diff -= 1 # Check for less $FPT Entries
			elif p_name == b'\xE0\x15' : p_name = '' # ME8 (E0150020)
			else : p_name = p_name.decode('utf-8', 'ignore')
			
			# Store $FPT Partition info for -dfpt
			if param.fpt_disp :
				if p_owner in [b'\xFF\xFF\xFF\xFF', b''] : p_owner = '' # Missing
				else : p_owner = p_owner.decode('utf-8', 'ignore')
				
				if p_offset in [0xFFFFFFFF, 0] : p_offset_print = ''
				else : p_offset_print = '0x%0.6X' % p_offset_spi
				
				if p_size in [0xFFFFFFFF, 0] : p_size_print = ''
				else : p_size_print = '0x%0.6X' % p_size
				
				if p_offset_print == '' or p_size_print == '' : p_end_print = ''
				else : p_end_print = '0x%0.6X' % (p_offset_spi + p_size)
				
				pt_dfpt.add_row([p_name,p_owner,p_offset_print,p_size_print,p_end_print,p_type_print,cse_in_id_str,p_valid_print,p_empty])
			
			p_store_all.append([p_name, p_offset_spi, p_size]) # For $FPT Recovery/Operational adjustment
			
			# Detect if firmware has ROM-Bypass (ROMB) partition 
			if p_name == 'ROMB' and not p_empty : fpt_romb_found = True
			
			# Detect if firmware has (CS)SPS Operational (OPRx/COD1) partition
			if p_name.startswith(('OPR','COD1')) and not p_empty : sps_opr_found = True
			
      ###### PMC2
			# Detect if firmware has Power Management Controller (PMCP) partition
			if p_name == 'PMCP' and not p_empty :
				pmcp_found = True
				pmcp_fwu_found = True # CSME12+ FWUpdate tool requires PMC
				pmcp_size = p_size
				
				x0,pmc_mod_attr,x2,pmc_vcn,x4,x5,x6,x7,x8,x9,x10,x11,pmc_mn2_ver,x13,pmc_arb_svn = ext_anl(reading, '$CPD', p_offset_spi, file_end, ['CSME', -1, -1, -1, -1], None, [[],''], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
				
			# Detect if firmware has CSE File System Partition
			if p_name in ('MFS','AFSP') and not p_empty :
				mfs_found = True
				mfs_start = p_offset_spi
				mfs_size = p_size
			
			# Detect if firmware has OEM Unlock Token (UTOK/STKN)
			if p_name in ('UTOK','STKN') and p_offset_spi < file_end and reading[p_offset_spi:p_offset_spi + 0x10] != b'\xFF' * 0x10 : utok_found = True
			
			# Detect if CSE firmware has OEM Key Manager Partition (OEMP)
			if p_name == 'OEMP' and p_offset_spi < file_end and reading[p_offset_spi:p_offset_spi + 0x10] != b'\xFF' * 0x10 : oemp_found = True
			
			if 0 < p_offset_spi < p_max_size and 0 < p_size < p_max_size : eng_fw_end = p_offset_spi + p_size
			else : eng_fw_end = p_max_size
			
			# Store last partition (max offset)
			if p_offset_last < p_offset_spi < p_max_size:
				p_offset_last = p_offset_spi
				p_size_last = p_size
				p_end_last = eng_fw_end
			
			fpt_step += 0x20 # Next $FPT entry
		
		# Adjust Manifest to Recovery (ME/TXE) or Operational (SPS) partition based on $FPT
		if fpt_count <= 2 :
			# This does not work with Intel Engine Capsule images because they have multiple $FPT and Engine CODE
			# regions. It cannot be removed because MEA needs to jump to COD1/OPR1 for (CS)SPS parsing. The Intel
			# POR is to have at most two $FPT at normal CS(SPS) images, Main ($FPT) and Backup (FPTB), so MEA skips
			# this adjustment for images with more than two $FPT hits. The drawback is that MEA detects FTPR instead
			# of COD1/OPR1 at these Intel Capsule images. A proper detection/extractor could be added in the future.
			for p_rec_fix in p_store_all :
				# For ME 2-5 & SPS 1, pick CODE if RCVY or COD1 are not present
				# For SPS, pick Operational (COD1/OPR1) instead of Recovery (CODE/FTPR)
				if p_rec_fix[0] in ['FTPR', 'RCVY', 'OPR1', 'COD1'] or (p_rec_fix[0] == 'CODE' and not any(p in ('RCVY', 'COD1') for p in p_store_all)) :
					# Only if partition exists at file (counter-example: sole $FPT etc)
					# noinspection PyTypeChecker
					if p_rec_fix[1] + p_rec_fix[2] <= file_end :
						rec_man_match = man_pat.search(reading[p_rec_fix[1]:p_rec_fix[1] + p_rec_fix[2]])
						
						if rec_man_match :
							(start_man_match, end_man_match) = rec_man_match.span()
							start_man_match += p_rec_fix[1] + 0xB # Add Recovery/Operational offset and 8680.{9} sanity check before .$MN2 or .$MAN
							end_man_match += p_rec_fix[1]
		else :
			# More than two $FPT detected, probably Intel Engine Capsule image
			mfs_found = False
		
		# Check for extra $FPT Entries, wrong NumPartitions (0x2+ for SPS3 Checksum)
		while reading[fpt_step + 0x2:fpt_step + 0xC] not in [b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'] :
			fpt_num_diff += 1
			fpt_step += 0x20
	
		# Check $FPT NumPartitions validity
		if fpt_num_diff != 0 :
			fpt_num_file = '0x%0.2X' % fpt_hdr.NumPartitions
			fpt_num_calc = '0x%0.2X' % (fpt_hdr.NumPartitions + fpt_num_diff)
			warn_stor.append([col_m + 'Warning: Wrong $FPT entry count %s, expected %s!' % (fpt_num_file,fpt_num_calc) + col_e, True])
	
	# Scan for IFWI/BPDT Ranges
	if cse_lt_exist :
		# Search Boot Partitions only when CSE LT exists (fast & robust)
		for part in cse_lt_part_all :
			if part[0].startswith('Boot') and not part[4] : # Non-Empty CSE LT Boot Partition (skip Data/MFS)
				bpdt_match = (re.compile(br'\xAA\x55[\x00\xAA]\x00.\x00[\x01-\x03]\x00', re.DOTALL)).search(reading[part[1]:part[3]]) # BPDT detection
				bpdt_matches.append((bpdt_match.start() + part[1], bpdt_match.end() + part[1])) # Store BPDT range, relative to 0x0
	else :
		# Search entire image when no CSE LT exists (slower & false positive prone)
		bpdt_match = list((re.compile(br'\xAA\x55[\x00\xAA]\x00.\x00[\x01-\x03]\x00', re.DOTALL)).finditer(reading)) # BPDT detection
		for match in bpdt_match :
			if mfs_found and mfs_start <= match.start() < mfs_start + mfs_size : continue # Skip BPDT within MFS (i.e. 008 > fwupdate> fwubpdtinfo)
			else : bpdt_matches.append(match.span()) # Store all BPDT ranges, already relative to 0x0
	
	# Parse IFWI/BPDT Ranges
	for ifwi_bpdt in range(len(bpdt_matches)):
		
		ifwi_exist = True # Set IFWI/BPDT detection boolean
		
		(start_fw_start_match, end_fw_start_match) = bpdt_matches[ifwi_bpdt] # Get BPDT range via bpdt_matches index
		
		if start_fw_start_match in s_bpdt_all : continue # Skip already parsed S-BPDT (Type 5)
		
		bpdt_hdr = get_struct(reading, start_fw_start_match, get_bpdt(reading, start_fw_start_match), file_end)
		
		# Store Primary BPDT info to show at CSE unpacking
		if param.me11_mod_extr :
			bpdt_hdr_all.append(bpdt_hdr.hdr_print())
			bpdt_data_all.append(reading[start_fw_start_match:start_fw_start_match + 0x200]) # Min size 0x200 (no size at Header, min is enough though)
		
		# Analyze BPDT header
		bpdt_step = start_fw_start_match + 0x18 # 0x18 BPDT Header size
		bpdt_part_num = bpdt_hdr.DescCount
		
		pt_dbpdt = ext_table([col_y + 'Name' + col_e, col_y + 'Type' + col_e, col_y + 'Partition' + col_e, col_y + 'Start' + col_e,
				  col_y + 'Size' + col_e, col_y + 'End' + col_e, col_y + 'ID' + col_e, col_y + 'Empty' + col_e], True, 1)
		pt_dbpdt.title = col_y + 'Boot Partition Descriptor Table' + col_e
		
		for i in range(0, bpdt_part_num):
			cse_in_id = 0
			
			bpdt_entry = get_struct(reading, bpdt_step, BPDT_Entry, file_end)
			
			p_type = bpdt_entry.Type
			p_offset = bpdt_entry.Offset
			p_offset_spi = start_fw_start_match + p_offset
			p_size = bpdt_entry.Size
			
			if p_offset in (0xFFFFFFFF, 0) or p_size in (0xFFFFFFFF, 0) or reading[p_offset_spi:p_offset_spi + p_size] in (b'', p_size * b'\xFF') : p_empty = True
			else : p_empty = False
			
			if p_type in bpdt_dict : p_name = bpdt_dict[p_type]
			else : p_name = 'Unknown'
			
			if not p_empty and p_offset_spi < file_end :
				# Get CSE Partition Instance ID
				cse_in_id,x1,x2 = cse_part_inid(reading, p_offset_spi, ext_dict, file_end, variant)
			
			# Store BPDT Partition info for -dfpt
			if param.fpt_disp :
				if p_offset in [0xFFFFFFFF, 0] : p_offset_print = ''
				else : p_offset_print = '0x%0.6X' % p_offset_spi
				
				if p_size in [0xFFFFFFFF, 0] : p_size_print = ''
				else : p_size_print = '0x%0.6X' % p_size
				
				if p_offset_print == '' or p_size_print == '' : p_end_print = ''
				else : p_end_print = '0x%0.6X' % (p_offset_spi + p_size)
				
				pt_dbpdt.add_row([p_name,'%0.2d' % p_type,'Primary',p_offset_print,p_size_print,p_end_print,'%0.4X' % cse_in_id,p_empty])
			####### PMC1
			# Detect if IFWI Primary includes PMC firmware (PMCP)
			if p_name == 'PMCP' and not p_empty :
				pmcp_found = True
				pmcp_fwu_found = False # CSME12+ FWUpdate tool requires PMC
				pmcp_size = p_size
				
				x0,pmc_mod_attr,x2,pmc_vcn,x4,x5,x6,x7,x8,x9,x10,x11,pmc_mn2_ver,x13,pmc_arb_svn = ext_anl(reading, '$CPD', p_offset_spi, file_end, ['CSME', -1, -1, -1, -1], None, [[],''], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
				
			# Detect if IFWI Primary has CSE File System Partition (Not POR, just in case)
			if p_name in ('MFS','AFSP') and not p_empty :
				mfs_found = True
				mfs_start = p_offset_spi
				mfs_size = p_size
			
			if p_type == 5 and not p_empty and p_offset_spi < file_end and reading[p_offset_spi:p_offset_spi + 0x2] == b'\xAA\x55' : # Secondary BPDT (S-BPDT)
				s_bpdt_hdr = get_struct(reading, p_offset_spi, get_bpdt(reading, p_offset_spi), file_end)
				
				# Store Secondary BPDT info to show at CSE unpacking
				if param.me11_mod_extr :
					bpdt_hdr_all.append(s_bpdt_hdr.hdr_print())
					bpdt_data_all.append(reading[start_fw_start_match:start_fw_start_match + 0x200]) # Min size 0x200 (no size at Header, min is enough though)
				
				s_bpdt_all.append(p_offset_spi) # Store parsed S-BPDT offset to skip at IFWI/BPDT Starting Offsets
				
				s_bpdt_step = p_offset_spi + 0x18 # 0x18 S-BPDT Header size
				s_bpdt_part_num = s_bpdt_hdr.DescCount
				
				for j in range(0, s_bpdt_part_num):
					cse_in_id = 0
					
					s_bpdt_entry = get_struct(reading, s_bpdt_step, BPDT_Entry, file_end)
					
					s_p_type = s_bpdt_entry.Type
					s_p_offset = s_bpdt_entry.Offset
					s_p_offset_spi = start_fw_start_match + s_p_offset
					s_p_size = s_bpdt_entry.Size
					
					if s_p_offset in (0xFFFFFFFF, 0) or s_p_size in (0xFFFFFFFF, 0) or reading[s_p_offset_spi:s_p_offset_spi + s_p_size] in (b'', s_p_size * b'\xFF') :
						s_p_empty = True
					else :
						s_p_empty = False
					
					if s_p_type in bpdt_dict : s_p_name = bpdt_dict[s_p_type]
					else : s_p_name = 'Unknown'
					
					if not s_p_empty and s_p_offset_spi < file_end :
						cse_in_id,x1,x2 = cse_part_inid(reading, s_p_offset_spi, ext_dict, file_end, variant)
					
					# Store BPDT Partition info for -dfpt
					if param.fpt_disp :
						if s_p_offset in [0xFFFFFFFF, 0] : s_p_offset_print = ''
						else : s_p_offset_print = '0x%0.6X' % s_p_offset_spi
						
						if s_p_size in [0xFFFFFFFF, 0] : s_p_size_print = ''
						else : s_p_size_print = '0x%0.6X' % s_p_size
						
						if s_p_offset_print == '' or s_p_size_print == '' : s_p_end_print = ''
						else : s_p_end_print = '0x%0.6X' % (s_p_offset_spi + s_p_size)
						
						pt_dbpdt.add_row([s_p_name,'%0.2d' % s_p_type,'Secondary',s_p_offset_print,s_p_size_print,s_p_end_print,'%0.4X' % cse_in_id,s_p_empty])
						
          ###### PMC3
					# Detect if IFWI Secondary includes PMC firmware (PMCP)
					if s_p_name == 'PMCP' and not s_p_empty :
						pmcp_found = True
						pmcp_fwu_found = False # CSME12+ FWUpdate tool requires PMC
						pmcp_size = s_p_size
						
						x0,pmc_mod_attr,x2,pmc_vcn,x4,x5,x6,x7,x8,x9,x10,x11,pmc_mn2_ver,x13,pmc_arb_svn = ext_anl(reading, '$CPD', s_p_offset_spi, file_end, ['CSME', -1, -1, -1, -1], None, [[],''], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
					
					# Detect if IFWI Secondary has CSE File System Partition (Not POR, just in case)
					if s_p_name in ('MFS','AFSP') and not s_p_empty :
						mfs_found = True
						mfs_start = s_p_offset_spi
						mfs_size = s_p_size
					
					# Store all Secondary BPDT entries for extraction
					bpdt_part_all.append([s_p_name,s_p_offset_spi,s_p_offset_spi + s_p_size,s_p_type,s_p_empty,'Secondary',cse_in_id])
						
					s_bpdt_step += 0xC # 0xC BPDT Entry size
			
			# Store all Primary BPDT entries for extraction
			bpdt_part_all.append([p_name,p_offset_spi,p_offset_spi + p_size,p_type,p_empty,'Primary',cse_in_id])
			
			bpdt_step += 0xC # 0xC BPDT Entry size
		
		# Show BPDT Partition info on demand (-dfpt)
		if param.fpt_disp : print('%s\n' % pt_dbpdt)
		
	# Perform actions on total stored BPDT entries
	for part in bpdt_part_all :
		# Detect if IFWI includes CSSPS Operational (OPRx) partition
		if part[3] == 2 and not part[4] and reading[part[1] + 0xC:part[1] + 0xF] == b'OPR' : sps_opr_found = True
		
		# Adjust Manifest to Recovery (CSME/CSTXE) or Operational (CSSPS) partition based on BPDT
		if part[3] == 2 and not part[4] and part[1] < file_end : # Type = CSE_BUP, non-Empty, Start < EOF
			# Only if partition exists at file (counter-example: sole IFWI etc)
			# noinspection PyTypeChecker
			if part[1] + (part[2] - part[1]) <= file_end :
				rec_man_match = man_pat.search(reading[part[1]:part[1] + (part[2] - part[1])])
				
				if rec_man_match :
					(start_man_match, end_man_match) = rec_man_match.span()
					start_man_match += part[1] + 0xB # Add CSE_BUP offset and 8680.{9} sanity check before .$MN2
					end_man_match += part[1]
	
		# Detect if CSE firmware has OEM Unlock Token (UTOK/STKN)
		if part[0] in ('UTOK','STKN') and reading[part[1]:part[1] + 0x10] != b'\xFF' * 0x10 : utok_found = True
		if part[0] == 'OEMP' and reading[part[1]:part[1] + 0x10] != b'\xFF' * 0x10 : oemp_found = True
	
		# Detect BPDT partition overlaps
		for all_part in bpdt_part_all :
			# Partition A starts before B but ends after B start
			# Ignore partitions which have empty offset or size
			# Ignore DLMP partition which overlaps by Intel design
			if not part[4] and not all_part[4] and not any(s in [0,0xFFFFFFFF] for s in (part[1],part[2],all_part[1],all_part[2])) \
			and part[0] not in ['S-BPDT','DLMP'] and all_part[0] not in ['S-BPDT','DLMP'] and (part[1] < all_part[1] < part[2]) :
				err_stor.append([col_r + 'Error: BPDT partition %s (0x%0.6X - 0x%0.6X) overlaps with %s (0x%0.6X - 0x%0.6X)' % \
								(part[0],part[1],part[2],all_part[0],all_part[1],all_part[2]) + col_e, True])
	
		# Ignore Flash Descriptor OEM backup at BPDT > OBBP > NvCommon (HP)
		if part[0] == 'OBBP' and not part[4] and re.compile(br'\x5A\xA5\xF0\x0F.{172}\xFF{16}', re.DOTALL).search(reading[part[1]:part[2]]) :
			fd_count -= 1
	
	# Scan $MAN/$MN2 Manifest, for basic info only
	mn2_ftpr_hdr = get_struct(reading, start_man_match - 0x1B, get_manifest(reading, start_man_match - 0x1B, variant), file_end)
	mn2_ftpr_ver = mn2_ftpr_hdr.HeaderVersion
	
	major = mn2_ftpr_hdr.Major
	minor = mn2_ftpr_hdr.Minor
	hotfix = mn2_ftpr_hdr.Hotfix
	build = mn2_ftpr_hdr.Build
	svn = mn2_ftpr_hdr.SVN
	if mn2_ftpr_ver == 0x10000 : vcn = mn2_ftpr_hdr.VCN
	day = mn2_ftpr_hdr.Day
	month = mn2_ftpr_hdr.Month
	year = mn2_ftpr_hdr.Year
	date = '%0.4X-%0.2X-%0.2X' % (year, month, day)
	
	# Get & Hash the Manifest RSA Public Key and Signature
	rsa_block_off = end_man_match + 0x60 # RSA Block Offset
	rsa_key_len = mn2_ftpr_hdr.PublicKeySize * 4 # RSA Key/Signature Length
	rsa_exp_len = mn2_ftpr_hdr.ExponentSize * 4 # RSA Exponent Length
	rsa_key = reading[rsa_block_off:rsa_block_off + rsa_key_len] # RSA Public Key
	rsa_key_hash = get_hash(rsa_key, 0x20) # SHA-256 of RSA Public Key
	rsa_sig = reading[rsa_block_off + rsa_key_len + rsa_exp_len:rsa_block_off + rsa_key_len * 2 + rsa_exp_len] # RSA Signature
	rsa_sig_hash = get_hash(rsa_sig, 0x20) # SHA-256 of RSA Signature
	
	# Detect Variant/Family
	variant, variant_p, var_rsa_db = get_variant()
	
	# Get & Hash the Proper + Initial Manifest RSA Signatures for (CS)SPS EXTR (FTPR + OPR1)
	if variant in ('SPS','CSSPS') and sps_opr_found :
		rsa_block_off_i = init_man_match[1] + 0x60 # Initial (FTPR) RSA Block Offset
		rsa_sig_i = reading[rsa_block_off_i + rsa_key_len + rsa_exp_len:rsa_block_off_i + rsa_key_len * 2 + rsa_exp_len] # Initial (FTPR) RSA Signature
		rsa_sig_s = rsa_sig_i + rsa_sig # Proper (OPR1) + Initial (FTPR) RSA Signatures
		rsa_sig_hash = get_hash(rsa_sig_s, 0x20) # SHA-256 of Proper (OPR1) + Initial (FTPR) RSA Signatures
	
	# Detect & Scan $MAN/$MN2 Manifest via Variant, for accurate info
	mn2_ftpr_hdr = get_struct(reading, start_man_match - 0x1B, get_manifest(reading, start_man_match - 0x1B, variant), file_end)
	
	# Detect RSA Public Key Recognition
	if not var_rsa_db : err_stor.append([col_r + 'Error: Unknown RSA Public Key!' + col_e, True])
	
	# Detect RSA Signature Validity
	man_valid = rsa_sig_val(mn2_ftpr_hdr, reading, start_man_match - 0x1B)
	if not man_valid[0] :
		if rsa_key_len == 0x180 : err_stor.append([col_m + 'Warning: RSA SSA-PSS Signature validation not implemented!' + col_e, False])
		else : err_stor.append([col_r + 'Error: Invalid RSA Signature!' + col_e, True])
	
	if rgn_exist :
		
		# Multiple Backup $FPT header bypass at SPS1/SPS4 (DFLT/FPTB)
		if variant == 'CSSPS' or (variant,major) == ('SPS',1) and fpt_count % 2 == 0 : fpt_count /= 2
		
		# Last/Uncharted partition scanning inspired by Lordkag's UEFIStrip
		# ME2-ME6 don't have size for last partition, scan its submodules
		if p_end_last == p_max_size :
			
			mn2_hdr = get_struct(reading, p_offset_last, get_manifest(reading, p_offset_last, variant), file_end)
			man_tag = mn2_hdr.Tag
			
			# ME6
			if man_tag == b'$MN2' :
				man_num = mn2_hdr.NumModules
				man_len = mn2_hdr.HeaderLength * 4
				mod_start = p_offset_last + man_len + 0xC
				
				for _ in range(0, man_num) :
					mme_mod = get_struct(reading, mod_start, MME_Header_New, file_end)
					
					mod_code_start = mme_mod.Offset_MN2
					mod_size_comp = mme_mod.SizeComp
					mod_size_uncomp = mme_mod.SizeUncomp
					
					if mod_size_comp > 0 : mod_size = mod_size_comp
					elif mod_size_comp == 0 : mod_size = mod_size_uncomp
					
					mod_end = p_offset_last + mod_code_start + mod_size
					
					if mod_end > mod_end_max : mod_end_max = mod_end # In case modules are not offset sorted
					
					mod_start += 0x60
			
			# ME2-5
			elif man_tag == b'$MAN' :
				man_num = mn2_hdr.NumModules
				man_len = mn2_hdr.HeaderLength * 4
				mod_start = p_offset_last + man_len + 0xC
				
				for _ in range(0, man_num) :
					mme_mod = get_struct(reading, mod_start, MME_Header_Old, file_end)
					mme_tag = mme_mod.Tag
					
					if mme_tag == b'$MME' : # Sanity check
						mod_size_all += mme_mod.Size # Append all $MOD ($MME Code) sizes
						mod_end_max = mod_start + 0x50 + 0xC + mod_size_all # Last $MME + $MME size + $SKU + all $MOD sizes
						mod_end = mod_end_max
					
						mod_start += 0x50
			
			# For Engine alignment & size, remove fpt_start (included in mod_end_max < mod_end < p_offset_last)
			mod_align = (mod_end_max - fpt_start) % 0x1000 # 4K alignment on Engine size only
			
			if mod_align > 0 : eng_fw_end = mod_end + 0x1000 - mod_align - fpt_start
			else : eng_fw_end = mod_end
		
		# Last $FPT entry has size, scan for uncharted partitions
		else :
			
			# Due to 4K $FPT Partition alignment, Uncharted can start after 0x0 to 0x1000 bytes
			if not fd_exist and not cse_lt_exist and reading[p_end_last:p_end_last + 0x4] != b'$CPD' :
				p_end_last_back = p_end_last # Store $FPT-based p_end_last offset for CSME 12+ FWUpdate Support detection
				uncharted_start = reading[p_end_last:p_end_last + 0x1004].find(b'$CPD') # Should be within the next 4K bytes
				if uncharted_start != -1 : p_end_last += uncharted_start # Adjust p_end_last to actual Uncharted start
			
			# ME8-10 WCOD/LOCL but works for ME7, TXE1-2, SPS2-3 even though these end at last $FPT entry
			while reading[p_end_last + 0x1C:p_end_last + 0x20] == b'$MN2' :
				mod_in_id = '0000'
				
				mn2_hdr = get_struct(reading, p_end_last, get_manifest(reading, p_end_last, variant), file_end)
				man_ven = '%X' % mn2_hdr.VEN_ID
				
				if man_ven == '8086' : # Sanity check
					man_num = mn2_hdr.NumModules
					man_len = mn2_hdr.HeaderLength * 4
					mod_start = p_end_last + man_len + 0xC
					mod_name = reading[p_end_last + man_len:p_end_last + man_len + 0x8].strip(b'\x00').decode('utf-8')
					mod_in_id = reading[p_end_last + man_len + 0x15:p_end_last + man_len + 0x15 + 0xB].strip(b'\x00').decode('utf-8')
					if variant == 'TXE' : mme_size = 0x80
					else : mme_size = 0x60 # ME & SPS
					mcp_start = mod_start + man_num * mme_size + mme_size # (each $MME = mme_size, mme_size padding after last $MME)
					
					mcp_mod = get_struct(reading, mcp_start, MCP_Header, file_end) # $MCP holds total partition size
					
					if mcp_mod.Tag == b'$MCP' : # Sanity check
						fpt_part_all.append([mod_name,p_end_last,p_end_last + mcp_mod.Offset_Code_MN2 + mcp_mod.CodeSize,mod_in_id,'Code',True,False])
						
						# Store $FPT Partition info for -dfpt
						if param.fpt_disp : # No Owner, Type Code, Valid, Not Empty
							pt_dfpt.add_row([mod_name,'','0x%0.6X' % p_end_last,'0x%0.6X' % mcp_mod.CodeSize,
							        '0x%0.6X' % (p_end_last + mcp_mod.Offset_Code_MN2 + mcp_mod.CodeSize),'Code',mod_in_id,True,False])
									
						p_end_last += mcp_mod.Offset_Code_MN2 + mcp_mod.CodeSize
					else :
						break # main "while" loop
				else :
					break # main "while" loop
				
			# SPS1, should not be run but works even though it ends at last $FPT entry
			while reading[p_end_last + 0x1C:p_end_last + 0x20] == b'$MAN' :
				
				mn2_hdr = get_struct(reading, p_end_last, get_manifest(reading, p_end_last, variant), file_end)
				man_ven = '%X' % mn2_hdr.VEN_ID
				
				if man_ven == '8086': # Sanity check
					man_num = mn2_hdr.NumModules
					man_len = mn2_hdr.HeaderLength * 4
					mod_start = p_end_last + man_len + 0xC
					mod_size_all = 0
					
					for _ in range(0, man_num) :
						mme_mod = get_struct(reading, mod_start, MME_Header_Old, file_end)
						mme_tag = mme_mod.Tag
						
						if mme_tag == b'$MME': # Sanity check
							mod_size_all += mme_mod.Size # Append all $MOD ($MME Code) sizes
							p_end_last = mod_start + 0x50 + 0xC + mod_size_all # Last $MME + $MME size + $SKU + all $MOD sizes
						
							mod_start += 0x50
						else :
							p_end_last += 10 # to break main "while" loop
							break # nested "for" loop
				else :
					break # main "while" loop
			
			# ME11+ WCOD/LOCL, TXE3+ DNXP
			while reading[p_end_last:p_end_last + 0x4] == b'$CPD' :
				cse_in_id = 0
				
				cpd_hdr_struct, cpd_hdr_size = get_cpd(reading, p_end_last)
				cpd_hdr = get_struct(reading, p_end_last, cpd_hdr_struct, file_end)
				cpd_num = cpd_entry_num_fix(reading, p_end_last, cpd_hdr.NumModules, cpd_hdr_size)
				cpd_tag = cpd_hdr.PartitionName
				
				# Calculate partition size by the CSE Extension 03 or 16 (CSE_Ext_03 or CSE_Ext_16)
				# PartitionSize of CSE_Ext_03/16 is always 0x0A at TXE3+ so check $CPD entries instead
				cse_in_id,cse_ext_part_name,cse_ext_part_size = cse_part_inid(reading, p_end_last, ext_dict, file_end, variant)
					
				# Last charted $FPT region size can be larger than CSE_Ext_03/16.PartitionSize because of 4K pre-alignment by Intel
				if cse_ext_part_name == cpd_hdr.PartitionName : # Sanity check
					p_end_last_cont = cse_ext_part_size
				
				# Calculate partition size by the $CPD entries (TXE3+, 2nd check for ME11+)
				for entry in range(1, cpd_num, 2) : # Skip 1st .man module, check only .met
					cpd_entry_hdr = get_struct(reading, p_end_last + cpd_hdr_size + entry * 0x18, CPD_Entry, file_end)
					cpd_mod_off,cpd_mod_huff,cpd_mod_res = cpd_entry_hdr.get_flags()
					
					cpd_entry_name = cpd_entry_hdr.Name
					
					if b'.met' not in cpd_entry_name and b'.man' not in cpd_entry_name : # Sanity check
						cpd_entry_offset = cpd_mod_off
						cpd_entry_size = cpd_entry_hdr.Size
						
						# Store last entry (max $CPD offset)
						if cpd_entry_offset > cpd_offset_last :
							cpd_offset_last = cpd_entry_offset
							cpd_end_last = cpd_entry_offset + cpd_entry_size
					else :
						break # nested "for" loop
				
				fpt_off_start = p_end_last # Store starting offset of current $FPT Partition for fpt_part_all
				
				# Take the largest partition size from the two checks
				# Add previous $CPD start for next size calculation
				p_end_last += max(p_end_last_cont,cpd_end_last)
				
				# Store all $FPT Partitions, uncharted (Type Code, Valid, Not Empty)
				fpt_part_all.append([cpd_tag,fpt_off_start,p_end_last,cse_in_id,'Code',True,False])
				
				# Store $FPT Partition info for -dfpt
				if param.fpt_disp :
					pt_dfpt.add_row([cpd_tag.decode('utf-8'),'','0x%0.6X' % fpt_off_start,'0x%0.6X' % (p_end_last - fpt_off_start),
					        '0x%0.6X' % p_end_last,'Code','%0.4X' % cse_in_id,True,False])
			
			# CSME 12+ consists of Layout Table (0x1000) + Data (MEA or LT size) + BPx (LT size)
			if cse_lt_exist :
				p_end_last = cse_lt_size + max(p_end_last,cse_lt_hdr_info[0][2]) + cse_lt_hdr_info[1][2] + cse_lt_hdr_info[2][2] + \
				             cse_lt_hdr_info[3][2] + cse_lt_hdr_info[4][2] + cse_lt_hdr_info[5][2]
			
			# For Engine alignment & size, remove fpt_start (included in p_end_last < eng_fw_end < p_offset_spi)
			mod_align = (p_end_last - fpt_start) % 0x1000 # 4K alignment on Engine size only
			
			if mod_align > 0 : eng_fw_end = p_end_last + 0x1000 - mod_align - fpt_start
			else : eng_fw_end = p_end_last - fpt_start
		
		# Show $FPT Partition info on demand (-dfpt)
		if param.fpt_disp : print('%s\n' % pt_dfpt)
		
		# Detect if uncharted $FPT partitions (IUPs) exist
		if len(fpt_part_all) > fpt_part_num : fwu_iup_exist = True
		
		# Detect $FPT partition overlaps
		for part in fpt_part_all :
			for all_part in fpt_part_all :
				# Partition A starts before B but ends after B start
				# Ignore partitions which have empty offset or size
				# Ignore FTUP combo partition (NFTP + WCOD + LOCL)
				# Ignore DLMP partition which overlaps by Intel design
				if not part[6] and not all_part[6] and not any(s in [0,0xFFFFFFFF] for s in (part[1],part[2],all_part[1],all_part[2])) \
				and part[0] not in [b'FTUP',b'DLMP'] and all_part[0] not in [b'FTUP',b'DLMP'] and (part[1] < all_part[1] < part[2]) :
					err_stor.append([col_r + 'Error: $FPT partition %s (0x%0.6X - 0x%0.6X) overlaps with %s (0x%0.6X - 0x%0.6X)' % \
									(part[0].decode('utf-8'),part[1],part[2],all_part[0].decode('utf-8'),all_part[1],all_part[2]) + col_e, True])
		
		# Detect CSSPS 4 sometimes uncharted/empty $BIS partition
		sps4_bis_match = (re.compile(br'\x24\x42\x49\x53\x00')).search(reading) if variant == 'CSSPS' else None
		
		# SPI image with FD
		if fd_me_rgn_exist :
			if eng_fw_end > me_fd_size :
				eng_size_text = [col_m + 'Warning: Firmware size exceeds Engine region, possible data loss!' + col_e, False]
			elif eng_fw_end < me_fd_size :
				# Extra data at Engine FD region padding
				padd_size_fd = me_fd_size - eng_fw_end
				padd_start_fd = fpt_start - cse_lt_size + eng_fw_end
				padd_end_fd = fpt_start - cse_lt_size + eng_fw_end + padd_size_fd
				if reading[padd_start_fd:padd_end_fd] != padd_size_fd * b'\xFF' :
					if sps4_bis_match is not None : eng_size_text = ['', False]
					else : eng_size_text = [col_m + 'Warning: Data in Engine region padding, possible data corruption!' + col_e, True]
		
		# Bare Engine Region
		elif fpt_start == 0 or (cse_lt_exist and cse_lt_off == 0) :
			# noinspection PyTypeChecker
			padd_size_file = file_end - eng_fw_end
			
			# noinspection PyTypeChecker
			if eng_fw_end > file_end :
				if eng_fw_end == file_end + 0x1000 - mod_align :
					pass # Firmware ends at last $FPT entry but is not 4K aligned, can be ignored (CSME12+)
				else :
					eng_size_text = [col_m + 'Warning: Firmware size exceeds file, possible data loss!' + col_e, False]
			elif eng_fw_end < file_end :
				if reading[eng_fw_end:eng_fw_end + padd_size_file] == padd_size_file * b'\xFF' :
					# Extra padding is clear
					eng_size_text = [col_y + 'Note: File size exceeds firmware, unneeded padding!' + col_e, False] # warn_stor
				else :
					# Extra padding has data
					if sps4_bis_match is not None : eng_size_text = ['', False]
					else : eng_size_text = [col_m + 'Warning: File size exceeds firmware, data in padding!' + col_e, True]
	
	# Firmware Type detection (Stock, Extracted, Update)
	if ifwi_exist : # IFWI
		fitc_ver_found = True
		fw_type = 'Region, Extracted'
		fitc_major = bpdt_hdr.FitMajor
		fitc_minor = bpdt_hdr.FitMinor
		fitc_hotfix = bpdt_hdr.FitHotfix
		fitc_build = bpdt_hdr.FitBuild
	elif rgn_exist : # SPS 1-3 have their own firmware Types
		if variant == 'SPS' : fw_type = 'Region' # SPS is built manually so EXTR
		elif variant == 'ME' and (2 <= major <= 7) :
			# Check 1, FOVD partition
			if (major >= 3 and not fovd_clean('new')) or (major == 2 and not fovd_clean('old')) : fw_type = 'Region, Extracted'
			else :
				# Check 2, EFFS/NVKR strings
				fitc_match = re.compile(br'\x4B\x52\x4E\x44\x00').search(reading) # KRND. detection = FITC, 0x00 adds old ME RGN support
				if fitc_match is not None :
					if major == 4 : fw_type_fix = True # ME4-Only Fix 3
					else : fw_type = 'Region, Extracted'
				elif major in [2,3] : fw_type_fix = True # ME2-Only Fix 1, ME3-Only Fix 1
				else : fw_type = 'Region, Stock'
		elif (variant == 'ME' and major >= 8) or variant in ['CSME','CSTXE','CSSPS','TXE'] :
			# Check 1, FITC Version
			if fpt_hdr.FitBuild in [0,65535] : # 0000/FFFF --> clean CS(ME)/CS(TXE)
				fw_type = 'Region, Stock'
				
				# Check 2, FOVD partition
				if not fovd_clean('new') : fw_type = 'Region, Extracted'
				
				# Check 3, CSTXE FIT placeholder $FPT Header entries
				if reading[fpt_start:fpt_start + 0x10] + reading[fpt_start + 0x1C:fpt_start + 0x30] == b'\xFF' * 0x24 : fw_type = 'Region, Extracted'
				
				# Check 4, CSME 13+ FWUpdate EXTR has placeholder $FPT ROM-Bypass Vectors 0-3 (0xFF instead of 0x00 padding)
				# If not enough (should be OK), MEA could further check if FTUP is empty and/or if PMCP & PCHC exist or not
				if variant == 'CSME' and major >= 13 and reading[fpt_start:fpt_start + 0x10] == b'\xFF' * 0x10 : fw_type = 'Region, Extracted'
			else :
				# Get FIT/FITC version used to build the image
				fitc_ver_found = True
				fw_type = 'Region, Extracted'
				fitc_major = fpt_hdr.FitMajor
				fitc_minor = fpt_hdr.FitMinor
				fitc_hotfix = fpt_hdr.FitHotfix
				fitc_build = fpt_hdr.FitBuild
				
	else :
		fw_type = 'Update' # No Region detected, Update
	
	# Verify $FPT Checksums (must be after Firmware Type detection)
	if rgn_exist :
		# Check $FPT Checksum-8
		fpt_chk_file = '0x%0.2X' % fpt_hdr.HeaderChecksum
		fpt_chk_sum = sum(reading[fpt_start + fpt_chk_start:fpt_start + fpt_chk_start + fpt_length]) - fpt_chk_byte
		fpt_chk_calc = '0x%0.2X' % ((0x100 - fpt_chk_sum & 0xFF) & 0xFF)
		if fpt_chk_calc != fpt_chk_file: fpt_chk_fail = True
		
		# CSME 12+, CSTXE and CSSPS 5+ EXTR $FPT Checksum is usually wrong (0x00 placeholder or same as in RGN), ignore
		if fw_type == 'Region, Extracted' and ((variant == 'CSME' and major >= 12) or variant == 'CSTXE' or (variant == 'CSSPS' and major >= 5)) :
			fpt_chk_fail = False
		
		# Warn when $FPT Checksum is wrong
		if fpt_chk_fail : warn_stor.append([col_m + 'Warning: Wrong $FPT Checksum %s, expected %s!' % (fpt_chk_file,fpt_chk_calc) + col_e, True])
		
		# Check SPS 3 extra $FPT Checksum-16 (from Lordkag's UEFIStrip)
		if variant == 'SPS' and major == 3 :
			sps3_chk_start = fpt_start + 0x30
			sps3_chk_end = sps3_chk_start + fpt_part_num * 0x20
			sps3_chk16_file = '0x%0.4X' % int.from_bytes(reading[sps3_chk_end:sps3_chk_end + 0x2], 'little')
			sps3_chk16_sum = sum(bytearray(reading[sps3_chk_start:sps3_chk_end])) & 0xFFFF
			sps3_chk16_calc = '0x%0.4X' % (~sps3_chk16_sum & 0xFFFF)
			if sps3_chk16_calc != sps3_chk16_file:
				warn_stor.append([col_m + 'Warning: Wrong $FPT SPS3 Checksum %s, expected %s!' % (sps3_chk16_file,sps3_chk16_calc) + col_e, True])
	
	# Check for Fujitsu UMEM ME Region (RGN/$FPT or UPD/$MN2)
	if (fd_me_rgn_exist and reading[me_fd_start:me_fd_start + 0x4] == b'\x55\x4D\xC9\x4D') or (reading[:0x4] == b'\x55\x4D\xC9\x4D') :
		warn_stor.append([col_m + 'Warning: Fujitsu Intel Engine firmware detected!' + col_e, False])
	
	# Detect Firmware Release (Production, Pre-Production, ROM-Bypass, Other)
	mn2_flags_pvbit,mn2_flags_reserved,mn2_flags_pre,mn2_flags_debug = mn2_ftpr_hdr.get_flags()
	rel_signed = ['Production', 'Debug'][mn2_flags_debug]
	
	# Production PRD, Pre-Production PRE, ROM-Bypass BYP
	if fpt_romb_found :
		release = 'ROM-Bypass'
		rel_db = 'BYP'
	elif rel_signed == 'Production' :
		release = 'Production'
		rel_db = 'PRD'
	else :
		release = 'Pre-Production' # rel_signed = Debug
		rel_db = 'PRE'
	
	# Detect PV/PC bit (0 or 1)
	if (variant == 'ME' and major >= 8) or variant == 'TXE' :
		pvbit_match = (re.compile(br'\x24\x44\x41\x54....................\x49\x46\x52\x50', re.DOTALL)).search(reading) # $DAT + [0x14] + IFRP detection
		if pvbit_match : pvbit = int.from_bytes(reading[pvbit_match.start() + 0x10:pvbit_match.start() + 0x11], 'little')
	elif variant in ['CSME','CSTXE','CSSPS'] or variant.startswith('PMC') :
		pvbit = mn2_flags_pvbit
	
	if variant == 'ME' : # Management Engine
		
		# Detect SKU Attributes
		sku_match = re.compile(br'\x24\x53\x4B\x55[\x03-\x04]\x00\x00\x00').search(reading[start_man_match:]) # $SKU detection
		if sku_match is not None :
			(start_sku_match, end_sku_match) = sku_match.span()
			start_sku_match += start_man_match
			end_sku_match += start_man_match
			
			if 2 <= major <= 6 :
				# https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/WordDocuments/instanceidandversionstringformats.htm
				# https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/WordDocuments/vproverificationtableparameterdefinitions.htm
				sku_me = int.from_bytes(reading[start_sku_match + 8:start_sku_match + 0xC], 'big')
			elif 7 <= major <= 10 :
				sku_attrib = get_struct(reading, start_sku_match, SKU_Attributes, file_end)
				x1,sku_slim,x3,x4,x5,x6,x7,x8,x9,is_patsburg,sku_type,sku_size,x13 = sku_attrib.get_flags()
		
		if major == 2 : # ICH8 2.0 - 2.2 or ICH8M 2.5 - 2.6
			sku_byte = {0: 'AMT + ASF + QST', 1: 'ASF + QST', 2: 'QST'}
			
			if sku_me == 0x00000000 : # AMT + ASF + QST
				sku = 'AMT'
				sku_db = 'AMT'
				if minor <= 2 : sku_db_check = 'AMTD'
				else : sku_db_check = 'AMTM'
			elif sku_me == 0x02000000 : # QST
				sku = 'QST'
				sku_db = 'QST'
				sku_db_check = 'QST'
			else :
				sku = col_r + 'Unknown' + col_e
				sku_db_check = 'UNK'
				err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
			
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_2_%s' % sku_db_check)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			# ME2-Only Fix 1 : The usual method to detect EXTR vs RGN does not work for ME2
			if fw_type_fix :
				if sku == 'QST' or (sku == 'AMT' and minor >= 5) :
					nvkr_match = (re.compile(br'\x4E\x56\x4B\x52\x4B\x52\x49\x44')).search(reading) # NVKRKRID detection
					if nvkr_match is not None :
						(start_nvkr_match, end_nvkr_match) = nvkr_match.span()
						nvkr_start = int.from_bytes(reading[end_nvkr_match:end_nvkr_match + 0x4], 'little')
						nvkr_size = int.from_bytes(reading[end_nvkr_match + 0x4:end_nvkr_match + 0x8], 'little')
						nvkr_data = reading[fpt_start + nvkr_start:fpt_start + nvkr_start + nvkr_size]
						# NVKR sections : Name[0xC] + Size[0x3] + Data[Size]
						prat_match = (re.compile(br'\x50\x72\x61\x20\x54\x61\x62\x6C\x65\xFF\xFF\xFF')).search(nvkr_data) # "Pra Table" detection (2.5/2.6)
						maxk_match = (re.compile(br'\x4D\x61\x78\x55\x73\x65\x64\x4B\x65\x72\x4D\x65\x6D\xFF\xFF\xFF')).search(nvkr_data) # "MaxUsedKerMem" detection
						if prat_match is not None :
							(start_prat_match, end_prat_match) = prat_match.span()
							prat_start = fpt_start + nvkr_start + end_prat_match + 0x3
							prat_end = fpt_start + nvkr_start + end_prat_match + 0x13
							me2_type_fix = int.from_bytes(reading[prat_start:prat_end], 'big')
							me2_type_exp = 0x7F45DBA3E65424458CB09A6E608812B1
						elif maxk_match is not None :
							(start_maxk_match, end_maxk_match) = maxk_match.span()
							qstpat_start = fpt_start + nvkr_start + end_maxk_match + 0x68
							qstpat_end = fpt_start + nvkr_start + end_maxk_match + 0x78
							me2_type_fix = int.from_bytes(reading[qstpat_start:qstpat_end], 'big')
							me2_type_exp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
				elif sku == 'AMT' and minor < 5 :
					nvsh_match = (re.compile(br'\x4E\x56\x53\x48\x4F\x53\x49\x44')).search(reading) # NVSHOSID detection
					if nvsh_match is not None :
						(start_nvsh_match, end_nvsh_match) = nvsh_match.span()
						nvsh_start = int.from_bytes(reading[end_nvsh_match:end_nvsh_match + 0x4], 'little')
						nvsh_size = int.from_bytes(reading[end_nvsh_match + 0x4:end_nvsh_match + 0x8], 'little')
						nvsh_data = reading[fpt_start + nvsh_start:fpt_start + nvsh_start + nvsh_size]
						netip_match = (re.compile(br'\x6E\x65\x74\x2E\x69\x70\xFF\xFF\xFF')).search(reading) # "net.ip" detection (2.0-2.2)
						if netip_match is not None :
							(start_netip_match, end_netip_match) = netip_match.span()
							netip_size = int.from_bytes(reading[end_netip_match + 0x0:end_netip_match + 0x3], 'little')
							netip_start = fpt_start + end_netip_match + 0x4 # 0x4 always 03 so after that byte for 00 search
							netip_end = fpt_start + end_netip_match + netip_size + 0x3 # (+ 0x4 - 0x1)
							me2_type_fix = int.from_bytes(reading[netip_start:netip_end], 'big')
							me2_type_exp = int.from_bytes(b'\x00' * (netip_size - 0x1), 'big')
							
				if me2_type_fix != me2_type_exp : fw_type = 'Region, Extracted'
				else : fw_type = 'Region, Stock'
			
			# ME2-Only Fix 2 : Identify ICH Revision B0 firmware SKUs
			me2_sku_fix = ['FF4DAEACF679A7A82269C1C722669D473F7D76AD3DFDE12B082A0860E212CD93',
			'345F39266670F432FCFF3B6DA899C7B7E0137ED3A8A6ABAD4B44FB403E9BB3BB',
			'8310BA06D7B9687FC18847991F9B1D747B55EF30E5E0E5C7B48E1A13A5BEE5FA']
			if rsa_sig_hash in me2_sku_fix :
				sku = 'AMT B0'
				sku_db = 'AMT_B0'
			
			# ME2-Only Fix 3 : Detect ROMB RGN/EXTR image correctly (at $FPT v1 ROMB was before $FPT)
			if rgn_exist and release == 'Pre-Production' :
				byp_pat = re.compile(br'\x24\x56\x45\x52\x02\x00\x00\x00') # $VER2... detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				
				if byp_match is not None :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
					(byp_start, byp_end) = byp_match.span()
					byp_size = fpt_start - (byp_start - 0x80)
					eng_fw_end += byp_size
					if 'Data in Engine region padding' in eng_size_text[0] : eng_size_text = ['', False]
					
			if minor >= 5 : platform = 'ICH8M'
			else : platform = 'ICH8'
	
		elif major == 3 : # ICH9 or ICH9DO
			sku_bits = {1: 'IDT', 2: 'TPM', 3: 'AMT Lite', 4: 'AMT', 5: 'ASF', 6: 'QST'}
			
			if sku_me in [0x0E000000,0x00000000] : # AMT + ASF + QST (00000000 for Pre-Alpha ROMB)
				sku = 'AMT' # Q35 only
				sku_db = 'AMT'
			elif sku_me == 0x06000000 : # ASF + QST
				sku = 'ASF' # Q33 (HP dc5800)
				sku_db = 'ASF'
			elif sku_me == 0x02000000 : # QST
				sku = 'QST'
				sku_db = 'QST'
			else :
				sku = col_r + 'Unknown' + col_e
				err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
				
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_3_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True

			# ME3-Only Fix 1 : The usual method to detect EXTR vs RGN does not work for ME3
			if fw_type_fix :
				me3_type_fix1 = []
				me3_type_fix2a = 0x10 * 0xFF
				me3_type_fix2b = 0x10 * 0xFF
				me3_type_fix3 = 0x10 * 0xFF
				effs_match = (re.compile(br'\x45\x46\x46\x53\x4F\x53\x49\x44')).search(reading) # EFFSOSID detection
				if effs_match is not None :
					(start_effs_match, end_effs_match) = effs_match.span()
					effs_start = int.from_bytes(reading[end_effs_match:end_effs_match + 0x4], 'little')
					effs_size = int.from_bytes(reading[end_effs_match + 0x4:end_effs_match + 0x8], 'little')
					effs_data = reading[fpt_start + effs_start:fpt_start + effs_start + effs_size]
					
					me3_type_fix1 = (re.compile(br'\x4D\x45\x5F\x43\x46\x47\x5F\x44\x45\x46\x04\x4E\x56\x4B\x52')).findall(effs_data) # ME_CFG_DEF.NVKR detection (RGN have <= 2)
					me3_type_fix2 = (re.compile(br'\x4D\x61\x78\x55\x73\x65\x64\x4B\x65\x72\x4D\x65\x6D\x04\x4E\x56\x4B\x52\x7F\x78\x01')).search(effs_data) # MaxUsedKerMem.NVKR.x. detection
					me3_type_fix3 = int.from_bytes(reading[fpt_start + effs_start + effs_size - 0x20:fpt_start + effs_start + effs_size - 0x10], 'big')
					
					if me3_type_fix2 is not None :
						(start_me3f2_match, end_me3f2_match) = me3_type_fix2.span()
						me3_type_fix2a = int.from_bytes(reading[fpt_start + effs_start + end_me3f2_match - 0x30:fpt_start + effs_start + end_me3f2_match - 0x20], 'big')
						me3_type_fix2b = int.from_bytes(reading[fpt_start + effs_start + end_me3f2_match + 0x30:fpt_start + effs_start + end_me3f2_match + 0x40], 'big')

				if len(me3_type_fix1) > 2 or me3_type_fix3 != 0x10 * 0xFF or me3_type_fix2a != 0x10 * 0xFF or me3_type_fix2b != 0x10 * 0xFF : fw_type = 'Region, Extracted'
				else : fw_type = 'Region, Stock'
			
			# ME3-Only Fix 2 : Detect AMT ROMB UPD image correctly (very vague, may not always work)
			if fw_type == 'Update' and release == 'Pre-Production' : # Debug Flag detected at $MAN but PRE vs BYP is needed for UPD (not RGN)
				# It seems that ROMB UPD is smaller than equivalent PRE UPD
				# min size(ASF, UPD) is 0xB0904 so 0x100000 safe min AMT ROMB
				# min size(AMT, UPD) is 0x190904 so 0x185000 safe max AMT ROMB
				# min size(QST, UPD) is 0x2B8CC so 0x40000 safe min for ASF ROMB
				# min size(ASF, UPD) is 0xB0904 so 0xAF000 safe max for ASF ROMB
				# min size(QST, UPD) is 0x2B8CC so 0x2B000 safe max for QST ROMB
				# noinspection PyTypeChecker
				if (sku == 'AMT' and 0x100000 < file_end < 0x185000) or (sku == 'ASF' and 0x40000 < file_end < 0xAF000) or (sku == 'QST' and file_end < 0x2B000) :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			# ME3-Only Fix 3 : Detect Pre-Alpha ($FPT v1) ROMB RGN/EXTR image correctly
			if rgn_exist and fpt_version == 16 and release == 'Pre-Production' :
				byp_pat = re.compile(br'\x24\x56\x45\x52\x03\x00\x00\x00') # $VER3... detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				
				if byp_match is not None :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
					(byp_start, byp_end) = byp_match.span()
					byp_size = fpt_start - (byp_start - 0x80)
					eng_fw_end += byp_size
					if 'Data in Engine region padding' in eng_size_text[0] : eng_size_text = ['', False]
			
			platform = 'ICH9'
	
		elif major == 4 : # ICH9M or ICH9M-E (AMT or TPM+AMT): 4.0 - 4.2 , xx00xx --> 4.0 , xx20xx --> 4.1 or 4.2
			sku_bits = {0: 'Reserved', 1: 'IDT', 2: 'TPM', 3: 'AMT Lite', 4: 'AMT', 5: 'ASF', 6: 'QST', 7: 'Reserved'}
			
			if sku_me in [0xAC200000,0xAC000000,0x04000000] : # 040000 for Pre-Alpha ROMB
				sku = 'AMT + TPM' # CA_ICH9_REL_ALL_SKUs_ (TPM + AMT)
				sku_db = 'ALL'
			elif sku_me in [0x8C200000,0x8C000000,0x0C000000] : # 0C000000 for Pre-Alpha ROMB
				sku = 'AMT' # CA_ICH9_REL_IAMT_ (AMT)
				sku_db = 'AMT'
			elif sku_me in [0xA0200000,0xA0000000] :
				sku = 'TPM' # CA_ICH9_REL_NOAMT_ (TPM)
				sku_db = 'TPM'
			else :
				sku = col_r + 'Unknown' + col_e
				err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
			
			# ME4-Only Fix 1 : Detect ROMB UPD image correctly
			if fw_type == "Update" :
				byp_pat = re.compile(br'\x52\x4F\x4D\x42') # ROMB detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				if byp_match is not None :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			# ME4-Only Fix 2 : Detect SKUs correctly, only for Pre-Alpha firmware
			if minor == 0 and hotfix == 0 :
				if fw_type == 'Update' :
					tpm_tag = (re.compile(br'\x24\x4D\x4D\x45........................\x54\x50\x4D', re.DOTALL)).search(reading) # $MME + [0x18] + TPM
					amt_tag = (re.compile(br'\x24\x4D\x4D\x45........................\x4D\x4F\x46\x46\x4D\x31\x5F\x4F\x56\x4C', re.DOTALL)).search(reading) # $MME + [0x18] + MOFFM1_OVL
				else :
					tpm_tag = (re.compile(br'\x4E\x56\x54\x50\x54\x50\x49\x44')).search(reading) # NVTPTPID partition found at ALL or TPM
					amt_tag = (re.compile(br'\x4E\x56\x43\x4D\x41\x4D\x54\x43')).search(reading) # NVCMAMTC partition found at ALL or AMT
				
				if tpm_tag is not None and amt_tag is not None :
					sku = 'AMT + TPM' # CA_ICH9_REL_ALL_SKUs_
					sku_db = 'ALL'
				elif tpm_tag is not None :
					sku = 'TPM' # CA_ICH9_REL_NOAMT_
					sku_db = 'TPM'
				else :
					sku = 'AMT' # CA_ICH9_REL_IAMT_
					sku_db = 'AMT'
			
			# ME4-Only Fix 3 : The usual method to detect EXTR vs RGN does not work for ME4, KRND. not enough
			if fw_type_fix :
				effs_match = (re.compile(br'\x45\x46\x46\x53\x4F\x53\x49\x44')).search(reading) # EFFSOSID detection
				if effs_match is not None :
					(start_effs_match, end_effs_match) = effs_match.span()
					effs_start = int.from_bytes(reading[end_effs_match:end_effs_match + 0x4], 'little')
					effs_size = int.from_bytes(reading[end_effs_match + 0x4:end_effs_match + 0x8], 'little')
					effs_data = reading[fpt_start + effs_start:fpt_start + effs_start + effs_size]
				
					me4_type_fix1 = (re.compile(br'\x4D\x45\x5F\x43\x46\x47\x5F\x44\x45\x46')).findall(effs_data) # ME_CFG_DEF detection (RGN have 2-4)
					me4_type_fix2 = (re.compile(br'\x47\x50\x49\x4F\x31\x30\x4F\x77\x6E\x65\x72')).search(effs_data) # GPIO10Owner detection
					me4_type_fix3 = (re.compile(br'\x41\x70\x70\x52\x75\x6C\x65\x2E\x30\x33\x2E\x30\x30\x30\x30\x30\x30')).search(effs_data) # AppRule.03.000000 detection
				
					if len(me4_type_fix1) > 5 or me4_type_fix2 is not None or me4_type_fix3 is not None : fw_type = "Region, Extracted"
					else : fw_type = 'Region, Stock'
			
			# Placed here in order to comply with Fix 2 above in case it is triggered
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_4_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				
			platform = 'ICH9M'
			
		elif major == 5 : # ICH10D or ICH10DO
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 5: 'ASF', 6: 'QST', 8: 'Level III Manageability Upgrade', 9: 'Corporate', 10: 'Anti-Theft', 15: 'Remote PC Assist'}
			
			if sku_me == 0x3E080000 : # EL_ICH10_SKU1
				sku = 'Digital Office' # AMT
				sku_db = 'DO'
			elif sku_me == 0x060D0000 : # EL_ICH10_SKU4
				sku = 'Base Consumer' # NoAMT
				sku_db = 'BC'
			elif sku_me == 0x06080000 : # EL_ICH10_SKU2 or EL_ICH10_SKU3
				sku = 'Digital Home or Base Corporate (?)'
				sku_db = 'DHBC'
			else :
				sku = col_r + 'Unknown' + col_e
				err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
				
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_5_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				
			# ME5-Only Fix : Detect ROMB UPD image correctly
			if fw_type == 'Update' :
				byp_pat = re.compile(br'\x52\x4F\x4D\x42') # ROMB detection (ROM-Bypass)
				byp_match = byp_pat.search(reading)
				if byp_match is not None :
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			platform = 'ICH10'
	
		elif major == 6 :
			platform = 'IBX'
			
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 6: 'QST', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist'}
			
			if sku_me == 0x00000000 : # Ignition (128KB, 2MB)
				if hotfix == 50 : # 89xx (Cave/Coleto Creek)
					ign_pch = 'CCK'
					platform = 'CCK'
				else : # P55, PM55, 34xx (Ibex Peak)
					ign_pch = 'IBX'
				sku_db = 'IGN_' + ign_pch
				sku = 'Ignition ' + ign_pch
			elif sku_me == 0x701C0000 : # Home IT (1.5MB, 4MB)
				sku = '1.5MB'
				sku_db = '1.5MB'
			# xxDCxx = 6.x, xxFCxx = 6.0, xxxxEE = Mobile, xxxx6E = Desktop, F7xxxx = Old Alpha/Beta Releases
			elif sku_me in [0x77DCEE00,0x77FCEE00,0xF7FEFE00] : # vPro (5MB, 8MB)
				sku = '5MB MB'
				sku_db = '5MB_MB'
			elif sku_me in [0x77DC6E00,0x77FC6E00,0xF7FE7E00] : # vPro (5MB, 8MB)
				sku = '5MB DT'
				sku_db = '5MB_DT'
			else :
				sku = col_r + 'Unknown' + col_e
				err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
				
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_6_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			# ME6-Only Fix 1 : ME6 Ignition does not work with KRND
			if 'Ignition' in sku and rgn_exist :
				ign_pat = (re.compile(br'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6D\x3C\x75\x6D')).findall(reading) # Clean $MINIFAD checksum
				if len(ign_pat) < 2 : fw_type = "Region, Extracted" # 2 before NFTP & IGRT
				else : fw_type = "Region, Stock"
			
			# ME6-Only Fix 2 : Ignore errors at ROMB (Region present, FTPR tag & size missing)
			if release == "ROM-Bypass" :
				if 'Firmware size exceeds file' in eng_size_text[0] : eng_size_text = ['', False]
			
		elif major == 7 :
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist'}
			
			if sku_slim == 1 :
				sku = 'Slim'
				sku_db = 'SLM'
			elif sku_size * 0.5 == 1.5 :
				sku = '1.5MB'
				sku_db = '1.5MB'
			elif sku_size * 0.5 == 5 or (build,hotfix,minor,sku_size) == (1041,0,0,1) :
				sku = '5MB'
				sku_db = '5MB'
			
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_7_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			# ME7-Only Fix: ROMB UPD detection
			if fw_type == 'Update' :
				me7_mn2_hdr_len = mn2_ftpr_hdr.HeaderLength * 4
				me7_mn2_mod_len = (mn2_ftpr_hdr.NumModules + 1) * 0x60
				me7_mcp = get_struct(reading, start_man_match - 0x1B + me7_mn2_hdr_len + 0xC + me7_mn2_mod_len, MCP_Header, file_end) # Goto $MCP
				
				if me7_mcp.CodeSize == 374928 or me7_mcp.CodeSize == 419984 : # 1.5/5MB ROMB Code Sizes
					release = 'ROM-Bypass'
					rel_db = 'BYP'
			
			# ME7 Blacklist Table Detection
			me7_blist_1_minor  = int.from_bytes(reading[start_man_match + 0x6DF:start_man_match + 0x6E1], 'little')
			me7_blist_1_hotfix  = int.from_bytes(reading[start_man_match + 0x6E1:start_man_match + 0x6E3], 'little')
			me7_blist_1_build  = int.from_bytes(reading[start_man_match + 0x6E3:start_man_match + 0x6E5], 'little')
			if me7_blist_1_build != 0 : me7_blist_1 = '<= 7.%d.%d.%d' % (me7_blist_1_minor, me7_blist_1_hotfix, me7_blist_1_build)
			me7_blist_2_minor  = int.from_bytes(reading[start_man_match + 0x6EB:start_man_match + 0x6ED], 'little')
			me7_blist_2_hotfix  = int.from_bytes(reading[start_man_match + 0x6ED:start_man_match + 0x6EF], 'little')
			me7_blist_2_build  = int.from_bytes(reading[start_man_match + 0x6EF:start_man_match + 0x6F1], 'little')
			if me7_blist_2_build != 0 : me7_blist_2 = '<= 7.%d.%d.%d' % (me7_blist_2_minor, me7_blist_2_hotfix, me7_blist_2_build)
			
			platform = ['CPT','CPT/PBG'][is_patsburg]
			
		elif major == 8 :
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist', 23: 'Small Business'}
			
			if sku_size * 0.5 == 1.5 :
				sku = '1.5MB'
				sku_db = '1.5MB'
			elif sku_size * 0.5 == 5 :
				sku = '5MB'
				sku_db = '5MB'
			
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_8_%s' % sku_db)
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
				
			# ME8-Only Fix: SVN location
			svn = mn2_ftpr_hdr.SVN_8
			
			platform = 'CPT/PBG/PPT'
		
		elif major == 9 :
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist', 23: 'Small Business'}
			
			if sku_type == 0 :
				sku = '5MB'
				sku_db = '5MB'
			elif sku_type == 1 :
				sku = '1.5MB'
				sku_db = '1.5MB'
			elif sku_type == 2 :
				sku = 'Slim'
				sku_db = 'SLM'
			
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_9%d_%s' % (minor, sku_db))
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			if minor == 0 : platform = 'LPT'
			elif minor == 1 : platform = 'LPT/WPT'
			elif minor in [5,6] : platform = 'LPT-LP'
				
			# 9.6 --> Intel Harris Beach Ultrabook, HSW developer preview (https://bugs.freedesktop.org/show_bug.cgi?id=90002)
			
		elif major == 10 :
			sku_bits = {3: 'Standard Manageability', 4: 'AMT', 8: 'Local Wakeup Timer', 9: 'KVM', 10: 'Anti-Theft', 15: 'Remote PC Assist', 23: 'Small Business'}
			
			if sku_type == 0 :
				sku = '5MB'
				sku_db = '5MB'
			elif sku_type == 1 :
				sku = '1.5MB'
				sku_db = '1.5MB'
			elif sku_type == 2 :
				sku = 'Slim'
				sku_db = 'SLM'
			
			db_maj,db_min,db_hot,db_bld = check_upd('Latest_ME_10%d_%s' % (minor, sku_db))
			if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
			
			if minor == 0 : platform = 'WPT-LP'
	
	elif variant == 'CSME' : # Converged Security Management Engine
		
		# Firmware Unpacking for all CSME
		if param.me11_mod_extr :
			cse_unpack(variant, fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail)
			continue # Next input file
		
		# Get CSE File System Attributes & Configuration State (invokes mfs_anl, must be before ext_anl)
		mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final = get_mfs_anl(mfs_state, mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final, mfs_found)
		
		# Get CSE Firmware Attributes (must be after mfs_anl)
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext32_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info,ext_iunit_val,arb_svn \
		= ext_anl(reading, '$MN2', start_man_match, file_end, [variant, major, minor, hotfix, build], None, [mfs_parsed_idx,intel_cfg_hash_mfs], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
		
		# MFS missing, determine state via FTPR > fitc.cfg (must be after mfs_anl & ext_anl)
		if mfs_state == 'Unconfigured' and oem_config : mfs_state = 'Configured'
		
		fw_0C_sku0,fw_0C_sku1,fw_0C_lbg,fw_0C_sku2 = ext12_info # Get SKU Capabilities, SKU Type, HEDT Support, SKU Platform
		
		# Set SKU Type via Extension 0xC Attributes
		if fw_0C_sku1 == 0 : # 0 Corporate/Intel (1272K MFS)
			sku_init = 'Corporate'
			sku_init_db = 'COR'
		elif fw_0C_sku1 == 1 : # 1 Consumer/Intel (400K MFS)
			sku_init = 'Consumer'
			sku_init_db = 'CON'
		elif fw_0C_sku1 == 2 : # 2 Slim/Apple (256K MFS)
			sku_init = 'Slim'
			sku_init_db = 'SLM'
		else :
			sku_init = 'Unknown'
			sku_init_db = 'UNK'
		
		# Detect SKU Platform via Extension 0xC Attributes
		if fw_0C_sku2 == 0 : pos_sku_ext = 'H' # Halo
		elif fw_0C_sku2 == 1 : pos_sku_ext = 'LP' # Low Power
		elif fw_0C_sku2 == 2 : pos_sku_ext = 'N' # Maybe V for Value ???
		
		# Detect SKU Platform via MFS Intel PCH Initialization Table
		if pch_init_final and '-LP' in pch_init_final[-1][0] : pos_sku_tbl = 'LP'
		elif pch_init_final and '-H' in pch_init_final[-1][0] : pos_sku_tbl = 'H'
		elif pch_init_final and '-N' in pch_init_final[-1][0] : pos_sku_tbl = 'N'
		
		db_sku_chk,sku,sku_stp,sku_pdm = get_cse_db(variant) # Get CSE SKU info from DB
		
		# Fix Release of PRE firmware which are wrongly reported as PRD
		release, rel_db = release_fix(release, rel_db, rsa_key_hash)
		
		# Detected stitched PMC firmware
		if pmcp_found :
			pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,pmc_mn2_signed_db,pmcp_upd_found,pmc_platform,pmc_date,pmc_svn,pmc_pvbit = pmc_anl(pmc_mn2_ver, pmc_mod_attr)
		
		if major == 11 :
			
			# Set SKU Platform via Extension 0C Attributes
			if minor > 0 or (minor == 0 and (hotfix > 0 or (hotfix == 0 and build >= 1205 and build != 7101))) :
				pass # Use the already set general CSME pos_sku_ext
			else :
				pos_sku_ext = 'Invalid' # Only for CSME >= 11.0.0.1205
			
			# SKU not in Extension 0C and not in DB, scan decompressed Huffman module FTPR > kernel
			if pos_sku_ext == 'Invalid' and sku == 'NaN' :
				for mod in cpd_mod_attr :
					if mod[0] == 'kernel' :
						huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, 'error')
						ker_decomp, huff_error = cse_huffman_decompress(reading[mod[3]:mod[3] + mod[4]], mod[4], mod[5], huff_shape, huff_sym, huff_unk, 'none')
						
						# 0F22D88D65F85B5E5DC355B8 (56 & AA for H, 60 & A0 for LP)
						sku_pat = re.compile(br'\x0F\x22\xD8\x8D\x65\xF8\x5B\x5E\x5D\xC3\x55\xB8').search(ker_decomp)
						
						if sku_pat :
							sku_bytes = int.from_bytes(ker_decomp[sku_pat.end():sku_pat.end() + 0x1] + ker_decomp[sku_pat.end() + 0x17:sku_pat.end() + 0x18], 'big')
							if sku_bytes == 0x56AA : pos_sku_ker = 'H'
							elif sku_bytes == 0x60A0 : pos_sku_ker = 'LP'
						
						break # Skip rest of FTPR modules
			
			if pos_sku_ext in ['Unknown','Invalid'] : # SKU not retrieved from Extension 0C
				if pos_sku_ker == 'Invalid' : # SKU not retrieved from Kernel
					if sku == 'NaN' : # SKU not retrieved from manual MEA DB entry
						sku = col_r + 'Unknown' + col_e
						err_stor.append([col_r + 'Error: Unknown %s %d.%d SKU!' % (variant, major, minor) + col_e, True])
					else :
						pass # SKU retrieved from manual MEA DB entry
				else :
					sku = sku_init + ' ' + pos_sku_ker # SKU retrieved from Kernel
			else :
				sku = sku_init + ' ' + pos_sku_ext # SKU retrieved from Extension 0C
			
			# Store final SKU result (CSME 11 only)
			if ' LP' in sku : sku_result = 'LP'
			elif ' H' in sku : sku_result = 'H'
			
			# Set PCH/SoC Stepping, if not found at DB
			if sku_stp == 'NaN' and pch_init_final : sku_stp = pch_init_final[-1][1]
			
			# Adjust PCH Platform via Minor version
			if minor == 0 and not pch_init_final : platform = 'SPT' # Sunrise Point
			elif minor in [5,6,7,8] and not pch_init_final : platform = 'SPT/KBP' # Sunrise/Union Point
			elif minor in [10,11] and not pch_init_final : platform = 'BSF' # Basin Falls
			elif minor in [20,21,22] and not pch_init_final : platform = 'LBG' # Lewisburg
			
			# Get DB SKU and check for Latest status (must be before sku_pdm)
			sku_db,upd_found = sku_db_upd_cse(sku_init_db, sku_result, sku_stp, upd_found, False)
			
			if minor in [0,5,6,7,10,20,21] : upd_found = True # INTEL-SA-00086
			
			# Power Down Mitigation (PDM) is a SPT-LP C erratum, first fixed at ~11.0.0.1183
			# Hardcoded in FTPR > BUP, Huffman decompression required to detect NPDM or YPDM
			# Hardfixed at KBP-LP A but 11.5-8 have PDM firmware for SPT-LP C with KBL(R)
			if sku_result == 'LP' :
				# PDM not in DB, scan decompressed Huffman module FTPR > bup
				if sku_pdm not in ['NPDM','YPDM'] :
					for mod in cpd_mod_attr :
						if mod[0] == 'bup' :
							huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, 'error')
							bup_decomp, huff_error = cse_huffman_decompress(reading[mod[3]:mod[3] + mod[4]], mod[4], mod[5], huff_shape, huff_sym, huff_unk, 'none')
							
							if bup_decomp != b'' :
								# 55B00189E55DC3
								pdm_pat = re.compile(br'\x55\xB0\x01\x89\xE5\x5D\xC3').search(bup_decomp)
							
								if pdm_pat : sku_pdm = 'YPDM'
								else : sku_pdm = 'NPDM'
							
							break # Skip rest of FTPR modules
				
				if sku_pdm == 'YPDM' : pdm_status = 'Yes'
				elif sku_pdm == 'NPDM' : pdm_status = 'No'
				elif sku_pdm == 'UPDM1' : pdm_status = 'Unknown 1'
				elif sku_pdm == 'UPDM2' : pdm_status = 'Unknown 2'
				else : pdm_status = 'Unknown'
				
				sku_db += '_%s' % sku_pdm # Must be after sku_db_upd_cse
		
		elif major == 12 :
			
			# Get Final SKU, SKU Platform, SKU Stepping
			sku,sku_result,sku_stp = get_csme_sku(sku_init, fw_0C_sku0, ['H','H','LP','LP'], sku, sku_stp, db_sku_chk, pos_sku_tbl, pos_sku_ext, pch_init_final)
			
			# Verify PMC compatibility
			if pmcp_found and pmc_pch_gen == 300 : pmc_chk(pmc_mn2_signed, release, pmc_pch_gen, [300], pmc_pch_sku, sku_result, sku_stp, pmc_pch_rev, pmc_platform)
			
			# Get DB SKU and check for Latest status
			sku_db,upd_found = sku_db_upd_cse(sku_init_db, sku_result, sku_stp, upd_found, False)
			
			# Adjust PCH/SoC Platform via Minor version
			if minor == 0 and not pch_init_final : platform = 'CNP' # Cannon Point
			
		elif major == 13 :
			
			# Get Final SKU, SKU Platform, SKU Stepping
			sku,sku_result,sku_stp = get_csme_sku(sku_init, fw_0C_sku0, ['H','H','LP','H'], sku, sku_stp, db_sku_chk, pos_sku_tbl, pos_sku_ext, pch_init_final)
			
			# Verify PMC compatibility
			if pmcp_found : pmc_chk(pmc_mn2_signed, release, pmc_pch_gen, [400,130], pmc_pch_sku, sku_result, sku_stp, pmc_pch_rev, pmc_platform)
			
			# Get DB SKU and check for Latest status
			sku_db,upd_found = sku_db_upd_cse(sku_init_db, sku_result, sku_stp, upd_found, False)
			
			# Adjust PCH/SoC Platform via Minor version
			if minor == 0 and not pch_init_final : platform = 'ICP' # Ice Point
			
		elif major == 14 :
			
			# Get Final SKU, SKU Platform, SKU Stepping
			sku,sku_result,sku_stp = get_csme_sku(sku_init, fw_0C_sku0, ['H','H','LP','H'], sku, sku_stp, db_sku_chk, pos_sku_tbl, pos_sku_ext, pch_init_final)
			
			# Verify PMC compatibility
			if pmcp_found : pmc_chk(pmc_mn2_signed, release, pmc_pch_gen, [140], pmc_pch_sku, sku_result, sku_stp, pmc_pch_rev, pmc_platform)
			
			# Get DB SKU and check for Latest status
			sku_db,upd_found = sku_db_upd_cse(sku_init_db, sku_result, sku_stp, upd_found, False)
			
			# Adjust PCH/SoC Platform via Minor version
			if minor == 0 and not pch_init_final : platform = 'CMP' # Comet Point
			
		elif major == 15 :
			
			# Adjust PCH/SoC Platform via Minor version
			if minor == 0 and not pch_init_final : platform = 'TGP' # Tiger Point
	
	elif variant == 'TXE' : # Trusted Execution Engine
		
		# Detect SKU Attributes
		sku_match = re.compile(br'\x24\x53\x4B\x55[\x03-\x04]\x00\x00\x00').search(reading[start_man_match:]) # $SKU detection
		if sku_match is not None :
			(start_sku_match, end_sku_match) = sku_match.span()
			start_sku_match += start_man_match
			end_sku_match += start_man_match
			
			sku_attrib = get_struct(reading, start_sku_match, SKU_Attributes, file_end)
			x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,sku_size,x13 = sku_attrib.get_flags()
			
		if major in [0,1] :
			if sku_size * 0.5 in (1.5,2.0) :
				if minor == 0 :
					sku = '1.25MB'
					sku_db = '1.25MB'
				else :
					sku = '1.375MB'
					sku_db = '1.375MB'
			elif sku_size * 0.5 in (2.5,3.0) :
				sku = '3MB'
				sku_db = '3MB'
			else :
				sku = col_r + 'Unknown' + col_e
			
			if rsa_key_hash in ['6B8B10107E20DFD45F6C521100B950B78969B4AC9245D90DE3833E0A082DF374','86C0E5EF0CFEFF6D810D68D83D8C6ECB68306A644C03C0446B646A3971D37894'] :
				sku += ' M/D'
				sku_db += '_MD'
			elif rsa_key_hash in ['613421A156443F1C038DDE342FF6564513A1818E8CC23B0E1D7D7FB0612E04AC','86C0E5EF0CFEFF6D810D68D83D8C6ECB68306A644C03C0446B646A3971D37894'] :
				sku += ' I/T'
				sku_db += '_IT'
			
			platform = 'BYT'
				
		elif major == 2 :
			if sku_size * 0.5 == 1.5 :
				sku = '1.375MB'
				sku_db = '1.375MB'
			
			platform = 'BSW/CHT'
			
		db_maj,db_min,db_hot,db_bld = check_upd('Latest_TXE_%d%d_%s' % (major, minor, sku_db))
		if minor < db_min or (minor == db_min and (hotfix < db_hot or (hotfix == db_hot and build < db_bld))) : upd_found = True
	
	elif variant == 'CSTXE' : # Converged Security Trusted Execution Engine
		
		# Firmware Unpacking for all CSTXE
		if param.me11_mod_extr :
			cse_unpack(variant, fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail)
			continue # Next input file
		
		# Get CSE File System Attributes & Configuration State (invokes mfs_anl, must be before ext_anl)
		mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final = get_mfs_anl(mfs_state, mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final, mfs_found)
		
		# Detect CSE Firmware Attributes (must be after mfs_anl)
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext32_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info,ext_iunit_val,arb_svn \
		= ext_anl(reading, '$MN2', start_man_match, file_end, [variant, major, minor, hotfix, build], None, [mfs_parsed_idx,intel_cfg_hash_mfs], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
		
		# MFS missing, determine state via FTPR > fitc.cfg (must be after mfs_anl & ext_anl)
		if mfs_state == 'Unconfigured' and oem_config : mfs_state = 'Configured'
		
		fw_0C_sku0,fw_0C_sku1,fw_0C_lbg,fw_0C_sku2 = ext12_info # Get SKU Capabilities, SKU Type, HEDT Support, SKU Platform
		
		db_sku_chk,sku,sku_stp,sku_pdm = get_cse_db(variant) # Get CSE SKU info from DB
		
		# Fix Release of PRE firmware which are wrongly reported as PRD
		release, rel_db = release_fix(release, rel_db, rsa_key_hash)
		
		# Detected stitched PMC firmware
		if pmcp_found :				
			pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,pmc_mn2_signed_db,pmcp_upd_found,pmc_platform,pmc_date,pmc_svn,pmc_pvbit = pmc_anl(pmc_mn2_ver, pmc_mod_attr)
		
		if major == 3 :
			
			if minor in [0,1] :
				
				# Adjust SoC Stepping if not from DB
				if sku_stp == 'NaN' :
					if release == 'Production' : sku_stp = 'B' # PRD
					else : sku_stp = 'A' # PRE, BYP
					
				platform = 'APL' # Apollo Lake
				
			elif minor == 2 :
				
				# Adjust SoC Stepping if not from DB
				if sku_stp == 'NaN' :
					if release == 'Production' : sku_stp = 'C' # PRD (Joule_C0-X64-Release)
					else : sku_stp = 'A' # PRE, BYP
					
				platform = 'BXT' # Broxton (Joule)
					
			if minor == 0 : upd_found = True # INTEL-SA-00086
			
		elif major == 4 :
			
			if minor == 0 :
				
				# Adjust SoC Stepping if not from DB
				if sku_stp == 'NaN' :
					if release == 'Production' : sku_stp = 'B' # PRD
					else : sku_stp = 'A' # PRE, BYP
			
				platform = 'GLK'
		
		# Detected stitched PMC firmware
		if pmcp_found : pmc_chk(pmc_mn2_signed, release, -1, [-1], 'N/A', 'N/A', sku_stp, pmc_pch_rev, pmc_platform)
			
		# Get DB SKU and check for Latest status (must be after CSTXE 3 due to INTEL-SA-00086)
		sku_db,upd_found = sku_db_upd_cse('', '', sku_stp, upd_found, True)
			
	elif variant == 'SPS' : # Server Platform Services
		
		if major == 1 and not rgn_exist :
			sps1_rec_match = re.compile(br'\x45\x70\x73\x52\x65\x63\x6F\x76\x65\x72\x79').search(reading[start_man_match:]) # EpsRecovery detection
			if sps1_rec_match : fw_type = 'Recovery'
			else : fw_type = 'Operational'
		
		elif major in [2,3] :
			sps_platform = {'GR':'Grantley', 'GP':'Grantley-EP', 'GV':'Grangeville', 'DE':'Denlow', 'BR':'Bromolow', 'RO':'Romley', 'BK':'Brickland'}
			sps_type = (reading[end_man_match + 0x264:end_man_match + 0x266]).decode('utf-8') # FT (Recovery) or OP (Operational)
			
			if sps_type == 'OP' :
				if not rgn_exist : fw_type = 'Operational'
				sku = (reading[end_man_match + 0x266:end_man_match + 0x268]).decode('utf-8') # OPxx (example: OPGR --> Operational Grantley)
				sku_db = sku
				platform = sps_platform[sku] if sku in sps_platform else 'Unknown ' + sku
			
			elif sps_type == 'FT' :
				if not rgn_exist : fw_type = 'Recovery'
				rec_sku_match = re.compile(br'\x52\x32\x4F\x50......\x4F\x50', re.DOTALL).search(reading[start_man_match:start_man_match + 0x2000]) # R2OP.{6}OP detection
				if rec_sku_match :
					(start_rec_sku, end_rec_sku) = rec_sku_match.span()
					sku = (reading[start_man_match + start_rec_sku + 0x8:start_man_match + start_rec_sku + 0xA]).decode('utf-8')
					sku_db = sku
					platform = sps_platform[sku] if sku in sps_platform else 'Unknown ' + sku

	elif variant == 'CSSPS' : # Converged Security Server Platform Services
		
		# Firmware Unpacking for all CSSPS
		if param.me11_mod_extr :
			cse_unpack(variant, fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail)
			continue # Next input file
		
		# Get CSE File System Attributes & Configuration State (invokes mfs_anl, must be before ext_anl)
		mfs_state,mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final = get_mfs_anl(mfs_state, mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final, mfs_found)
		
		# Detect CSE Firmware Attributes (must be after mfs_anl)
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext32_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info,ext_iunit_val,arb_svn \
		= ext_anl(reading, '$MN2', start_man_match, file_end, [variant, major, minor, hotfix, build], None, [mfs_parsed_idx,intel_cfg_hash_mfs], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
		
		# MFS missing, determine state via FTPR > fitc.cfg (must be after mfs_anl & ext_anl)
		if mfs_state == 'Unconfigured' and oem_config : mfs_state = 'Configured'
		
		fw_0C_sku0,fw_0C_sku1,fw_0C_lbg,fw_0C_sku2 = ext12_info # Get SKU Capabilities, SKU Type, HEDT Support, SKU Platform
		
		db_sku_chk,sku,sku_stp,sku_pdm = get_cse_db(variant) # Get CSE SKU info from DB
		
		# Set PCH/SoC Stepping, if not found at DB
		if sku_stp == 'NaN' and pch_init_final : sku_stp = pch_init_final[-1][1]
		
		# Set Recovery or Operational Region Type
		if not rgn_exist :
			# Intel releases OPR as partition ($CPD) but REC as region ($FPT)
			if ext_pname == 'FTPR' : fw_type = 'Recovery' # Non-Intel POR for REC
			elif ext_pname == 'OPR' : fw_type = 'Operational' # Intel POR for OPR
		elif not ifwi_exist and not sps_opr_found :
			fw_type = 'Recovery' # Intel POR for REC ($FPT + FTPR)
			
		sku = '%d' % fw_0C_sku1 # SKU Type via Extension 12
		sku_plat = ext32_info[1] # SKU Platform via Extension 32
		sku_db = sku_plat + '_SKU' + sku
		if sku_stp != 'NaN' : sku_db += '_%s' % sku_stp
		
		if sku_plat in cssps_platform : platform = cssps_platform[sku_plat] # Chipset Platform via SKU Platform
		elif pch_init_final : platform = pch_init_final[0][0] # Chipset Platform via MFS Intel PCH Initialization Table
		else : platform = 'Unknown' # Chipset Platform is Unknown
		
		# Detected stitched PMC firmware
		if pmcp_found :
			pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,pmc_mn2_signed_db,pmcp_upd_found,pmc_platform,pmc_date,pmc_svn,pmc_pvbit = pmc_anl(pmc_mn2_ver, pmc_mod_attr)
		
		if major == 4 :
			if platform == 'Unknown' : platform = 'SPT-H' # Sunrise Point
		
		elif major == 5 :
			
			# Verify PMC compatibility
			if pmcp_found : pmc_chk(pmc_mn2_signed, release, pmc_pch_gen, [300], pmc_pch_sku, 'H', sku_stp, pmc_pch_rev, pmc_platform) 
					
			if platform == 'Unknown' : platform = 'CNP-H' # Cannon Point
	
	elif variant.startswith('PMC') : # Power Management Controller
		
		# Firmware Unpacking for all PMC
		if param.me11_mod_extr :
			cse_unpack(variant, fpt_part_all, bpdt_part_all, file_end, fpt_start if rgn_exist else -1, fpt_chk_fail)
			continue # Next input file
		
		# Detect CSE Firmware Attributes
		cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext32_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info,ext_iunit_val,arb_svn \
		= ext_anl(reading, '$CPD', 0, file_end, ['NaN', -1, -1, -1, -1], None, [[],''], param, fpt_part_all, bpdt_part_all, mfs_found, err_stor)
		
		pmc_fw_ver,pmc_pch_gen,pmc_pch_sku,pmc_pch_rev,pmc_fw_rel,pmc_mn2_signed,pmc_mn2_signed_db,upd_found,pmc_platform,pmc_date,pmc_svn,pmc_pvbit = pmc_anl(cpd_mn2_info, cpd_mod_attr)
		
		sku = pmc_pch_sku
		sku_stp = pmc_pch_rev[0]
		release = pmc_mn2_signed
		rel_db = pmc_mn2_signed_db
		sku_db = '%s_%s' % (sku, sku_stp)
		platform = pmc_platform
		fw_type = 'Independent'
		
		eng_fw_end = cpd_size_calc(reading, 0, 0x1000, file_end) # Get PMC firmware size
		
		# Check PMC firmware size
		if eng_fw_end > file_end :
			eng_size_text = [col_m + 'Warning: PMC %s firmware size exceeds file, possible data loss!' % pmc_platform + col_e, True]
		elif eng_fw_end < file_end :
			padd_size_pmc = file_end - eng_fw_end
			if reading[eng_fw_end:file_end] == padd_size_pmc * b'\xFF' :
				eng_size_text = [col_y + 'Note: File size exceeds PMC %s firmware, unneeded padding!' % pmc_platform + col_e, False] # warn_stor
			else :
				eng_size_text = [col_m + 'Warning: File size exceeds PMC %s firmware, data in padding!' % pmc_platform + col_e, True]
	
	# Partial Firmware Update adjustments
	if pr_man_8 or pr_man_9 :
		wcod_found = True
		fw_type = 'Partial Update'
		del err_stor[:]
	
	# Create Firmware Type DB entry
	fw_type, type_db = fw_types(fw_type)
	
	# Check for CSME 12+ FWUpdate Support/Compatibility
	if variant == 'CSME' and major >= 12 and not wcod_found :
		fwu_iup_check = True if type_db == 'EXTR' and sku_db.startswith('COR') else False
		if fwu_iup_check and (uncharted_start != -1 or not fwu_iup_exist) : fwu_iup_result = 'Impossible'
		else : fwu_iup_result = ['No','Yes'][int(pmcp_fwu_found)]
	
	# Create firmware DB names
	if variant in ['CSSPS','SPS'] and sku != 'NaN' :
		name_db = '%s_%s_%s_%s_%s' % (fw_ver(major,minor,hotfix,build), sku_db, rel_db, type_db, rsa_sig_hash)
		name_db_p = '%s_%s_%s_%s' % (fw_ver(major,minor,hotfix,build), sku_db, rel_db, type_db)
	elif variant == 'SPS' :
		name_db = '%s_%s_%s_%s' % (fw_ver(major,minor,hotfix,build), rel_db, type_db, rsa_sig_hash)
		name_db_p = '%s_%s_%s' % (fw_ver(major,minor,hotfix,build), rel_db, type_db)
	elif variant.startswith(('PMCAPL','PMCBXT','PMCGLK')) : # PMC APL A/B, BXT C, GLK A/B
		name_db = '%s_%s_%s_%s_%s_%s' % (pmc_platform, fw_ver(major,minor,hotfix,build), pmc_pch_rev[0], date, rel_db, rsa_sig_hash)
		name_db_p = '%s_%s_%s_%s_%s' % (pmc_platform, fw_ver(major,minor,hotfix,build), pmc_pch_rev[0], date, rel_db)
	elif variant.startswith('PMCCNP') and (major < 130 or major == 3232) : # PMC CNP A
		name_db = '%s_%s_%s_%s_%s_%s' % (pmc_platform, fw_ver(major,minor,hotfix,build), sku_db, date, rel_db, rsa_sig_hash)
		name_db_p = '%s_%s_%s_%s_%s' % (pmc_platform, fw_ver(major,minor,hotfix,build), sku_db, date, rel_db)
	elif variant.startswith('PMC') : # PMC CNP A/B, ICP, CMP
		name_db = '%s_%s_%s_%s_%s' % (pmc_platform, fw_ver(major,minor,hotfix,build), sku_db, rel_db, rsa_sig_hash)
		name_db_p = '%s_%s_%s_%s' % (pmc_platform, fw_ver(major,minor,hotfix,build), sku_db, rel_db)
	elif variant == 'CSME' and major >= 12 and type_db == 'EXTR' and sku_db.startswith('COR') :
		name_db = '%s_%s_%s_%s-%s_%s' % (fw_ver(major,minor,hotfix,build), sku_db, rel_db, type_db, ['N','Y'][int(fwu_iup_exist)], rsa_sig_hash)
		name_db_p = '%s_%s_%s_%s-%s' % (fw_ver(major,minor,hotfix,build), sku_db, rel_db, type_db, ['N','Y'][int(fwu_iup_exist)])
	else : # CS(ME) & (CS)TXE
		name_db = '%s_%s_%s_%s_%s' % (fw_ver(major,minor,hotfix,build), sku_db, rel_db, type_db, rsa_sig_hash)
		name_db_p = '%s_%s_%s_%s' % (fw_ver(major,minor,hotfix,build), sku_db, rel_db, type_db)
	
	if param.db_print_new :
		with open(os.path.join(mea_dir, 'MEA_DB_NEW.txt'), 'a', encoding = 'utf-8') as db_file : db_file.write(name_db + '\n')
		continue # Next input file
	
	# Search Database for firmware
	if not variant.startswith('PMC') and not wcod_found : # Not PMC or Partial Update
		fw_db = db_open()
		for line in fw_db :
			# Search the re-created file name without extension at the database
			if name_db in line : fw_in_db_found = True # Known firmware, nothing new
			if rsa_sig_hash in line and type_db == 'EXTR' and ('_RGN_' in line or '_EXTR-Y_' in line) :
				rgn_over_extr_found = True # Same firmware found but of preferred type (RGN > EXTR, EXTR-Y > EXTR-N), nothing new
				fw_in_db_found = True
			# For ME 6.0 IGN, (CS)ME 7+, (CS)TXE
			if rsa_sig_hash in line and type_db == 'UPD' and ((variant in ['ME','CSME'] and (major >= 7 or
			(major == 6 and 'Ignition' in sku))) or variant in ['TXE','CSTXE']) and ('_RGN_' in line or '_EXTR_' in line) :
				rgn_over_extr_found = True # Same RGN/EXTR firmware found at database, UPD disregarded
			if rsa_sig_hash in line and (variant,type_db,sku_stp) == ('CSSPS','REC','NaN') :
				fw_in_db_found = True # REC w/o $FPT are not POR for CSSPS, notify only if REC w/ $FPT does not exist
		fw_db.close()
	else :
		can_search_db = False # Do not search DB for PMC or Partial Update
	
	if can_search_db and not rgn_over_extr_found and not fw_in_db_found :
		note_stor.append([col_g + 'Note: This %s firmware was not found at the database, please report it!' % variant_p + col_e, True])
	
	# Check if firmware is updated, Production only
	if release == 'Production' and not wcod_found : # Does not display if firmware is non-Production or Partial Update
		if not variant.startswith(('SPS','CSSPS','PMCAPL','PMCBXT','PMCGLK')) : # (CS)SPS and old PMC excluded
			if upd_found : upd_rslt = col_r + 'No' + col_e
			elif not upd_found : upd_rslt = col_g + 'Yes' + col_e
	
	# Rename input file based on the DB structured name
	if param.give_db_name :
		file_name = file_in
		new_dir_name = os.path.join(os.path.dirname(file_in), name_db_p + '.bin')
		
		if not os.path.exists(new_dir_name) : os.replace(file_name, new_dir_name)
		elif os.path.basename(file_in) == name_db_p + '.bin' : pass
		else : print(col_r + 'Error: A file with the same name already exists!' + col_e)
		
		continue # Next input file
	
	# UEFI Strip Integration
	if param.extr_mea :
		print('%s %s %s %s %s' % (variant, name_db_p, fw_ver(major,minor,hotfix,build), sku_db, date))
		
		mea_exit(0)
	
	# Print Firmware Info
	elif not param.print_msg :
		print()
		msg_pt = ext_table(['Field', 'Value'], False, 1)
		msg_pt.title = col_c + '%s (%d/%d)' % (os.path.basename(file_in)[:45], cur_count, in_count) + col_e
		
		msg_pt.add_row(['Family', variant_p])
		msg_pt.add_row(['Version', fw_ver(major,minor,hotfix,build)])
		msg_pt.add_row(['Release', release + ', Engineering ' if build >= 7000 else release])
		msg_pt.add_row(['Type', fw_type])
		
		if (variant == 'CSTXE' and 'Unknown' not in sku) or (variant,sku) == ('SPS','NaN') or wcod_found \
		or variant.startswith(('PMCAPL','PMCBXT','PMCGLK')) :
			pass
		else :
			msg_pt.add_row(['SKU', sku])
		
		if variant.startswith(('CS','PMC')) and not wcod_found :
			if sku_stp == 'NaN' : msg_pt.add_row(['Chipset', 'Unknown'])
			elif pch_init_final : msg_pt.add_row(['Chipset', pch_init_final[-1][0]])
			else : msg_pt.add_row(['Chipset Stepping', ', '.join(map(str, list(sku_stp)))])
		
		if ((variant in ['ME','CSME'] and major >= 8) or variant in ['TXE','CSTXE','CSSPS'] or variant.startswith('PMC')) and not wcod_found :
			msg_pt.add_row(['%sSecurity Version Number' % ('TCB ' if arb_svn != -1 else ''), svn])
			
		if arb_svn != -1 and not wcod_found : msg_pt.add_row(['ARB Security Version Number', arb_svn])
			
		if ((variant in ['ME','CSME'] and major >= 8) or variant in ['TXE','CSTXE','CSSPS'] or variant.startswith('PMC')) and not wcod_found :
			msg_pt.add_row(['Version Control Number', vcn])
		
		if pvbit in [0,1] and wcod_found is False : msg_pt.add_row(['Production Ready', ['No','Yes'][pvbit]])
		
		if [variant,major,wcod_found] == ['CSME',11,False] :
			if pdm_status != 'NaN' : msg_pt.add_row(['Power Down Mitigation', pdm_status])
			msg_pt.add_row(['Lewisburg PCH Support', ['No','Yes'][fw_0C_lbg]])
			
		if variant == 'ME' and major == 7 : msg_pt.add_row(['Patsburg PCH Support', ['No','Yes'][is_patsburg]])
			
		if variant in ('CSME','CSTXE','CSSPS') and not wcod_found : msg_pt.add_row(['OEM RSA Signature', ['No','Yes'][int(oem_signed or oemp_found)]])
			
		if (rgn_exist or ifwi_exist) and variant in ('CSME','CSTXE','CSSPS','TXE') : msg_pt.add_row(['OEM Unlock Token', ['No','Yes'][int(utok_found)]])
		
		if variant == 'CSME' and major >= 12 and not wcod_found : msg_pt.add_row(['FWUpdate Support', fwu_iup_result])
		
		msg_pt.add_row(['Date', date])

		if variant in ('CSME','CSTXE','CSSPS') and not wcod_found : msg_pt.add_row(['File System State', mfs_state])
		
		if rgn_exist or variant.startswith('PMC') :
			if (variant,major,release) == ('ME',6,'ROM-Bypass') : msg_pt.add_row(['Size', 'Unknown'])
			elif (variant,fd_devexp_rgn_exist) == ('CSTXE',True) : pass
			else : msg_pt.add_row(['Size', '0x%X' % eng_fw_end])
		
		if fitc_ver_found :
			msg_pt.add_row(['Flash Image Tool', fw_ver(fitc_major,fitc_minor,fitc_hotfix,fitc_build)])
		
		if (variant,major) == ('ME',7) :
			msg_pt.add_row(['Downgrade Blacklist 7.0', me7_blist_1])
			msg_pt.add_row(['Downgrade Blacklist 7.1', me7_blist_2])
		
		if platform != 'NaN' : msg_pt.add_row(['Chipset Support', platform]) 
		
		if variant not in ['SPS','CSSPS'] and upd_rslt != '' : msg_pt.add_row(['Latest', upd_rslt])
		
		print(msg_pt)
		
		if param.write_html :
			with open('%s.html' % os.path.basename(file_in), 'w') as o : o.write('\n<br/>\n%s' % pt_html(msg_pt))
		
		if param.write_json :
			with open('%s.json' % os.path.basename(file_in), 'w') as o : o.write('\n%s' % pt_json(msg_pt))
		
		if pmcp_found :
			msg_pmc_pt = ext_table(['Field', 'Value'], False, 1)
			msg_pmc_pt.title = 'Power Management Controller'
			
			msg_pmc_pt.add_row(['Family', 'PMC'])
			msg_pmc_pt.add_row(['Version', pmc_fw_ver])
			msg_pmc_pt.add_row(['Release', pmc_mn2_signed + ', Engineering ' if pmc_fw_rel >= 7000 else pmc_mn2_signed])
			msg_pmc_pt.add_row(['Type', 'Independent'])
			if (variant == 'CSME' and major >= 12) or (variant == 'CSSPS' and major >= 5) or not pmc_platform.startswith(('APL','BXT','GLK')) :
				msg_pmc_pt.add_row(['Chipset SKU', pmc_pch_sku])
			msg_pmc_pt.add_row(['Chipset Stepping', pmc_pch_rev[0]])
			msg_pmc_pt.add_row(['TCB Security Version Number', pmc_svn])
			msg_pmc_pt.add_row(['ARB Security Version Number', pmc_arb_svn])
			msg_pmc_pt.add_row(['Version Control Number', pmc_vcn])
			if pmc_pvbit in [0,1] : msg_pmc_pt.add_row(['Production Ready', ['No','Yes'][pmc_pvbit]])
			msg_pmc_pt.add_row(['Date', pmc_date])
			msg_pmc_pt.add_row(['Size', '0x%X' % pmcp_size])
			msg_pmc_pt.add_row(['Chipset Support', pmc_platform])
			if pmc_mn2_signed == 'Production' and (variant == 'CSME' and major >= 12) :
				msg_pmc_pt.add_row(['Latest', [col_g + 'Yes' + col_e, col_r + 'No' + col_e][pmcp_upd_found]])
			
			print(msg_pmc_pt)
			
			if param.write_html :
				with open('%s.html' % os.path.basename(file_in), 'a') as o : o.write('\n<br/>\n%s' % pt_html(msg_pmc_pt))
				
			if param.write_json :
				with open('%s.json' % os.path.basename(file_in), 'a') as o : o.write('\n%s' % pt_json(msg_pmc_pt))
	
	# Print Messages which must be at the end of analysis
	if eng_size_text != ['', False] : warn_stor.append(['%s' % eng_size_text[0], eng_size_text[1]])
	
	if fwu_iup_result == 'Impossible' and uncharted_start != -1 :
		fwu_iup_msg = (uncharted_start,p_end_last_back,p_end_last_back + uncharted_start)
		warn_stor.append([col_m + 'Warning: Remove 0x%X padding from 0x%X - 0x%X for FWUpdate Support!' % fwu_iup_msg + col_e, False])
	
	if fpt_count > 1 : note_stor.append([col_y + 'Note: Multiple (%d) Intel Engine firmware detected!' % fpt_count + col_e, True])
	
	if fd_count > 1 : note_stor.append([col_y + 'Note: Multiple (%d) Intel Flash Descriptors detected!' % fd_count + col_e, True])
	
	# Print Error/Warning/Note Messages
	msg_stor = err_stor + warn_stor + note_stor
	for msg_idx in range(len(msg_stor)) :
		print('\n' + msg_stor[msg_idx][0])
		if param.write_html :
			with open('%s.html' % os.path.basename(file_in), 'a') as o : o.write('\n<p>%s</p>' % ansi_escape.sub('', str(msg_stor[msg_idx][0])))
		if param.write_json :
			msg_entries['Entry %0.4d' % msg_idx] = ansi_escape.sub('', str(msg_stor[msg_idx][0]))
	
	if param.write_json :
		msg_dict['Messages'] = msg_entries
		with open('%s.json' % os.path.basename(file_in), 'a') as o : o.write('\n%s' % json.dumps(msg_dict, indent=4))
	
	# Close input and copy it in case of messages
	if not param.extr_mea : copy_on_msg()
	
	# Show MEA help screen only once
	if param.help_scr : mea_exit(0)
	
mea_exit(0)
