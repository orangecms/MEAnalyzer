import ctypes
import json

from BPDT import *
from CPD import *
from FPT import *
from MN2 import *

# Process ctypes Structure Classes
def get_struct(input_stream, start_offset, class_name, file_end, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = input_stream[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= file_end) or (fit_len < struct_len) :
		err_stor.append([col_r + 'Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name) + col_e, True])
		
		for error in err_stor : print('\n' + error[0])
		
		if not param.extr_mea : copy_on_msg() # Close input and copy it in case of messages
		
		mea_exit(1)
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure
	
# https://stackoverflow.com/a/34301571
# noinspection PyProtectedMember
def struct_json(structure) :
	result = {}
	
	def get_value(value) :
		if (type(value) not in [int, float, bool, str]) and not bool(value) :
			value = None # Null Pointer (not primitive type, is False)
		elif hasattr(value, '_length_') and hasattr(value, '_type_') :
			value = get_array(value) # Probably an Array
		elif isinstance(value, (bytes, bytearray)) :
			value = value.decode('utf-8') # Byte
		elif hasattr(value, '_fields_') :
			value = struct_json(value) # Probably nested struct
		
		return value
	
	def get_array(array) :
		ar = []
		for value in array :
			value = get_value(value)
			ar.append(value)
		
		return ar
	
	for field in structure._fields_ :
		value = get_value(getattr(structure, field[0]))
		result[field[0]] = value
	
	return json.dumps(result, indent=4)
	
# Get Engine Manifest Structure
def get_manifest(buffer, offset, variant) :
	man_ver = int.from_bytes(buffer[offset + 0x8:offset + 0xC], 'little') # $MAN/$MN2 Version Tag
	
	if man_ver == 0x10000 and variant in ('ME','TXE','SPS','Unknown') : return MN2_Manifest_R0
	elif man_ver == 0x10000 : return MN2_Manifest_R1
	elif man_ver == 0x21000 : return MN2_Manifest_R2
	else : return MN2_Manifest_R2
	
# Get Flash Partition Table Structure
def get_fpt(buffer, offset) :
	fpt_ver = buffer[offset + 0x8] # $FPT Version Tag
	
	if fpt_ver in (0x10,0x20) : return FPT_Header
	elif fpt_ver == 0x21 : return FPT_Header_21
	else : return FPT_Header_21
	
# Get Code Partition Directory Structure	
def get_cpd(buffer, offset) :
	cpd_ver = buffer[offset + 0x8] # $CPD Version Tag
	
	if cpd_ver == 1 : return CPD_Header_R1, ctypes.sizeof(CPD_Header_R1)
	elif cpd_ver == 2 : return CPD_Header_R2, ctypes.sizeof(CPD_Header_R2)
	else : return CPD_Header_R2, ctypes.sizeof(CPD_Header_R2)
	
# Get Code Partition Directory Structure	
def get_bpdt(buffer, offset) :
	bpdt_ver = buffer[offset + 0x6] # BPDT Version Tag
	
	if bpdt_ver == 1 : return BPDT_Header_1
	elif bpdt_ver == 2 : return BPDT_Header_2
	else : return BPDT_Header_2
