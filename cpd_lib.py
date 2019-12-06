from struct_lib import *

# Get correct $CPD Entry Counter for end offset detection
def cpd_entry_num_fix(buffer, cpd_offset, cpd_entry_count, cpd_hdr_size) :
	cpd_entry_empty = 0
	cpd_entry_end = cpd_offset + cpd_hdr_size + cpd_entry_count * 0x18
	
	# Some $CPD may have X entries + empty Y. Try to adjust counter a maximum of 5 times (GREAT WORK INTEL/OEMs...)
	while int.from_bytes(buffer[cpd_entry_end:cpd_entry_end + 0x18], 'little') == 0 :
		cpd_entry_end += 0x18
		cpd_entry_empty += 1
		if cpd_entry_empty > 5 :
			err_stor.append([col_r + 'Error: Failed to fix $CPD entry counter at 0x%X!' % cpd_offset + col_e, True])
			break
		
	return cpd_entry_count + cpd_entry_empty
	
# Calculate $CPD Partition size via its Entries
def cpd_size_calc(buffer, cpd_offset, align_size, file_end):
	cpd_fw_end = 0
	cpd_offset_last = 0
	
	cpd_hdr_struct, cpd_hdr_size = get_cpd(buffer, cpd_offset)
	cpd_hdr = get_struct(buffer, cpd_offset, cpd_hdr_struct, file_end)
	cpd_num = cpd_entry_num_fix(buffer, cpd_offset, cpd_hdr.NumModules, cpd_hdr_size)
	
	for entry in range(1, cpd_num, 2) : # Skip 1st .man module, check only .met
		cpd_entry_hdr = get_struct(buffer, cpd_offset + cpd_hdr_size + entry * 0x18, CPD_Entry, file_end)
		cpd_mod_off,cpd_mod_huff,cpd_mod_res = cpd_entry_hdr.get_flags()
		
		cpd_entry_name = cpd_entry_hdr.Name
		
		if b'.met' not in cpd_entry_name and b'.man' not in cpd_entry_name : # Sanity check
			cpd_entry_offset = cpd_mod_off
			cpd_entry_size = cpd_entry_hdr.Size
			
			# Store last entry (max $CPD offset)
			if cpd_entry_offset > cpd_offset_last :
				cpd_offset_last = cpd_entry_offset
				cpd_fw_end = cpd_entry_offset + cpd_entry_size
		else :
			break # nested "for" loop
		
	cpd_align = (cpd_fw_end - cpd_offset) % align_size
	cpd_fw_end = cpd_fw_end + align_size - cpd_align
	
	return cpd_fw_end
	
# Validate $CPD Checksum
def cpd_chk(cpd_data) :
	cpd_hdr_struct, cpd_hdr_size = get_cpd(cpd_data, 0)
	
	if cpd_hdr_struct.__name__ == 'CPD_Header_R1' :
		cpd_chk_file = cpd_data[0xB]
		cpd_sum = sum(cpd_data) - cpd_chk_file
		cpd_chk_calc = (0x100 - cpd_sum & 0xFF) & 0xFF
	elif cpd_hdr_struct.__name__ == 'CPD_Header_R2' :
		cpd_chk_file = int.from_bytes(cpd_data[0x10:0x14], 'little')
		cpd_chk_calc = zlib.crc32(cpd_data[:0x10] + b'\x00' * 4 + cpd_data[0x14:]) & 0xFFFFFFFF
	else :
		cpd_chk_file = int.from_bytes(cpd_data[0x10:0x14], 'little')
		cpd_chk_calc = zlib.crc32(cpd_data[:0x10] + b'\x00' * 4 + cpd_data[0x14:]) & 0xFFFFFFFF
	
	return cpd_chk_file == cpd_chk_calc, cpd_chk_file, cpd_chk_calc
