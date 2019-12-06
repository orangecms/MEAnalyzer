from CSE import *

from cpd_lib import *
from hash_lib import *
from struct_lib import *

# Analyze CSE Extensions
# noinspection PyUnusedLocal
def ext_anl(buffer, input_type, input_offset, file_end, ftpr_var_ver, single_man_name, mfs_idx_cfg, param, fpt_part_all, bpdt_part_all, mfs_found):
	vcn = -1
	in_id = 0
	cpd_num = 0
	arb_svn = -1
	mn2_size = -1
	ext_psize = -1
	mea_phash = -1
	fw_0C_lbg = -1
	fw_0C_sku1 = -1
	fw_0C_sku2 = -1
	cpd_offset = -1
	mn2_offset = -1
	dnx_version = -1
	dnx_rcip_off = -1
	dnx_rcip_len = -1
	cpd_hdr_size = -1
	end_man_match = -1
	start_man_match = -1
	dnx_hash_arr_off = -1
	iunit_chunk_start = -1
	hash_arr_valid_count = 0
	chunk_hash_valid_count = 0
	cpd_hdr = None
	mn2_hdr = None
	utfl_hdr = None
	msg_shown = False
	cpd_valid = False
	oem_config = False
	oem_signed = False
	intel_cfg_ftpr = False
	cpd_name = ''
	ext_pname = ''
	ibbp_all = []
	ibbp_del = []
	ext_print = []
	cpd_ext_hash = []
	cpd_mod_attr = []
	cpd_ext_attr = []
	cpd_mn2_info = []
	cpd_mod_names = []
	cpd_ext_names = []
	mn2_hdr_print = []
	cpd_wo_met_info = []
	cpd_wo_met_back = []
	iunit_chunk_valid = []
	intel_cfg_hash_ftpr = []
	ext32_info = ['UNK', 'XX']
	fptemp_info = [False, -1, -1]
	ibbp_bpm = ['IBBL', 'IBB', 'OBB']
	ext12_info = ['00000000', 'NA', 0, 'NA'] # SKU Capabilities, SKU Type, LBG Support, SKU Platform
	ext_dnx_val = [-1, False, False] # [DnXVer, AllHashArrValid, AllChunkValid]
	ext_iunit_val = [False] # [AllChunkValid]
	ext_phval = [False, False, 0, 0]
	mn2_sigs = [False, -1, -1, True, -1, None]
	variant,major,minor,hotfix,build = ftpr_var_ver
	mfs_parsed_idx,intel_cfg_hash_mfs = mfs_idx_cfg
	buffer_len = len(buffer)
	
	if input_type.startswith('$MN2') :
		start_man_match = input_offset
		end_man_match = start_man_match + 0x5 # .$MN2
		
		# Scan backwards for $CPD (max $CPD size = 0x2000, .$MN2 Tag starts at 0x1B, works with both RGN --> $FPT & UPD --> 0x0)
		for offset in range(start_man_match + 2, start_man_match + 2 - 0x201D, -4) : # Search from MN2 (no .$) to find CPD (no $) at 1, before loop break at 0
			if b'$CPD' in buffer[offset - 1:offset - 1 + 4] :
				cpd_offset = offset - 1 # Adjust $CPD to 0 (offset - 1 = 1 - 1 = 0)
				break # Stop at first detected $CPD
	
	elif input_type.startswith('$CPD') :
		cpd_offset = input_offset
		
		# Scan forward for .$MN2 (max $CPD size = 0x2000, .$MN2 Tag ends at 0x20, works with both RGN --> $FPT & UPD --> 0x0)
		mn2_pat = re.compile(br'\x00\x24\x4D\x4E\x32').search(buffer[cpd_offset:cpd_offset + 0x2020]) # .$MN2 detection, 0x00 for extra sanity check
		if mn2_pat is not None :
			(start_man_match, end_man_match) = mn2_pat.span()
			start_man_match += cpd_offset
			end_man_match += cpd_offset
	
	# $MN2 existence not mandatory
	if start_man_match != -1 :
		mn2_hdr = get_struct(buffer, start_man_match - 0x1B, get_manifest(buffer, start_man_match - 0x1B, variant), file_end)
		
		if mn2_hdr.Tag == b'$MN2' : # Sanity Check (also UTOK w/o Manifest)
			mn2_offset = start_man_match - 0x1B # $MN2 Manifest Offset
			mn2_size = mn2_hdr.Size * 4 # $MN2 Manifest Size
			mn2_date = '%0.4X-%0.2X-%0.2X' % (mn2_hdr.Year,mn2_hdr.Month,mn2_hdr.Day)
			mn2_hdr_print = mn2_hdr.hdr_print_cse()
			
			mn2_rsa_block_off = end_man_match + 0x60 # RSA Block Offset
			mn2_rsa_key_len = mn2_hdr.PublicKeySize * 4 # RSA Key/Signature Length
			mn2_rsa_exp_len = mn2_hdr.ExponentSize * 4 # RSA Exponent Length
			mn2_rsa_key = buffer[mn2_rsa_block_off:mn2_rsa_block_off + mn2_rsa_key_len] # RSA Public Key
			mn2_rsa_key_hash = get_hash(mn2_rsa_key, 0x20) # SHA-256 of RSA Public Key
			mn2_rsa_sig = buffer[mn2_rsa_block_off + mn2_rsa_key_len + mn2_rsa_exp_len:mn2_rsa_block_off + mn2_rsa_key_len * 2 + mn2_rsa_exp_len] # RSA Signature
			mn2_rsa_sig_hash = get_hash(mn2_rsa_sig, 0x20) # SHA-256 of RSA Signature
			
			mn2_flags_pvbit,mn2_flags_reserved,mn2_flags_pre,mn2_flags_debug = mn2_hdr.get_flags()
			
			cpd_mn2_info = [mn2_hdr.Major, mn2_hdr.Minor, mn2_hdr.Hotfix, mn2_hdr.Build, ['Production','Debug'][mn2_flags_debug],
							mn2_rsa_key_hash, mn2_rsa_sig_hash, mn2_date, mn2_hdr.SVN, mn2_flags_pvbit]
		
			if param.me11_mod_extr : mn2_sigs = rsa_sig_val(mn2_hdr, buffer, start_man_match - 0x1B) # For each Partition
		else :
			mn2_hdr = None
			start_man_match = -1
	
	# $CPD detected
	if cpd_offset > -1 :
		cpd_hdr_struct, cpd_hdr_size = get_cpd(buffer, cpd_offset)
		cpd_hdr = get_struct(buffer, cpd_offset, cpd_hdr_struct, file_end)
		cpd_num = cpd_entry_num_fix(buffer, cpd_offset, cpd_hdr.NumModules, cpd_hdr_size)
		cpd_name = cpd_hdr.PartitionName.decode('utf-8')
		
		# Validate $CPD Checksum, skip at special _Stage1 mode (Variant/fptemp) to not see duplicate messages
		if not input_type.endswith('_Stage1') :
			cpd_valid,cpd_chk_fw,cpd_chk_exp = cpd_chk(buffer[cpd_offset:cpd_offset + cpd_hdr_size + cpd_num * 0x18])
			
			if not cpd_valid :
				cse_anl_err(col_r + 'Error: Wrong $CPD "%s" Checksum 0x%0.2X, expected 0x%0.2X' % (cpd_name, cpd_chk_fw, cpd_chk_exp) + col_e, None)
		
		# Stage 1: Store $CPD Entry names to detect Partition attributes for MEA
		for entry in range(0, cpd_num) :
			cpd_entry_hdr = get_struct(buffer, cpd_offset + cpd_hdr_size + entry * 0x18, CPD_Entry, file_end)
			cpd_entry_name = cpd_entry_hdr.Name.decode('utf-8')
			cpd_mod_names.append(cpd_entry_name) # Store each $CPD Module name
			cpd_entry_size = cpd_entry_hdr.Size # Uncompressed only
			cpd_entry_res0 = cpd_entry_hdr.Reserved
			cpd_entry_offset,cpd_entry_huff,cpd_entry_res1 = cpd_entry_hdr.get_flags()
			
			# Detect if FTPR Partition is FWUpdate-customized to skip potential $FPT false positive at fptemp module
			if cpd_entry_name == 'fptemp' and (cpd_entry_offset,cpd_entry_size) != (0,0) and not (cpd_offset + cpd_entry_offset >= file_end
			or buffer[cpd_offset + cpd_entry_offset:cpd_offset + cpd_entry_offset + cpd_entry_size] == b'\xFF' * cpd_entry_size) : # FWUpdate -save (fptemp not empty)
				fptemp_info = [True, cpd_offset + cpd_entry_offset, cpd_offset + cpd_entry_offset + cpd_entry_size]
			
			# Gathered any info for special _Stage1 mode (cpd_mod_names, fptemp_info)
			if input_type.endswith('_Stage1') : continue
			
			# Check if $CPD Entry Reserved field is zero, skip at special _Stage1 mode
			if (cpd_entry_res0,cpd_entry_res1) != (0,0) and not input_type.endswith('_Stage1') :
				cse_anl_err(col_m + 'Warning: Detected $CPD Entry with non-zero Reserved field at %s > %s' % (cpd_name, cpd_entry_name) + col_e, None)
			
			cpd_wo_met_info.append([cpd_entry_name,cpd_entry_offset,cpd_entry_size,cpd_entry_huff,cpd_entry_res0,cpd_entry_res1])
		
			# Detect if FTPR Partition includes MFS Intel Configuration (intl.cfg) to validate FTPR Extension 0x00 Hash at Stage 2
			# The FTPR intl.cfg Hash is stored separately from $FPT MFS Low Level File 6 Hash to validate both at Stage 2 (CSTXE, CSME 12 Alpha)
			if cpd_entry_name == 'intl.cfg' and (cpd_entry_offset,cpd_entry_size) != (0,0) :
				intel_cfg_ftpr = True # Detected FTPR > intl.cfg module
				intel_cfg_data = buffer[cpd_offset + cpd_entry_offset:cpd_offset + cpd_entry_offset + cpd_entry_size] # FTPR > intl.cfg Contents
				intel_cfg_hash_ftpr = [get_hash(intel_cfg_data, 0x20), get_hash(intel_cfg_data, 0x30)] # Store FTPR MFS Intel Configuration Hashes
		
			# Detect if FTPR Partition is FIT/OEM-customized to skip Hash check at Stages 2 & 4
			if cpd_entry_name == 'fitc.cfg' and (cpd_entry_offset,cpd_entry_size) != (0,0) : # FIT OEM Configuration
				oem_config = True
			if cpd_entry_name == 'oem.key' and (cpd_entry_offset,cpd_entry_size) != (0,0) : # OEM RSA Signature
				oem_signed = True
			
			# Detect Recovery Image Partition (RCIP)
			if cpd_name == 'RCIP' :
				dnx_entry_off, x1, x2 = cpd_entry_hdr.get_flags()
				
				# Get DNX R1/R2 version
				if cpd_entry_name == 'version' : dnx_version = int.from_bytes(buffer[cpd_offset + dnx_entry_off:cpd_offset + dnx_entry_off + 0x4], 'little')
				
				# Get DNX R2 Hash Array offset
				elif cpd_entry_name == 'hash.array' : dnx_hash_arr_off = cpd_offset + dnx_entry_off
				
				# Get DNX R1/R2 RCIP IFWI offset
				elif cpd_entry_name == 'rcipifwi' :
					dnx_rcip_off = cpd_offset + dnx_entry_off
					dnx_rcip_len = cpd_entry_size # RCIP IFWI is uncompressed
		
		# Return only $CPD Module Names & fptemp info for special _Stage1 mode
		if input_type.endswith('_Stage1') : return cpd_mod_names, fptemp_info
	
		# Sort $CPD Entry Info based on Offset in ascending order
		cpd_wo_met_info = sorted(cpd_wo_met_info, key=lambda entry: entry[1])
		cpd_wo_met_back = cpd_wo_met_info # Backup for adjustments validation
	
	# $CPD not found but special _Stage1 mode requires it, return null info
	elif input_type.endswith('_Stage1') : return cpd_mod_names, fptemp_info
	
	# Stage 2: Analyze Manifest & Metadata (must be before Module analysis)
	# Set cpd_num = 1 to analyze single $MN2 w/o $CPD (CSSPS MFS Low Level File 9)
	for entry in range(0, 1 if single_man_name else cpd_num) :
		# Variable Initialization based on Single Manifest existence
		if not single_man_name :
			cpd_entry_hdr = get_struct(buffer, cpd_offset + cpd_hdr_size + entry * 0x18, CPD_Entry, file_end)
			cpd_mod_off,cpd_mod_huff,cpd_mod_res = cpd_entry_hdr.get_flags()
			
			cpd_entry_offset = cpd_offset + cpd_mod_off
			cpd_entry_size = cpd_entry_hdr.Size # Uncompressed only
			cpd_entry_name = cpd_entry_hdr.Name
		else :
			cpd_offset = 0
			cpd_name = single_man_name
			cpd_entry_offset = 0
			cpd_entry_size = mn2_size
			cpd_entry_name = bytes(single_man_name, 'utf-8')
			dnx_rcip_off = 0
			dnx_rcip_len = 0
			cpd_valid = True
			
		ext_print_temp = []
		cpd_ext_offset = 0
		loop_break = 0
		entry_empty = 0
		
		if b'.man' in cpd_entry_name or b'.met' in cpd_entry_name or (single_man_name and start_man_match != -1) :
			# Set initial CSE Extension Offset
			if (b'.man' in cpd_entry_name or single_man_name) and start_man_match != -1 :
				cpd_ext_offset = cpd_entry_offset + mn2_hdr.HeaderLength * 4 # Skip $MN2 at .man
			elif b'.met' in cpd_entry_name :
				cpd_ext_offset = cpd_entry_offset # Metadata is always Uncompressed
			
			# Analyze all Manifest & Metadata Extensions
			ext_tag = int.from_bytes(buffer[cpd_ext_offset:cpd_ext_offset + 0x4], 'little') # Initial Extension Tag
			
			ext_print.append(cpd_entry_name.decode('utf-8')) # Store Manifest/Metadata name
			
			while True : # Parse all CSE Extensions and break at Manifest/Metadata end
				
				# Break loop just in case it becomes infinite
				loop_break += 1
				if loop_break > 100 :
					cse_anl_err(col_r + 'Error: Forced CSE Extension Analysis break after 100 loops at %s > %s!' % (cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					break
				
				# Determine if Entry is Empty/Missing
				entry_data = buffer[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
				if entry_data == b'\xFF' * cpd_entry_size or cpd_entry_offset >= file_end : entry_empty = 1
				
				# Determine Extension Size & End Offset
				cpd_ext_size = int.from_bytes(buffer[cpd_ext_offset + 0x4:cpd_ext_offset + 0x8], 'little')
				cpd_ext_end = cpd_ext_offset + cpd_ext_size
				
				# Detect unknown CSE Extension & notify user
				if ext_tag not in ext_tag_all :
					cse_anl_err(col_r + 'Error: Detected unknown CSE Extension 0x%0.2X at %s > %s!\n       Some modules may not be detected without adding 0x%0.2X support!'
					% (ext_tag, cpd_name, cpd_entry_name.decode('utf-8'), ext_tag) + col_e, None)
				
				# Detect CSE Extension data overflow & notify user
				if entry_empty == 0 and (cpd_ext_end > cpd_entry_offset + cpd_entry_size) : # Manifest/Metadata Entry overflow
					cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X data overflow at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
				
				hdr_rev_tag = '' # CSE Extension Header Revision Tag
				mod_rev_tag = '' # CSE Extension Module Revision Tag
				
				#variant,major = ('CSME',15) # TGP Debug/Research
				
				if (variant,major) == ('CSME',15) :
					if ext_tag in ext_tag_rev_hdr_csme15 : hdr_rev_tag = ext_tag_rev_hdr_csme15[ext_tag]
					if ext_tag in ext_tag_rev_mod_csme15 : mod_rev_tag = ext_tag_rev_mod_csme15[ext_tag]
				elif (variant,major) in [('CSME',13), ('CSME',14)] or ((variant,major) == ('CSME',12) and not ((minor,hotfix) == (0,0) and build >= 7000 and year < 0x2018)) or dnx_version == 2 :
					if ext_tag in ext_tag_rev_hdr_csme12 : hdr_rev_tag = ext_tag_rev_hdr_csme12[ext_tag]
					if ext_tag in ext_tag_rev_mod_csme12 : mod_rev_tag = ext_tag_rev_mod_csme12[ext_tag]
				elif (variant,major,minor) == ('CSSPS',5,0) and hotfix in (0,1,2,3) :
					if ext_tag in ext_tag_rev_hdr_cssps503 : hdr_rev_tag = ext_tag_rev_hdr_cssps503[ext_tag]
					if ext_tag in ext_tag_rev_mod_cssps503 : mod_rev_tag = ext_tag_rev_mod_cssps503[ext_tag]
				elif (variant,major) == ('CSSPS',5) :
					if ext_tag in ext_tag_rev_hdr_cssps5 : hdr_rev_tag = ext_tag_rev_hdr_cssps5[ext_tag]
					if ext_tag in ext_tag_rev_mod_cssps5 : mod_rev_tag = ext_tag_rev_mod_cssps5[ext_tag]
				else :
					pass # These CSE use the original Header/Module Structures
				
				ext_dict_name = 'CSE_Ext_%0.2X%s' % (ext_tag, hdr_rev_tag)
				ext_struct_name = ext_dict[ext_dict_name] if ext_dict_name in ext_dict else None
				ext_dict_mod = 'CSE_Ext_%0.2X_Mod%s' % (ext_tag, mod_rev_tag)
				ext_struct_mod = ext_dict[ext_dict_mod] if ext_dict_mod in ext_dict else None
				
				# Analyze Manifest/Metadata Extension Info
				if param.me11_mod_extr :
					if ext_dict_name in ext_dict :
						ext_length = ctypes.sizeof(ext_struct_name)
						
						# Detect CSE Extension without Modules different size & notify user
						if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
							cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
						
						if ext_tag == 0xC : # CSE_Ext_0C requires Variant & Version input
							ext_hdr_p = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end, ftpr_var_ver)
						else :
							ext_hdr_p = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
						
						ext_print_temp.append(ext_hdr_p.ext_print())
						
						if ext_tag == 0x14 and dnx_version == 1 : # CSE_Ext_14 Revision 1 (R1) has a unique structure
							# For CSE_Ext_14_R1, all the processing is done at the Manifest Analysis level. All validation results
							# are transfered to mod_anl via ext_dnx_val list so that they can be displayed in logical -unp86 order.
							
							ext_dnx_val[0] = dnx_version # DnX Version 1 (R1)
							ifwi_rgn_hdr_step = 0 # Step to loop through IFWI Region Maps
							rcip_chunk_size = ext_hdr_p.ChunkSize # RCIP IFWI Chunk Size
							rcip_chunk_count_ext = ext_hdr_p.ChunkCount # RCIP IFWI Chunk Count from Extension
							rcip_chunk_count_mea = int(dnx_rcip_len / rcip_chunk_size) # RCIP IFWI Chunk Count from MEA
							ifwi_rgn_count = ext_hdr_p.IFWIRegionCount # IFWI Region Count (eMMC/UFS)
							
							# Check if RCIP length is divisible by RCIP Chunk length and if RCIP Chunk count from EXT is the same as MEA's
							if (dnx_rcip_len % rcip_chunk_size != 0) or (rcip_chunk_count_ext != rcip_chunk_count_mea) :
								cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
							
							# Parse each IFWI Region Map
							for region in range(ifwi_rgn_count) :
								ifwi_rgn_map = get_struct(buffer, cpd_ext_offset + ext_length + ifwi_rgn_hdr_step, CSE_Ext_14_RegionMap, file_end)
								ext_print_temp.append(ifwi_rgn_map.ext_print())
								
								ifwi_rgn_hdr_step += ctypes.sizeof(CSE_Ext_14_RegionMap)
							
							# Parse each RCIP IFWI Chunk
							for chunk in range(rcip_chunk_count_ext) :
								rcip_chunk_off = dnx_rcip_off + chunk * rcip_chunk_size
								chunk_hash_off = cpd_ext_offset + ext_length + ifwi_rgn_hdr_step + chunk * 0x20
								
								rcip_chunk_hash = get_hash(buffer[rcip_chunk_off:rcip_chunk_off + rcip_chunk_size], 0x20) # SHA-256
								ext_chunk_hash = format(int.from_bytes(buffer[chunk_hash_off:chunk_hash_off + 0x20], 'little'), '064X')
								
								# Check if Extension Chunk Hash is equal to RCIP IFWI Chunk Hash
								if ext_chunk_hash == rcip_chunk_hash : chunk_hash_valid_count += 1
								
								pt_14_R2 = ext_table(['Field', 'Value'], False, 1)
								pt_14_R2.title = col_y + 'Extension 20 R1 Chunk %d/%d' % (chunk + 1, rcip_chunk_count_ext) + col_e
								pt_14_R2.add_row(['Chunk EXT Hash', ext_chunk_hash])
								pt_14_R2.add_row(['Chunk MEA Hash', rcip_chunk_hash])
								
								ext_print_temp.append(pt_14_R2)
								
							# Check if all Extension Chunk Hashes and RCIP IFWI Chunk Hashes are Valid
							if chunk_hash_valid_count == rcip_chunk_count_ext : ext_dnx_val[2] = True
							
						if ext_tag == 0x14 and dnx_version in (2,3) : # CSE_Ext_14 Revision 2-3 (R2-R3) have a unique structure
							# For CSE_Ext_14_R2, all the processing is done at the Manifest Analysis level. All validation results
							# are transfered to mod_anl via ext_dnx_val list so that they can be displayed in logical -unp86 order.
							
							ext_dnx_val[0] = dnx_version # DnX Version 2 (R2)
							ifwi_rgn_hdr_step = 0 # Step to loop through IFWI Region Maps
							hash_arr_hdr_step = 0 # Step to loop through Hashes Array Headers
							hash_arr_prev_part_size = 0 # Step to loop through Hashes Array file sections
							hash_arr_hdr_count = ext_hdr_p.HashArrHdrCount # Hashes Array Header Count
							chunk_hash_size = ext_hdr_p.ChunkHashSize # Hashes Array Chunk Hash Size
							rcip_chunk_size = ext_hdr_p.ChunkSize # RCIP IFWI Chunk Size
							rcip_chunk_count = int(dnx_rcip_len / rcip_chunk_size) # RCIP IFWI Chunk Count
							ifwi_rgn_count = ext_hdr_p.IFWIRegionCount # IFWI Region Count (eMMC/UFS)
							
							# Parse each Hashes Array Header
							for header in range(hash_arr_hdr_count) :
								hash_arr_part_struct = CSE_Ext_14_HashArray if dnx_version == 2 else CSE_Ext_14_HashArray_R2
								hash_arr_part_hdr = get_struct(buffer, cpd_ext_offset + ext_length + hash_arr_hdr_step, hash_arr_part_struct, file_end)
								hash_arr_part_size = hash_arr_part_hdr.HashArrSize * 4 # Hashes Array file section size
								hash_arr_part_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(hash_arr_part_hdr.HashArrHash)) # Hashes Array file section hash
								hash_arr_part_data_off = dnx_hash_arr_off + hash_arr_prev_part_size # Hashes Array file section data offset
								hash_arr_part_data = buffer[hash_arr_part_data_off:hash_arr_part_data_off + hash_arr_part_size] # Hashes Array file section data
								hash_arr_part_data_hash = get_hash(hash_arr_part_data, chunk_hash_size) # Hashes Array file section data hash
								
								# Check if RCIP length is divisible by RCIP Chunk length and if Hashes Array file section length is divisible by its Size
								if (dnx_rcip_len % rcip_chunk_size != 0) or (len(hash_arr_part_data) % hash_arr_part_size != 0) :
									cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
								
								# Check if Hashes Array file section Hash is valid to Hashes Array file section Header
								if hash_arr_part_hash == hash_arr_part_data_hash : hash_arr_valid_count += 1
								
								pt_14_R2 = ext_table(['Field', 'Value'], False, 1)
								pt_14_R2.title = col_y + 'Extension 20 R2 Hashes Array %d/%d' % (header + 1, hash_arr_hdr_count) + col_e
								pt_14_R2.add_row(['Hashes Array EXT Hash', hash_arr_part_hash])
								pt_14_R2.add_row(['Hashes Array MEA Hash', hash_arr_part_data_hash])
								
								ext_print_temp.append(pt_14_R2)
								
								# Parse each RCIP IFWI Chunk
								for chunk in range(rcip_chunk_count) :
									rcip_chunk_off = dnx_rcip_off + chunk * rcip_chunk_size
									hash_arr_chunk_off = dnx_hash_arr_off + chunk * chunk_hash_size
									
									rcip_chunk_hash = get_hash(buffer[rcip_chunk_off:rcip_chunk_off + rcip_chunk_size], chunk_hash_size)
									hash_arr_chunk_hash = format(int.from_bytes(buffer[hash_arr_chunk_off:hash_arr_chunk_off + chunk_hash_size], 'little'), '064X')
									
									# Check if Hashes Array Chunk Hash is equal to RCIP IFWI Chunk Hash
									if hash_arr_chunk_hash == rcip_chunk_hash : chunk_hash_valid_count += 1
									
									pt_14_R2 = ext_table(['Field', 'Value'], False, 1)
									pt_14_R2.title = col_y + 'Extension 20 R2 Chunk %d/%d' % (chunk + 1, rcip_chunk_count) + col_e
									pt_14_R2.add_row(['Chunk EXT Hash', hash_arr_chunk_hash])
									pt_14_R2.add_row(['Chunk MEA Hash', rcip_chunk_hash])
									
									ext_print_temp.append(pt_14_R2)
								
								hash_arr_prev_part_size += hash_arr_part_size
								hash_arr_hdr_step += ctypes.sizeof(hash_arr_part_struct)

							# Parse each IFWI Region Map
							for region in range(ifwi_rgn_count) :
								ifwi_rgn_map = get_struct(buffer, cpd_ext_offset + ext_length + hash_arr_hdr_step + ifwi_rgn_hdr_step, CSE_Ext_14_RegionMap, file_end)
								ext_print_temp.append(ifwi_rgn_map.ext_print())
								
								ifwi_rgn_hdr_step += ctypes.sizeof(CSE_Ext_14_RegionMap)
								
							# Check if all Hashes Array Header Hashes and RCIP IFWI Chunk Hashes are Valid
							if hash_arr_valid_count == hash_arr_hdr_count : ext_dnx_val[1] = True
							if chunk_hash_valid_count == rcip_chunk_count * hash_arr_hdr_count : ext_dnx_val[2] = True
						
						elif ext_tag == 0x15 : # CSE_Ext_15 has a unique structure
							CSE_Ext_15_PartID_length = ctypes.sizeof(CSE_Ext_15_PartID)
							CSE_Ext_15_Payload_length = ctypes.sizeof(CSE_Ext_15_Payload)
							CSE_Ext_15_Payload_Knob_length = ctypes.sizeof(CSE_Ext_15_Payload_Knob)
							
							part_id_count = ext_hdr_p.PartIDCount
							cpd_part_id_offset = cpd_ext_offset + ext_length # CSE_Ext_15 structure size (not entire Extension 15)
							cpd_payload_offset = cpd_part_id_offset + part_id_count * 0x14
							cpd_payload_knob_offset = cpd_payload_offset + 0x4
							
							for _ in range(part_id_count) :
								part_id_struct = get_struct(buffer, cpd_part_id_offset, CSE_Ext_15_PartID, file_end)
								ext_print_temp.append(part_id_struct.ext_print())
								cpd_part_id_offset += 0x14
							
							payload_struct = get_struct(buffer, cpd_payload_offset, CSE_Ext_15_Payload, file_end)
							ext_print_temp.append(payload_struct.ext_print())
							payload_knob_count = payload_struct.KnobCount
							payload_knob_area = cpd_ext_end - cpd_payload_knob_offset
							
							# Check Extension full size when Module Counter exists
							if ext_tag in ext_tag_mod_count and (cpd_ext_size != ext_length + part_id_count * CSE_Ext_15_PartID_length + CSE_Ext_15_Payload_length +
							payload_knob_count * CSE_Ext_15_Payload_Knob_length) :
								cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
							
							# Check if Knob data is divisible by Knob size
							if payload_knob_area % CSE_Ext_15_Payload_Knob_length != 0 :
								cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
							
							for knob in range(payload_knob_count) :
								payload_knob_struct = get_struct(buffer, cpd_payload_knob_offset, CSE_Ext_15_Payload_Knob, ftpr_var_ver, file_end)
								ext_print_temp.append(payload_knob_struct.ext_print())
								cpd_payload_knob_offset += 0x08
								
						elif ext_dict_mod in ext_dict :
							mod_length = ctypes.sizeof(ext_struct_mod)
							cpd_mod_offset = cpd_ext_offset + ext_length
							cpd_mod_area = cpd_ext_end - cpd_mod_offset
							
							# Check Extension full size when Module Counter exists
							if ext_tag in ext_tag_mod_count and (cpd_ext_size != ext_length + ext_hdr_p.ModuleCount * mod_length) :
								cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
							
							# Check if Mod data is divisible by Mod size
							if cpd_mod_area % mod_length != 0 :
								cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
							
							while cpd_mod_offset < cpd_ext_end :
								mod_hdr_p = get_struct(buffer, cpd_mod_offset, ext_struct_mod, file_end)
								ext_print_temp.append(mod_hdr_p.ext_print())
						
								cpd_mod_offset += mod_length
				
				if ext_tag == 0x0 :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					intel_cfg_hash_ext = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(ext_hdr.IMGDefaultHash))
					
					#print(intel_cfg_hash_ext) # Debug/Research
					
					# Validate CSME/CSSPS MFS Intel Configuration (Low Level File 6) Hash at Non-Initialized/Non-FWUpdated MFS
					if intel_cfg_hash_mfs and mfs_found and mfs_parsed_idx and 8 not in mfs_parsed_idx and intel_cfg_hash_ext not in intel_cfg_hash_mfs :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with wrong $FPT MFS Intel Configuration Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e,
						(intel_cfg_hash_ext,intel_cfg_hash_mfs))
					
					# Validate CSTXE or CSME 12 Alpha MFS/AFS Intel Configuration (FTPR > intl.cfg) Hash
					if intel_cfg_hash_ftpr and intel_cfg_ftpr and intel_cfg_hash_ext not in intel_cfg_hash_ftpr :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with wrong FTPR MFS Intel Configuration Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e,
						(intel_cfg_hash_ext,intel_cfg_hash_ftpr))
					
					# Detect unexpected inability to validate Non-Initialized/Non-FWUpdated $FPT (Low Level File 6) or FTPR (intl.cfg) MFS/AFS Intel Configuration Hash
					if (
             (
               mfs_found and
               mfs_parsed_idx and
               8 not in mfs_parsed_idx and
               not intel_cfg_hash_mfs
             ) or (
               intel_cfg_ftpr and
               not intel_cfg_hash_ftpr
             )
           ) and not param.me11_mod_extr :
						cse_anl_err(col_m + 'Warning: Could not validate CSE Extension 0x%0.2X MFS Intel Configuration Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
				
				elif ext_tag == 0x1 :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					CSE_Ext_01_length = ctypes.sizeof(ext_struct_name)
					cpd_mod_offset = cpd_ext_offset + CSE_Ext_01_length
					CSE_Ext_01_Mod_length = ctypes.sizeof(ext_struct_mod)
					
					# Check Extension full size when Module Counter exists
					if ext_tag in ext_tag_mod_count and (cpd_ext_size != CSE_Ext_01_length + ext_hdr.ModuleCount * CSE_Ext_01_Mod_length) :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
				
				elif ext_tag == 0x2 :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					CSE_Ext_02_length = ctypes.sizeof(ext_struct_name)
					cpd_mod_offset = cpd_ext_offset + CSE_Ext_02_length
					CSE_Ext_02_Mod_length = ctypes.sizeof(ext_struct_mod)
					
					# Check Extension full size when Module Counter exists
					if ext_tag in ext_tag_mod_count and (cpd_ext_size != CSE_Ext_02_length + ext_hdr.ModuleCount * CSE_Ext_02_Mod_length) :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
				
				elif ext_tag == 0x3 :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					ext_pname = ext_hdr.PartitionName.decode('utf-8') # Partition Name
					ext_psize = ext_hdr.PartitionSize # Partition Size
					ext_phash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(ext_hdr.Hash)) # Partition Hash
					vcn = ext_hdr.VCN # Version Control Number
					in_id = ext_hdr.InstanceID # LOCL/WCOD identifier
					CSE_Ext_03_length = ctypes.sizeof(ext_struct_name)
					cpd_mod_offset = cpd_ext_offset + CSE_Ext_03_length
					CSE_Ext_03_Mod_length = ctypes.sizeof(ext_struct_mod)
					CSE_Ext_03_Mod_area = cpd_ext_end - cpd_mod_offset
					
					# Verify Partition Hash ($CPD - $MN2 + Data)
					if start_man_match != -1 and not single_man_name and not oem_config and not oem_signed :
						mea_pdata = buffer[cpd_offset:mn2_offset] + buffer[mn2_offset + mn2_size:cpd_offset + ext_psize] # $CPD + Data (no $MN2)
						mea_phash = get_hash(mea_pdata, len(ext_phash) // 2) # Hash for CSE_Ext_03
						
						ext_phval = [True, ext_phash == mea_phash, ext_phash, mea_phash]
						if not ext_phval[1] and int(ext_phval[2], 16) != 0 :
							if (variant,major,minor,ext_psize) == ('CSME',11,8,0x88000) : (ext_phash, mea_phash) = ('IGNORE', 'IGNORE') # CSME 11.8 Slim Partition Hash is always wrong, ignore
							cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with wrong Partition Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, (ext_phash,mea_phash))
					
					# Check Extension full size when Module Counter exists
					if ext_tag in ext_tag_mod_count and (cpd_ext_size != CSE_Ext_03_length + ext_hdr.ModuleCount * CSE_Ext_03_Mod_length) :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					# Check if Mod data is divisible by Mod size
					if CSE_Ext_03_Mod_area % CSE_Ext_03_Mod_length != 0 :
						cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
						
					while cpd_mod_offset < cpd_ext_end :
						mod_hdr_p = get_struct(buffer, cpd_mod_offset, ext_struct_mod, file_end)
						met_name = mod_hdr_p.Name.decode('utf-8') + '.met'
						# Some may include 03/0F/16, may have 03/0F/16 MetadataHash mismatch, may have Met name with ".met" included (GREAT WORK INTEL/OEMs...)
						if met_name.endswith('.met.met') : met_name = met_name[:-4]
						met_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(mod_hdr_p.MetadataHash)) # Metadata Hash
						
						cpd_ext_hash.append([cpd_name, met_name, met_hash])
						
						cpd_mod_offset += CSE_Ext_03_Mod_length
					
				elif ext_tag == 0xA :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					ext_length = ctypes.sizeof(ext_struct_name)
					
					# Detect CSE Extension without Modules different size & notify user
					if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					mod_comp_type = ext_hdr.Compression # Metadata's Module Compression Type (0-2)
					mod_encr_type = ext_hdr.Encryption # Metadata's Module Encryption Type (0-1)
					mod_comp_size = ext_hdr.SizeComp # Metadata's Module Compressed Size ($CPD Entry's Module Size is always Uncompressed)
					mod_uncomp_size = ext_hdr.SizeUncomp # Metadata's Module Uncompressed Size (equal to $CPD Entry's Module Size)
					mod_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(ext_hdr.Hash)) # Metadata's Module Hash
					
					cpd_mod_attr.append([cpd_entry_name.decode('utf-8')[:-4], mod_comp_type, mod_encr_type, 0, mod_comp_size, mod_uncomp_size, 0, mod_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
				
				elif ext_tag == 0xC :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end, ftpr_var_ver)
					ext_length = ctypes.sizeof(ext_struct_name)
					
					# Detect CSE Extension without Modules different size & notify user
					if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					fw_0C_cse,fw_0C_sku1,fw_0C_lbg,fw_0C_m3,fw_0C_m0,fw_0C_sku2,fw_0C_sicl,fw_0C_res2 = ext_hdr.get_flags()
					
					ext12_info = [ext_hdr.FWSKUCaps, fw_0C_sku1, fw_0C_lbg, fw_0C_sku2]
				
				elif ext_tag == 0xF :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					if ext_pname == '' : ext_pname = ext_hdr.PartitionName.decode('utf-8') # Partition Name (prefer CSE_Ext_03)
					if vcn == -1 : vcn = ext_hdr.VCN # Version Control Number (prefer CSE_Ext_03)
					arb_svn = ext_hdr.ARBSVN # FPF Anti-Rollback (ARB) Security Version Number
					CSE_Ext_0F_length = ctypes.sizeof(ext_struct_name)
					cpd_mod_offset = cpd_ext_offset + CSE_Ext_0F_length
					CSE_Ext_0F_Mod_length = ctypes.sizeof(ext_struct_mod)
					CSE_Ext_0F_Mod_area = cpd_ext_end - cpd_mod_offset
					
					# Check if Mod data is divisible by Mod size
					if CSE_Ext_0F_Mod_area % CSE_Ext_0F_Mod_length != 0 :
						cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					while cpd_mod_offset < cpd_ext_end :
						mod_hdr_p = get_struct(buffer, cpd_mod_offset, ext_struct_mod, file_end)
						met_name = mod_hdr_p.Name.decode('utf-8') + '.met'
						# Some may include 03/0F/16, may have 03/0F/16 MetadataHash mismatch, may have Met name with ".met" included (GREAT WORK INTEL/OEMs...)
						if met_name.endswith('.met.met') : met_name = met_name[:-4]
						met_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(mod_hdr_p.MetadataHash)) # Metadata Hash
						
						cpd_ext_hash.append([cpd_name, met_name, met_hash])
						
						cpd_mod_offset += CSE_Ext_0F_Mod_length
				
				elif ext_tag == 0x10 :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					CSE_Ext_10_length = ctypes.sizeof(ext_struct_name)
					CSE_Ext_10_Chunk_offset = cpd_ext_offset + CSE_Ext_10_length # Offset of 1st iUnit Extension Entry/Chunk
					CSE_Ext_10_Chunk_length = ctypes.sizeof(ext_struct_mod) # iUnit Extension Entry/Chunk Size
					CSE_Ext_10_Chunk_area = cpd_ext_end - CSE_Ext_10_Chunk_offset # iUnit Extension Entries/Chunks Area
					CSE_Ext_10_Chunk_count = divmod(CSE_Ext_10_Chunk_area, CSE_Ext_10_Chunk_length) # Number of iUnit Entries/Chunks
					CSE_Ext_10_iUnit_offset = cpd_ext_end # iUnit Module data begin after iUnit Metadata
					while buffer[CSE_Ext_10_iUnit_offset] == 0xFF : CSE_Ext_10_iUnit_offset += 1 # Skip padding before iUnit Module data
					
					# Check if iUnit Entries/Chunks Area is divisible by Entry/Chunk Size size
					if CSE_Ext_10_Chunk_count[1] != 0 :
						cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					# Parse all iUnit Module Chunks via their Extension Metadata
					for chunk in range(CSE_Ext_10_Chunk_count[0]) :
						chunk_hdr = get_struct(buffer, CSE_Ext_10_Chunk_offset + chunk * CSE_Ext_10_Chunk_length, ext_struct_mod, file_end) # iUnit Chunk Metadata
						iunit_chunk_size = chunk_hdr.Size # iUnit Module Chunk Size
						if chunk == 0 : iunit_chunk_start = CSE_Ext_10_iUnit_offset + chunk_hdr.Unknown1 # First Chunk starts from a Base Address ?
						iunit_chunk_hash_ext = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in chunk_hdr.Hash) # iUnit Module Chunk Intel Hash (BE)
						iunit_chunk_hash_mea = get_hash(buffer[iunit_chunk_start:iunit_chunk_start + iunit_chunk_size], len(iunit_chunk_hash_ext) // 2) # iUnit Module Chunk MEA Hash
						iunit_chunk_valid.append(iunit_chunk_hash_mea == iunit_chunk_hash_ext) # Store iUnit Module Chunk(s) Hash validation results
						iunit_chunk_start += iunit_chunk_size # Next iUnit Module Chunk starts at the previous plus its size
					
					# Verify that all iUnit Module data Chunks are valid
					if iunit_chunk_valid == [True] * len(iunit_chunk_valid) : ext_iunit_val[0] = True
					
					CSE_Ext_10_iUnit_size = iunit_chunk_start - CSE_Ext_10_iUnit_offset # iUnit Module full Size for CSE Unpacking
					cpd_mod_attr.append([cpd_entry_name.decode('utf-8')[:-4], 0, 0, 0, CSE_Ext_10_iUnit_size, CSE_Ext_10_iUnit_size, 0, 0, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
						
				elif ext_tag == 0x11 :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					ext_length = ctypes.sizeof(ext_struct_name)
					
					# Detect CSE Extension without Modules different size & notify user
					if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					mod_unk_size = ext_hdr.SizeUnknown # Metadata's Module Unknown Size (needs to be subtracted from SizeUncomp)
					mod_uncomp_size = ext_hdr.SizeUncomp # Metadata's Module Uncompressed Size (SizeUnknown + SizeUncomp = $CPD Entry's Module Size)
					mod_cpd_size = mod_uncomp_size - mod_unk_size # Should be the same as $CPD
					mod_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in ext_hdr.Hash) # Metadata's Module Hash (BE)
					
					cpd_mod_attr.append([cpd_entry_name.decode('utf-8')[:-4], 0, 0, 0, mod_cpd_size, mod_cpd_size, 0, mod_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
				
				elif ext_tag == 0x12 :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					CSE_Ext_12_length = ctypes.sizeof(ext_struct_name)
					cpd_mod_offset = cpd_ext_offset + CSE_Ext_12_length
					CSE_Ext_12_Mod_length = ctypes.sizeof(ext_struct_mod)
					
					# Check Extension full size when Module Counter exists
					if ext_tag in ext_tag_mod_count and (cpd_ext_size != CSE_Ext_12_length + ext_hdr.ModuleCount * CSE_Ext_12_Mod_length) :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with Module Count size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
				
				elif ext_tag == 0x13 :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					ext_length = ctypes.sizeof(ext_struct_name)
					
					# Detect CSE Extension without Modules different size & notify user
					if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
					
					ibbl_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in ext_hdr.IBBLHash) # IBBL Hash (BE)
					ibb_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in ext_hdr.IBBHash) # IBB Hash (BE)
					obb_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in ext_hdr.OBBHash) # OBB Hash (BE)
					if ibbl_hash not in ['00' * ext_hdr.IBBLHashSize, 'FF' * ext_hdr.IBBLHashSize] : cpd_mod_attr.append(['IBBL', 0, 0, 0, 0, 0, 0, ibbl_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
					if ibb_hash not in ['00' * ext_hdr.IBBHashSize, 'FF' * ext_hdr.IBBHashSize] : cpd_mod_attr.append(['IBB', 0, 0, 0, 0, 0, 0, ibb_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
					if obb_hash not in ['00' * ext_hdr.OBBHashSize, 'FF' * ext_hdr.OBBHashSize] : cpd_mod_attr.append(['OBB', 0, 0, 0, 0, 0, 0, obb_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
					
				elif ext_tag == 0x16 :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					ext_length = ctypes.sizeof(ext_struct_name)
					ext_psize = ext_hdr.PartitionSize # Partition Size
					if ext_pname == '' : ext_pname = ext_hdr.PartitionName.decode('utf-8') # Partition Name (prefer CSE_Ext_03)
					if in_id == 0 : in_id = ext_hdr.InstanceID # LOCL/WCOD identifier (prefer CSE_Ext_03)
					ext_phalg = ext_hdr.HashAlgorithm # Partition Hash Algorithm
					ext_phlen = int(''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(ext_hdr.HashSize)), 16) # Partition Hash Size
					ext_phash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(ext_hdr.Hash)) # Partition Hash
					
					# Verify Partition Hash ($CPD - $MN2 + Data)
					if start_man_match != -1 and not single_man_name and not oem_config and not oem_signed :
						mea_pdata = buffer[cpd_offset:mn2_offset] + buffer[mn2_offset + mn2_size:cpd_offset + ext_psize] # $CPD + Data (no $MN2)
						
						mea_phash = get_hash(mea_pdata, ext_phlen)
						ext_phval = [True, ext_phash == mea_phash, ext_phash, mea_phash]
						if not ext_phval[1] and int(ext_phval[2], 16) != 0 :
							if (variant,major) == ('CSSPS',5) : (ext_phash, mea_phash) = ('IGNORE', 'IGNORE') # CSSPS 5 Partition Hash is always wrong, ignore
							cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X with wrong Partition Hash at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, (ext_phash,mea_phash))
					
					# Detect CSE Extension without Modules different size & notify user
					if ext_tag in ext_tag_mod_none and cpd_ext_size != ext_length :
						cse_anl_err(col_r + 'Error: Detected CSE Extension 0x%0.2X w/o Modules size difference at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)

				elif ext_tag in (0x18,0x19,0x1A) :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					CSE_Ext_TCSS_length = ctypes.sizeof(ext_struct_name)
					cpd_mod_offset = cpd_ext_offset + CSE_Ext_TCSS_length
					CSE_Ext_TCSS_Mod_length = ctypes.sizeof(ext_struct_mod)
					CSE_Ext_TCSS_Mod_area = cpd_ext_end - cpd_mod_offset
					tcss_types = {1:'iom', 2:'nphy' if cpd_name == 'NPHY' else 'mg', 3:'tbt', 4:'iom.cd', 5:'tbt.cd', 11:'iom.hwcd'} # mg = nphy
					
					# Check if Mod data is divisible by Mod size
					if CSE_Ext_TCSS_Mod_area % CSE_Ext_TCSS_Mod_length != 0 :
						cse_anl_err(col_r + 'Error: Detected non-divisible CSE Extension 0x%0.2X at %s > %s!' % (ext_tag, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
						
					while cpd_mod_offset < cpd_ext_end :
						mod_hdr_p = get_struct(buffer, cpd_mod_offset, ext_struct_mod, file_end)
						
						tcss_type = mod_hdr_p.HashType # Numeric value which corresponds to specific TCSS module filename
						tcss_hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in mod_hdr_p.Hash) # Hash (BE)
						
						if tcss_type in tcss_types : cpd_mod_attr.append([tcss_types[tcss_type], 0, 0, 0, 0, 0, 0, tcss_hash, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
						else : cse_anl_err(col_r + 'Error: Detected unknown CSE TCSS Type %d at %s > %s!' % (tcss_type, cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
						
						cpd_mod_offset += CSE_Ext_TCSS_Mod_length
				
				elif ext_tag == 0x32 :
					ext_hdr = get_struct(buffer, cpd_ext_offset, ext_struct_name, file_end)
					ext32_type = ext_hdr.Type.decode('utf-8') # OP/RC
					ext32_plat = ext_hdr.Platform.decode('utf-8') # GE/HA/PU/PE
					
					ext32_info = [ext32_type, ext32_plat]
				
				cpd_ext_offset += cpd_ext_size # Next Extension Offset
				
				if cpd_ext_offset + 1 > cpd_entry_offset + cpd_entry_size : # End of Manifest/Metadata Entry reached
					cpd_ext_attr.append([cpd_entry_name.decode('utf-8'), 0, 0, cpd_entry_offset, cpd_entry_size, cpd_entry_size, entry_empty, 0, cpd_name, in_id, mn2_sigs, cpd_offset, cpd_valid])
					cpd_ext_names.append(cpd_entry_name.decode('utf-8')[:-4]) # Store Module names which have Manifest/Metadata
					
					break # Stop Extension scanning at the end of Manifest/Metadata Entry
				
				ext_tag = int.from_bytes(buffer[cpd_ext_offset:cpd_ext_offset + 0x4], 'little') # Next Extension Tag
			
			# Detect last 0x20 of UTOK/STKN for Unlock Token Flags Structure (Optional)
			if buffer[buffer_len - 0x20:buffer_len - 0x1C] == b'UTFL' :
				utfl_hdr = get_struct(buffer, buffer_len - 0x20, UTFL_Header, file_end)
				ext_print_temp.append(utfl_hdr.hdr_print())
			
			# Add $MN2 Info followed by Manifest/Metadata/UTFL Info
			if single_man_name and mn2_hdr_print : ext_print_temp = [mn2_hdr_print] + ext_print_temp
			
			ext_print.append(ext_print_temp) # Store Manifest/Metadata/UTFL Info
			
		# Actions when parsing UTOK/STKN without Manifest (a.k.a. UTFL only)
		if single_man_name and start_man_match == -1 :
			ext_print.append(cpd_entry_name.decode('utf-8')) # Store UTOK w/o $MN2 Partition Name
			# Detect last 0x20 of UTOK/STKN for Unlock Token Flags Structure
			if buffer[buffer_len - 0x20:buffer_len - 0x1C] == b'UTFL' :
				utfl_hdr = get_struct(buffer, buffer_len - 0x20, UTFL_Header, file_end)
				ext_print_temp.append(utfl_hdr.hdr_print())
			ext_print.append(ext_print_temp) # Store UTFL Info

	if single_man_name : return ext_print # Stop Manifest/Metadata/UTFL analysis early when the input is a single Manifest
	
	# Stage 3: Calculate Module Compressed Size when no Metadata exists, thus treated as "Data" instead of "Module with Metadata" below
	# When the firmware lacks Module Metadata, the Compression Type, Encryption Yes/No, Compressed Size & Uncompressed Size are unknown
	# $CPD contains Huffman Yes/No and Uncompressed Size but Compressed Size is needed for Header parsing during Huffman decompression
	# RBEP > rbe and FTPR > pm Modules contain the Compressed Size, Uncompressed Size & Hash but without Names, only hardcoded DEV_IDs
	# With only Huffman Yes/No bit at $CPD, we can no longer discern between Uncompressed, LZMA Compressed and Encrypted Modules
	# This adjustment should only be required for Huffman Modules without Metadata but MEA calculates everything just in case
	for i in range(len(cpd_wo_met_info)) : # All $CPD entries should be ordered by Offset in ascending order for the calculation
		if (cpd_wo_met_info[i][1],cpd_wo_met_info[i][2]) == (0,0) : # Check if entry has valid Starting Offset & Size
			continue # Do not adjust empty entries to skip them during unpacking (i.e. fitc.cfg or oem.key w/o Data)
		elif oem_config or oem_signed : # Check if entry is FIT/OEM customized and thus outside Stock/RGN Partition
			continue # Do not adjust FIT/OEM-customized Partition entries (fitc.cfg, oem.key) since $CPD info is accurate
		elif i < len(cpd_wo_met_info) - 1 : # For all entries, use the next module offset to find its size, if possible
			cpd_wo_met_info[i][2] = cpd_wo_met_info[i + 1][1] - cpd_wo_met_info[i][1] # Size is Next Start - Current Start
		elif ext_psize != -1 : # For the last entry, use CSE Extension 0x3/0x16 to find its size via the total Partition size
			cpd_wo_met_info[i][2] = ext_psize - cpd_wo_met_info[i][1] # Size is Partition End - Current Start
		else : # For the last entry, if CSE Extension 0x3/0x16 is missing, find its size manually via EOF 0xFF padding
			entry_size = buffer[cpd_offset + cpd_wo_met_info[i][1]:].find(b'\xFF\xFF') # There is no Huffman codeword 0xFFFF
			if entry_size != -1 : cpd_wo_met_info[i][2] = entry_size # Size ends where the padding starts
			else : cse_anl_err(col_r + 'Error: Could not determine size of Module %s > %s!' % (cpd_name,cpd_wo_met_info[i][0]) + col_e, None)
			
		if cpd_wo_met_info[i][2] > cpd_wo_met_back[i][2] or cpd_wo_met_info[i][2] < 0 : # Report obvious wrong Module Size adjustments
			cpd_wo_met_info[i][2] = cpd_wo_met_back[i][2] # Restore default Module Size from backup in case of wrong adjustment
			cse_anl_err(col_r + 'Error: Could not determine size of Module %s > %s!' % (cpd_name,cpd_wo_met_info[i][0]) + col_e, None)
	
	# Stage 4: Fill Metadata Hash from Manifest
	for attr in cpd_ext_attr :
		for met_hash in cpd_ext_hash :
			if attr[8] == met_hash[0] and attr[0] == met_hash[1] : # Verify $CPD and Metadata name match
				attr[7] = met_hash[2] # Fill Metadata's Hash Attribute from Manifest Extension 0x3, 0xF or 0x16
				break # To hopefully avoid some 03/0F/16 MetadataHash mismatch, assuming 1st has correct MetadataHash
	
	# Stage 5: Analyze Modules, Keys, Microcodes & Data (must be after all Manifest & Metadata Extension analysis)
	for entry in range(0, cpd_num) :
		cpd_entry_hdr = get_struct(buffer, cpd_offset + cpd_hdr_size + entry * 0x18, CPD_Entry, file_end)
		cpd_mod_off,cpd_mod_huff,cpd_mod_res = cpd_entry_hdr.get_flags()
		
		cpd_entry_name = cpd_entry_hdr.Name
		cpd_entry_size = cpd_entry_hdr.Size # Uncompressed only
		cpd_entry_offset = cpd_offset + cpd_mod_off
		mod_size = cpd_entry_size # Uncompressed initially, to replace with Compressed for Modules
		mod_empty = 0 # Assume that Module is not empty initially
		
		# Manifest & Metadata Skip
		if b'.man' in cpd_entry_name or b'.met' in cpd_entry_name : continue
		
		# Fill Module Attributes by single unified Metadata (BPM.met > [IBBL, IBB, OBB] or iom.met > [iom, iom.cd, iom.hwcd] etc...)
		if cpd_name in ('IBBP','IOMP','MGPP','NPHY','TBTP') : # MGPP = NPHY
			for mod in range(len(cpd_mod_attr)) :
				if cpd_mod_attr[mod][0] == cpd_entry_name.decode('utf-8') :
					cpd_mod_attr[mod][4] = cpd_entry_size # Fill Module Uncompressed Size from $CPD Entry
					cpd_mod_attr[mod][5] = cpd_entry_size # Fill Module Uncompressed Size from $CPD Entry
					cpd_ext_names.append(cpd_entry_name.decode('utf-8')) # To enter "Module with Metadata" section below
					
					break
					
			# Store all IBBP Module names to exclude those missing but with Hash at .met (GREAT WORK INTEL/OEMs...)
			if cpd_name == 'IBBP' : ibbp_all.append(cpd_entry_name.decode('utf-8'))
		
		# Module with Metadata
		if cpd_entry_name.decode('utf-8') in cpd_ext_names :
			for mod in range(len(cpd_mod_attr)) :
				if cpd_mod_attr[mod][0] == cpd_entry_name.decode('utf-8') :
					
					cpd_mod_attr[mod][3] = cpd_entry_offset # Fill Module Starting Offset from $CPD Entry
					if cpd_mod_attr[mod][4] == 0 : cpd_mod_attr[mod][4] = cpd_entry_size # Prefer Metadata info, if available (!= 0)
					if cpd_mod_attr[mod][5] == 0 : cpd_mod_attr[mod][5] = cpd_entry_size # Prefer Metadata info, if available (!= 0)
					cpd_mod_attr[mod][9] = in_id # Fill Module Instance ID from CSE_Ext_03
					
					mod_comp_size = cpd_mod_attr[mod][4] # Store Module Compressed Size for Empty check
					mod_size = mod_comp_size # Store Module Compressed Size for Out of Partition Bounds check
					mod_data = buffer[cpd_entry_offset:cpd_entry_offset + mod_comp_size] # Store Module data for Empty check
					if mod_data == b'\xFF' * mod_comp_size or cpd_entry_offset >= file_end : cpd_mod_attr[mod][6] = 1 # Determine if Module is Empty/Missing
					
					break
				
			# Detect $FPT Partition Size mismatch vs CSE_Ext_03/16
			for part in fpt_part_all :
				# Verify that CSE_Ext_03/16.PartitionSize exists and that the same $CPD Partition was found at fpt_part_all
				# by its unique Name, Offset & Instance ID. If $FPT Entry size is smaller than Extension size, error is shown.
				# The check is skipped when Extension size is not found so no problem with OEM/FIT firmware configuration.
				# The check is skipped when IDLM partition (DLMP) is parsed because its $FPT size is wrong by Intel design.
				if not msg_shown and ext_psize != -1 and part[0] == cpd_hdr.PartitionName and part[0] != b'DLMP' \
				and part[1] == cpd_offset and part[3] == in_id and part[2] < (cpd_offset + ext_psize) :
					cse_anl_err(col_r + 'Error: Detected CSE Extension 0x3/0x16 with smaller $FPT %s Partition Size!' % cpd_name + col_e, None)
					msg_shown = True # Partition related error, show only once
			
			# Detect BPDT Partition Size mismatch vs CSE_Ext_03/16
			for part in bpdt_part_all :
				# Verify that CSE_Ext_03/16.PartitionSize exists and that the same $CPD Partition was found at bpdt_part_all
				# by its unique Name, Offset & Instance ID. If BPDT Entry size is smaller than Extension size, error is shown.
				# The check is skipped when Extension size is not found so no problem with OEM/FIT firmware configuration.
				# The check is skipped when IDLM partition (DLMP) is parsed because its BPDT size is wrong by Intel design.
				if not msg_shown and ext_psize != -1 and part[0] == cpd_hdr.PartitionName.decode('utf-8') and part[0] != 'DLMP' \
				and part[1] == cpd_offset and part[6] == in_id and part[2] < (cpd_offset + ext_psize) :
					cse_anl_err(col_r + 'Error: Detected CSE Extension 0x3/0x16 with smaller BPDT %s Partition Size!' % cpd_name + col_e, None)
					msg_shown = True # Partition related error, show only once
					
		# Key
		elif '.key' in cpd_entry_name.decode('utf-8') :
			mod_data = buffer[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
			if mod_data == b'\xFF' * cpd_entry_size or cpd_entry_offset >= file_end : mod_empty = 1 # Determine if Key is Empty/Missing
			
			# Key's RSA Signature is validated at mod_anl function
			
			cpd_mod_attr.append([cpd_entry_name.decode('utf-8'), 0, 0, cpd_entry_offset, cpd_entry_size, cpd_entry_size, mod_empty, 0, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
		
		# Microcode
		elif 'upatch' in cpd_entry_name.decode('utf-8') :
			mod_data = buffer[cpd_entry_offset:cpd_entry_offset + cpd_entry_size]
			if mod_data == b'\xFF' * cpd_entry_size or cpd_entry_offset >= file_end : mod_empty = 1 # Determine if Microcode is Empty/Missing
			
			# Detect actual Microcode length
			mc_len = int.from_bytes(mod_data[0x20:0x24], 'little')
			mc_data = buffer[cpd_entry_offset:cpd_entry_offset + mc_len]
			
			cpd_mod_attr.append([cpd_entry_name.decode('utf-8'), 0, 0, cpd_entry_offset, cpd_entry_size, cpd_entry_size, mod_empty, mc_chk32(mc_data), cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
		
		# Data
		else :
			mod_comp_type = 0 # The Type is Uncompressed by default since "Data" shouldn't have Metadata
			mod_comp_size = cpd_entry_size # Compressed = Uncompressed (via $CPD) size by default since "Data" shouldn't have Metadata
			mod_uncomp_size = cpd_entry_size # The Uncompressed Size can be taken directly from $CPD
			
			# When the firmware lacks Huffman Module Metadata, we must manually fill the Compression Type via $CPD and calculated Compressed Size
			for i in range(len(cpd_wo_met_info)) :
				if (cpd_wo_met_info[i][0], cpd_wo_met_info[i][3]) == (cpd_entry_name.decode('utf-8'), 1) :
					mod_comp_type = cpd_wo_met_info[i][3] # As taken from $CPD Huffman Yes/No bit
					mod_comp_size = cpd_wo_met_info[i][2] # As calculated at Stage 3 of the analysis
					mod_size = mod_comp_size # Store calculated Compressed Size for Out of Partition Bounds check
					break
			
			mod_data = buffer[cpd_entry_offset:cpd_entry_offset + mod_size]
			
			# When the firmware lacks LZMA Module Metadata, we must manually fill the Compression Type and calculated Uncompressed Size
			if mod_data.startswith(b'\x36\x00\x40\x00\x00') and mod_data[0xE:0x11] == b'\x00\x00\x00' :
				mod_comp_type = 2 # Compression Type 2 is LZMA
				mod_uncomp_size = int.from_bytes(mod_data[0x5:0xD], 'little') # LZMA Header 0x5-0xD (uint64) is the Uncompressed Size in LE
			
			if mod_data == b'\xFF' * mod_size or cpd_entry_offset >= file_end : mod_empty = 1 # Determine if Module is Empty/Missing
			
			cpd_mod_attr.append([cpd_entry_name.decode('utf-8'), mod_comp_type, 0, cpd_entry_offset, mod_comp_size, mod_uncomp_size, mod_empty, 0, cpd_name, 0, mn2_sigs, cpd_offset, cpd_valid])
		
		# Detect Modules which exceed or are located at/after the end of RGN Partition size (CSE_Ext_03/16.PartitionSize)
		if not oem_config and not oem_signed and ext_psize != -1 and ((cpd_entry_offset >= cpd_offset + ext_psize) or (cpd_entry_offset + mod_size > cpd_offset + ext_psize)) :
			cse_anl_err(col_r + 'Error: Detected out of Partition bounds Module at %s > %s!' % (cpd_name, cpd_entry_name.decode('utf-8')) + col_e, None)
		
	# Stage 6: Remove missing APL IBBP Module Attributes
	if len(ibbp_all) :
		for ibbp in ibbp_bpm :
			if ibbp not in ibbp_all : # Module has hash at unified Metadata but is actually missing
				for mod_index in range(len(cpd_mod_attr)) :
					if cpd_mod_attr[mod_index][0] == ibbp : ibbp_del.append(mod_index) # Store missing Module's Attributes
					
		for mod_index in ibbp_del : del cpd_mod_attr[mod_index] # Delete missing Module's Attributes
	
	return cpd_offset,cpd_mod_attr,cpd_ext_attr,vcn,ext12_info,ext_print,ext_pname,ext32_info,ext_phval,ext_dnx_val,oem_config,oem_signed,cpd_mn2_info,ext_iunit_val,arb_svn

# Analyze & Store CSE Modules
def mod_anl(cpd_offset, cpd_mod_attr, cpd_ext_attr, fw_name, ext_print, ext_phval, ext_dnx_val, ext_iunit_val, rbe_pm_met_hashes, rbe_pm_met_valid, ext12_info, param) :
	# noinspection PyUnusedLocal
	mea_hash_c = 0
	mea_hash_u = 0
	mod_hash_u_ok = False
	comp = ['Uncompressed','Huffman','LZMA']
	encr_empty = ['No','Yes']
	
	pt = ext_table([col_y + 'Name' + col_e, col_y + 'Compression' + col_e, col_y + 'Encryption' + col_e, col_y + 'Offset' + col_e, col_y + 'Compressed' + col_e, col_y + 'Uncompressed' + col_e,
					col_y + 'Empty' + col_e], True, 1)
	
	# $CPD validity verified
	if cpd_offset > -1 :
		
		cpd_all_attr = cpd_ext_attr + cpd_mod_attr
		
		# Store Module details
		for mod in cpd_all_attr :
			pt.add_row([mod[0],comp[mod[1]],encr_empty[mod[2]],'0x%0.6X' % mod[3],'0x%0.6X' % mod[4],'0x%0.6X' % mod[5],encr_empty[mod[6]]])
		
		# Parent Partition Attributes (same for all cpd_all_attr list instance entries)
		cpd_pname = cpd_all_attr[0][8] # $CPD Name
		cpd_poffset = cpd_all_attr[0][11] # $CPD Offset, covers any cases with duplicate name entries (Joule_C0-X64-Release)
		cpd_pvalid = cpd_all_attr[0][12] # CPD Checksum Valid
		ext_inid = cpd_all_attr[0][9] # Partition Instance ID
		
		pt.title = col_y + 'Detected %s Module(s) at %s %0.4X [0x%0.6X]' % (len(cpd_all_attr), cpd_pname, ext_inid, cpd_poffset) + col_e
		folder_name = os.path.join(mea_dir, fw_name, '%s %0.4X [0x%0.6X]' % (cpd_pname, ext_inid, cpd_poffset), '')
		info_fname = os.path.join(mea_dir, fw_name, '%s %0.4X [0x%0.6X].txt' % (cpd_pname, ext_inid, cpd_poffset))
		
		cpd_hdr_struct, cpd_hdr_size = get_cpd(reading, cpd_poffset)
		cpd_phdr = get_struct(reading, cpd_poffset, cpd_hdr_struct, file_end)
		if param.me11_mod_extr : print('\n%s' % cpd_phdr.hdr_print())
		
		if cpd_pvalid : print(col_g + '\n$CPD Checksum of partition "%s" is VALID\n' % cpd_pname + col_e)
		else :
			if param.me11_mod_bug :
				input(col_r + '\n$CPD Checksum of partition "%s" is INVALID\n' % cpd_pname + col_e) # Debug
			else :
				print(col_r + '\n$CPD Checksum of partition "%s" is INVALID\n' % cpd_pname + col_e)
			
		print(pt) # Show Module details
		
		os.mkdir(folder_name)
		
		# Store Partition $CPD Header & Entry details in TXT
		with open(info_fname, 'a', encoding = 'utf-8') as info_file :
			info_file.write('\n%s\n%s' % (ansi_escape.sub('', str(cpd_phdr.hdr_print())), ansi_escape.sub('', str(pt))))
		
		# Store Partition $CPD Header & Entry details in HTML
		if param.write_html :
			with open(info_fname[:-4] + '.html', 'a', encoding = 'utf-8') as info_file :
				info_file.write('\n<br/>\n%s\n<br/>\n%s' % (pt_html(cpd_phdr.hdr_print()), pt_html(pt)))
		
		# Store Partition $CPD Header & Entry details in JSON
		if param.write_json :
			with open(info_fname[:-4] + '.json', 'a', encoding = 'utf-8') as info_file :
				info_file.write('\n%s\n%s' % (pt_json(cpd_phdr.hdr_print()), pt_json(pt)))
		
		# Load Huffman Dictionaries for Decompression
		huff_shape, huff_sym, huff_unk = cse_huffman_dictionary_load(variant, major, 'error')
		
		# Parse all Modules based on their Metadata
		for mod in cpd_all_attr :
			mod_name = mod[0] # Name
			mod_comp = mod[1] # Compression
			mod_encr = mod[2] # Encryption
			mod_start = mod[3] # Starting Offset
			mod_size_comp = mod[4] # Compressed Size
			mod_size_uncomp = mod[5] # Uncompressed Size
			mod_empty = mod[6] # Empty/Missing
			mod_hash = mod[7] # Hash (LZMA --> Compressed + zeros, Huffman --> Uncompressed)
			mod_end = mod_start + mod_size_comp # Ending Offset
			mn2_valid = mod[10][0] # Check if RSA Signature is valid (rsa_hash == dec_hash)
			# noinspection PyUnusedLocal
			mn2_sig_dec = mod[10][1] # RSA Signature Decrypted Hash
			# noinspection PyUnusedLocal
			mn2_sig_sha = mod[10][2] # RSA Signature Data Hash
			mn2_error = mod[10][3] # Check if RSA validation crashed (try-except)
			# noinspection PyUnusedLocal
			mn2_start = mod[10][4] # Manifest Starting Offset
			mn2_struct = mod[10][5] # Manifest Structure Object
			
			if mod_empty == 1 : continue # Skip Empty/Missing Modules
			
			if '.man' in mod_name or '.met' in mod_name :
				mod_fname = folder_name + mod_name
				mod_type = 'metadata'
			else :
				mod_fname = folder_name + mod_name
				mod_type = 'module'
				
			mod_data = reading[mod_start:mod_end]
			
			if not mod_encr : print(col_y + '\n--> Stored %s %s "%s" [0x%0.6X - 0x%0.6X]' % (comp[mod_comp], mod_type, mod_name, mod_start, mod_end - 0x1) + col_e)
			else : print(col_m + '\n--> Stored Encrypted %s %s "%s" [0x%0.6X - 0x%0.6X]' % (comp[mod_comp], mod_type, mod_name, mod_start, mod_end - 0x1) + col_e)
			
			# Store & Ignore Encrypted Data
			if mod_encr == 1 :
				
				if param.me11_mod_bug : # Debug
					print('\n    MOD: %s' % mod_hash)
					print(col_m + '\n    Hash of Encrypted %s "%s" cannot be verified' % (mod_type, mod_name) + col_e)
					
				with open(mod_fname, 'wb') as mod_file : mod_file.write(mod_data) # Store Encrypted Data, cannot validate
			
			# Store Uncompressed Data
			elif mod_comp == 0 :
				
				# Manifest
				if '.man' in mod_name :
					if param.me11_mod_bug :
						print('\n    MN2: %s' % mn2_sig_dec) # Debug
						print('    MEA: %s' % mn2_sig_sha) # Debug
					
					if mn2_error :
						if param.me11_mod_bug :
							input(col_m + '\n    RSA Signature of partition "%s" is UNKNOWN' % cpd_pname + col_e) # Debug
						else :
							print(col_m + '\n    RSA Signature of partition "%s" is UNKNOWN' % cpd_pname + col_e)
					elif mn2_valid : print(col_g + '\n    RSA Signature of partition "%s" is VALID' % cpd_pname + col_e)
					else :
						if param.me11_mod_bug :
							input(col_r + '\n    RSA Signature of partition "%s" is INVALID' % cpd_pname + col_e) # Debug
						else :
							print(col_r + '\n    RSA Signature of partition "%s" is INVALID' % cpd_pname + col_e)
							
					mn2_hdr_print = mn2_struct.hdr_print_cse()
					print('\n%s' % mn2_hdr_print) # Show $MN2 details
					
					# Insert $MN2 Manifest details at Extension Info list (ext_print)
					ext_print_cur_len = len(ext_print) # Current length of Extension Info list
					for index in range(0, ext_print_cur_len, 2) : # Only Name (index), skip Info (index + 1)
						if str(ext_print[index]).startswith(mod_name) :
							ext_print[index + 1] = [mn2_hdr_print] + (ext_print[index + 1])
							break
					
					if param.me11_mod_bug and ext_phval[0] :
						print('\n    EXT: %s' % ext_phval[2]) # Debug
						print('    MEA: %s' % ext_phval[3]) # Debug
					
					if ext_phval[0] and int(ext_phval[2], 16) == 0 : # Hash exists but is not used (0)
						print(col_m + '\n    Hash of partition "%s" is UNKNOWN' % cpd_pname + col_e)
					elif ext_phval[0] and ext_phval[1] : # Hash exists and is Valid
						print(col_g + '\n    Hash of partition "%s" is VALID' % cpd_pname + col_e)
					elif ext_phval[0] : # Hash exists but is Invalid (CSME 11.8 SLM and CSSPS 5 Hashes are always wrong)
						if (variant,major,minor,ext12_info[1]) == ('CSME',11,8,2) :
							print(col_r + '\n    Hash of partition "%s" is INVALID (CSME 11.8 Slim Ignore)' % cpd_pname + col_e)
						elif (variant,major) == ('CSSPS',5) :
							print(col_r + '\n    Hash of partition "%s" is INVALID (%s %d Ignore)' % (cpd_pname,variant,major) + col_e)
						elif param.me11_mod_bug and (ext_phval[2],ext_phval[3]) not in cse_known_bad_hashes :
							input(col_r + '\n    Hash of partition "%s" is INVALID' % cpd_pname + col_e) # Debug
						else :
							print(col_r + '\n    Hash of partition "%s" is INVALID' % cpd_pname + col_e)
				
				# Metadata
				elif '.met' in mod_name :
					mea_hash = get_hash(mod_data, len(mod_hash) // 2)
					
					if param.me11_mod_bug :
						print('\n    MOD: %s' % mod_hash) # Debug
						print('    MEA: %s' % mea_hash) # Debug
				
					if mod_hash == mea_hash : print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						if param.me11_mod_bug and (mod_hash,mea_hash) not in cse_known_bad_hashes :
							input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
				# Key
				elif '.key' in mod_name :
					ext_print = ext_anl(mod_data, '$MN2', 0x1B, file_end, [variant,major,minor,hotfix,build], mod_name, [[],'']) # Retrieve & Store Key Extension Info
					
				# MFS Configuration
				elif mod_name in ('intl.cfg','fitc.cfg') :
					mfs_file_no = 6 if mod_name == 'intl.cfg' else 7
					mfs_file_name = {6:'Intel Configuration', 7:'OEM Configuration'}
					if param.me11_mod_extr : print(col_g + '\n    Analyzing MFS Low Level File %d (%s) ...' % (mfs_file_no, mfs_file_name[mfs_file_no]) + col_e)
					rec_folder = os.path.join(mea_dir, folder_name, mfs_file_name[mfs_file_no], '')
					# noinspection PyUnusedLocal
					pch_init_info = mfs_cfg_anl(mfs_file_no, mod_data, rec_folder, rec_folder, 0x1C, [], -1) # Parse MFS Configuration Records
					# noinspection PyUnusedLocal
					pch_init_final = pch_init_anl(pch_init_info) # Parse MFS Initialization Tables and store their Platforms/Steppings
					
					# Only Intel MFS Configuration protected by Hash
					if mod_name == 'intl.cfg' :
						mea_hash = get_hash(mod_data, len(mod_hash) // 2)
						
						if param.me11_mod_bug :
							print('\n    MOD: %s' % mod_hash) # Debug
							print('    MEA: %s' % mea_hash) # Debug
				
						if mod_hash == mea_hash : print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						else :
							if param.me11_mod_bug and (mod_hash,mea_hash) not in cse_known_bad_hashes :
								input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
				# Microcode
				elif 'upatch' in mod_name :
					if mod_hash == 0 :
						print(col_g + '\n    Checksum of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						if param.me11_mod_bug :
							input(col_r + '\n    Checksum of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						else :
							print(col_r + '\n    Checksum of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
				# Data
				elif mod_hash == 0 :
					
					# CSE_Ext_14 R1/R2 has a unique structure
					if cpd_pname == 'RCIP' :
						if (mod_name,ext_dnx_val[1]) == ('hash.array',True) or (mod_name,ext_dnx_val[2]) == ('rcipifwi',True) :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						elif mod_name == 'version' :
							print(col_m + '\n    Hash of %s %s "%s" is UNKNOWN' % (comp[mod_comp], mod_type, mod_name) + col_e)
						elif param.me11_mod_bug :
							input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					elif cpd_pname in ('IUNP','IUNM') :
						if (mod_name,ext_iunit_val[0]) == ('iunit',True) :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						elif param.me11_mod_bug :
							input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						print(col_m + '\n    Hash of %s %s "%s" is UNKNOWN' % (comp[mod_comp], mod_type, mod_name) + col_e)
				
				# Module
				else :
					mea_hash = get_hash(mod_data, len(mod_hash) // 2)
					
					if param.me11_mod_bug :
						print('\n    MOD: %s' % mod_hash) # Debug
						print('    MEA: %s' % mea_hash) # Debug
				
					if mod_hash == mea_hash : print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
					else :
						if param.me11_mod_bug and (mod_hash,mea_hash) not in cse_known_bad_hashes :
							input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
						else :
							print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							
				with open(mod_fname, 'wb') as mod_file : mod_file.write(mod_data) # Store Metadata or Module

			# Store & Decompress Huffman Data
			elif mod_comp == 1 :
				
				try :
					if param.me11_mod_bug :
						mod_data_d, huff_error = cse_huffman_decompress(mod_data, mod_size_comp, mod_size_uncomp, huff_shape, huff_sym, huff_unk, 'error') # Debug
						if (huff_error,mod_hash) == (True,0) : input() # Decompression incomplete, pause when no Module Metadata exist 
					else :
						mod_data_d, huff_error = cse_huffman_decompress(mod_data, mod_size_comp, mod_size_uncomp, huff_shape, huff_sym, huff_unk, 'none')
						
					print(col_c + '\n    Decompressed %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
					
					# Open decompressed Huffman module for Hash validation, when Metadata info is available
					if mod_hash != 0 :
						mea_hash = get_hash(mod_data_d, len(mod_hash) // 2)
						
						if param.me11_mod_bug :
							print('\n    MOD: %s' % mod_hash) # Debug
							print('    MEA: %s' % mea_hash) # Debug
							
						if mod_hash == mea_hash :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, valid data
						else :
							if param.me11_mod_bug and (mod_hash,mea_hash) not in cse_known_bad_hashes :
								input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, invalid data
					
					# Open decompressed Huffman module for Hash validation, when Metadata info is not available
					# When the firmware lacks Module Metadata, check RBEP > rbe and FTPR > pm Modules instead
					elif rbe_pm_met_hashes :
						mea_hash = get_hash(mod_data_d, len(rbe_pm_met_hashes[0]) // 2)
						
						if param.me11_mod_bug :
							print('\n    MOD: No Metadata, validation via RBEP > rbe and FTPR > pm Modules') # Debug
							print('    MEA: %s' % mea_hash) # Debug
							
						if mea_hash in rbe_pm_met_hashes :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							rbe_pm_met_valid.append(mea_hash) # Store valid RBEP > rbe or FTPR > pm Hash to single out leftovers
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, valid data
						else :
							if param.me11_mod_bug and (mod_hash,mea_hash) not in cse_known_bad_hashes :
								input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, invalid data
						
					else :
						with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, cannot validate
				
				except :
					if param.me11_mod_bug :
						input(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
					else :
						print(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
						
					with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data) # Decompression failed
			
			# Store & Decompress LZMA Data
			elif mod_comp == 2 :
				
				mod_data_r = mod_data # Store raw LZMA Module contents before zeros removal, for hashing
				
				# Remove zeros from LZMA header for decompression (inspired from Igor Skochinsky's me_unpack)
				if mod_data.startswith(b'\x36\x00\x40\x00\x00') and mod_data[0xE:0x11] == b'\x00\x00\x00' :
					mod_data = mod_data[:0xE] + mod_data[0x11:] # Visually, mod_size_comp += -3 for compressed module
				
				try :
					# noinspection PyArgumentList
					mod_data_d = lzma.LZMADecompressor().decompress(mod_data)
					
					# Add missing EOF Padding when needed (usually at NFTP.ptt Module)
					data_size_uncomp = len(mod_data_d)
					if data_size_uncomp != mod_size_uncomp :
						mod_last_byte = struct.pack('B', mod_data_d[data_size_uncomp - 1]) # Determine padding type (0xFF or 0x00)
						mod_miss_padd = mod_size_uncomp - data_size_uncomp # Determine missing padding size
						mod_data_d += mod_last_byte * mod_miss_padd # Fill module with missing padding
					
					print(col_c + '\n    Decompressed %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
					
					# Open decompressed LZMA module for Hash validation, when Metadata info is available
					if mod_hash != 0 :
						# Calculate LZMA Module Hash
						mea_hash_c = get_hash(mod_data_r, len(mod_hash) // 2) # Compressed, Header zeros included (most LZMA Modules)
						
						mod_hash_c_ok = mod_hash == mea_hash_c # Check Compressed LZMA validity
						if not mod_hash_c_ok : # Skip Uncompressed LZMA hash if not needed
							mea_hash_u = get_hash(mod_data_d, len(mod_hash) // 2) # Uncompressed (few LZMA Modules)
							mod_hash_u_ok = mod_hash == mea_hash_u # Check Uncompressed LZMA validity
						
						if param.me11_mod_bug : # Debug
							if mod_hash_c_ok :
								print('\n    MOD: %s' % mod_hash) 
								print('    MEA: %s' % mea_hash_c)
							elif mod_hash_u_ok :
								print('\n    MOD: %s' % mod_hash) 
								print('    MEA: %s' % mea_hash_u)
							else :
								print('\n    MOD  : %s' % mod_hash)
								print('    MEA C: %s' % mea_hash_c)
								print('    MEA U: %s' % mea_hash_u)
						
						if mod_hash_c_ok or mod_hash_u_ok :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							with open(mod_fname, 'wb') as mod_file : mod_file.write(mod_data_d) # Decompression complete, valid data
						else :
							if param.me11_mod_bug and (mod_hash,mea_hash_c) not in cse_known_bad_hashes :
								input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
								
							with open(mod_fname, 'wb') as mod_file : mod_file.write(mod_data_d) # Decompression complete, invalid data
							
					# Open decompressed LZMA module for Hash validation, when Metadata info is not available
					# When the firmware lacks Module Metadata, check RBEP > rbe and FTPR > pm Modules instead
					elif rbe_pm_met_hashes :
						mea_hash_c = get_hash(mod_data_r, len(rbe_pm_met_hashes[0]) // 2) # Compressed, Header zeros included (most LZMA Modules)
						
						mod_hash_c_ok = mea_hash_c in rbe_pm_met_hashes # Check Compressed LZMA validity
						if not mod_hash_c_ok : # Skip Uncompressed LZMA hash if not needed
							mea_hash_u = get_hash(mod_data_d, len(rbe_pm_met_hashes[0]) // 2) # Uncompressed (few LZMA Modules)
							mod_hash_u_ok = mea_hash_u in rbe_pm_met_hashes # Check Uncompressed LZMA validity
						
						if param.me11_mod_bug : # Debug
							print('\n    MOD: No Metadata, validation via RBEP > rbe and FTPR > pm Modules') # Debug
							if mod_hash_c_ok :
								print('    MEA: %s' % mea_hash_c)
							elif mod_hash_u_ok :
								print('    MEA: %s' % mea_hash_u)
							else :
								print('    MEA C: %s' % mea_hash_c)
								print('    MEA U: %s' % mea_hash_u)
						
						if mod_hash_c_ok :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							rbe_pm_met_valid.append(mea_hash_c) # Store valid RBEP > rbe or FTPR > pm Hash to single out leftovers
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, valid data
						elif mod_hash_u_ok :
							print(col_g + '\n    Hash of %s %s "%s" is VALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							rbe_pm_met_valid.append(mea_hash_u) # Store valid RBEP > rbe or FTPR > pm Hash to single out leftovers
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, valid data
						else :
							if param.me11_mod_bug and (mod_hash,mea_hash_c) not in cse_known_bad_hashes :
								input(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
							else :
								print(col_r + '\n    Hash of %s %s "%s" is INVALID' % (comp[mod_comp], mod_type, mod_name) + col_e)
							
							with open(mod_fname, 'wb') as mod_file: mod_file.write(mod_data_d) # Decompression complete, invalid data
				
				except :
					if param.me11_mod_bug :
						input(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e) # Debug
					else :
						print(col_r + '\n    Failed to decompress %s %s "%s"' % (comp[mod_comp], mod_type, mod_name) + col_e)
						
					with open(mod_fname, 'wb') as mod_file : mod_file.write(mod_data) # Decompression failed
				
			# Print Manifest/Metadata/Key Extension Info
			ext_print_len = len(ext_print) # Final length of Extension Info list (must be after Manifest & Key extraction)
			if mod_type == 'metadata' or '.key' in mod_name :
				for index in range(0, ext_print_len, 2) : # Only Name (index), skip Info (index + 1)
					if str(ext_print[index]).startswith(mod_name) :
						if param.me11_mod_ext : print() # Print Manifest/Metadata/Key Extension Info
						for ext in ext_print[index + 1] :
							ext_str = ansi_escape.sub('', str(ext)) # Ignore Colorama ANSI Escape Character Sequences
							with open(mod_fname + '.txt', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % ext_str)
							if param.write_html :
								with open(mod_fname + '.html', 'a', encoding = 'utf-8') as text_file : text_file.write('\n<br/>\n%s' % pt_html(ext))
							if param.write_json :
								with open(mod_fname + '.json', 'a', encoding = 'utf-8') as text_file : text_file.write('\n%s' % pt_json(ext))
							if param.me11_mod_ext : print(ext) # Print Manifest/Metadata/Key Extension Info
						break
						
	return rbe_pm_met_valid
	
# Store and show CSE Analysis Errors
def cse_anl_err(ext_err_msg, checked_hashes) :
	if checked_hashes is None : checked_hashes = ('','')
	
	copy_file = False if checked_hashes in cse_known_bad_hashes else True
	err_stor.append([ext_err_msg, copy_file])
	
	if param.me11_mod_extr :
		if copy_file and param.me11_mod_bug : input('\n%s' % ext_err_msg)
		else : print('\n%s' % ext_err_msg)

# Get CSE File System Attributes & Configuration State
def get_mfs_anl(mfs_state, mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final, mfs_found) :
	try :
		if mfs_found and not param.me11_mod_extr :
			# Get CSE File System Attributes
			mfs_parsed_idx,intel_cfg_hash_mfs,mfs_info,pch_init_final = mfs_anl('NA', mfs_start, mfs_start + mfs_size, variant)
			
			# CSE File System exists, determine its Configuration State
			if 8 in mfs_parsed_idx : mfs_state = 'Initialized'
			elif 7 in mfs_parsed_idx : mfs_state = 'Configured'
	except :
		# CSE File System analysis failed, maybe corrupted
		mfs_state = col_r + 'Error' + col_e
		
	return mfs_state, mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final

# Analyze & Extract CSE File Systems
# noinspection PyUnusedLocal
def mfs_anl(mfs_folder, mfs_start, mfs_end, variant) :
	mfs_info = [] # MFS Initial Info Printing
	mfs_tmp_page = [] # MFS Temporary Pages Message Storage
	mfs_buffer_init = reading[mfs_start:mfs_end] # MFS Initial Buffer
	
	mfsb_hdr = get_struct(mfs_buffer_init, 0, MFS_Backup_Header, file_end) # Check if input MFS is in MFS Backup state
	if mfsb_hdr.Signature == 0x4253464D : # MFS Backup Signature is "MFSB"
		if param.me11_mod_extr :
			print('\n%s' % mfsb_hdr.mfs_print()) # Print Structure Info during CSE Unpacking
			mfs_info.append(mfsb_hdr.mfs_print()) # Store Structure Info during CSE Unpacking
		mfsb_buffer = mfs_buffer_init[ctypes.sizeof(mfsb_hdr):] # MFS Backup Buffer without Header
		mfsb_crc32 = mfsb_hdr.CRC32 # Intel CRC-32 of MFS Backup Buffer
		mea_crc32 = ~zlib.crc32(mfsb_buffer, -1) & 0xFFFFFFFF # MEA CRC-32 of MFS Backup Buffer
		mfsb_patterns = re.compile(br'\x01\x03\x02\x04').finditer(mfsb_buffer) # Each MFS Backup Chunk ends with 0x01030204
		mfsb_end = re.compile(br'\xFF{32}').search(mfsb_buffer).start() # MFS Backup Buffer ends where enough Padding (0xFF) is found
		
		if mfsb_crc32 != mea_crc32 : mfs_tmp_page = mfs_anl_msg(col_r + 'Error: MFS Backup Header CRC-32 is INVALID!' + col_e, 'error', False, False, [])
		else : mfs_tmp_page = mfs_anl_msg(col_g + 'MFS Backup Header CRC-32 is VALID' + col_e, '', False, False, [])
		
		data_start = 0 # Starting Offset of each MFS Backup Chunk
		mfs_buffer_init = b'' # Actual MFS Buffer from converted MFS Backup state
		for pattern in mfsb_patterns : # Iterate over all 0x01030204 chunk endings
			padding = int.from_bytes(mfsb_buffer[pattern.end():pattern.end() + 0x4], 'big') # The 4 bytes after 0x01030204 are Padding (0xFF) Size in BE
			mfs_buffer_init += (mfsb_buffer[data_start:pattern.start()] + b'\xFF' * padding) # Append Chunk Data to Actual MFS Buffer
			data_start = pattern.end() + 0x4 # Adjust Starting Offset to 0x01030204 + Padding Size
		mfs_buffer_init += mfsb_buffer[data_start:mfsb_end] # Append Last MFS Backup Chunk Contents as has no 0x01030204 ending
		mfs_buffer_init += b'\xFF' * (- len(mfs_buffer_init) % 0x2000) # Append EOF Alignment Padding based on MFS Page Size of 0x2000
	
	mfs_size = len(mfs_buffer_init) # MFS Total Length
	page_size = 0x2000 # MFS Page Length
	page_count = mfs_size // page_size # MFS Total Pages Count
	sys_count = page_count // 12 # MFS System Pages Count
	dat_count = page_count - sys_count - 1 # MFS Data Pages Count
	chunk_size = 0x42 # MFS Chunk Payload + CRC Length
	index_size_sys = 0x2 # MFS System Page Index Entry Length
	index_size_dat = 0x1 # MFS Data Page Index Entry Length
	page_hdr_size = 0x12 # MFS Page Header Structure Size
	vol_hdr_size = 0xE # MFS Volume Header Structure Size
	mfs_files = [] # MFS Low Level Files Numbers & Contents
	mfs_page_init = [] # MFS Total Unsorted Pages Contents
	sys_page_sorted = [] # MFS Total Sorted System Pages Contents
	dat_page_sorted = [] # MFS Total Sorted Data Pages Contents
	mfs_buffer_sorted = b'' # MFS Total Sorted Pages Contents Buffer
	chunks_count_sys = 0xFFFF # MFS Actual System Chunks Count
	all_chunks_dict = {} # MFS Total Chunk Index & Data Dictionary
	mfs_parsed_idx = [] # Store all parsed MFS Low Level Files
	intel_cfg_hash_mfs = None # Store MFS Low Level File 6 Hash
	pch_init_info = [] # Store PCH Initialization Table Info
	pch_init_final = [] # Store PCH Initialization Table Final Info
	chunks_max_sys = sys_count * ((page_size - page_hdr_size - index_size_sys) // (index_size_sys + chunk_size)) # MFS Maximum System Chunks Count
	chunks_max_dat = dat_count * ((page_size - page_hdr_size) // (index_size_dat + chunk_size)) # MFS Maximum Data Chunks Count (= Actual)
	
	# Set MFS Integrity Table Structure Size
	if (variant,major) in [('CSME',11),('CSTXE',3),('CSTXE',4),('CSSPS',4)] : sec_hdr_size = 0x34
	elif (variant,major) in [('CSME',12),('CSME',13),('CSME',14),('CSSPS',5)] : sec_hdr_size = 0x28
	else : sec_hdr_size = 0x28
	
	# Set MFS Config Record Structure Size
	if (variant,major) in [('CSME',11),('CSME',12),('CSTXE',3),('CSTXE',4),('CSSPS',4),('CSSPS',5)] : config_rec_size = 0x1C
	elif (variant,major) in [('CSME',13),('CSME',14)] : config_rec_size = 0xC
	else : config_rec_size = 0xC
	
	# Sort MFS System & Data Pages
	for page_index in range(page_count) :
		page_start = page_index * page_size # Page Offset
		page_hdr = get_struct(mfs_buffer_init, page_start, MFS_Page_Header, file_end) # Page Header Structure
		if page_hdr.FirstChunkIndex != 0 : chunks_count_sys = min(chunks_count_sys, page_hdr.FirstChunkIndex) # Store MFS Actual System Chunks Count
		# Page Number for System Page Sorting, Page First Chunk Index for Data Page Sorting, Page Contents
		mfs_page_init.append([page_hdr.PageNumber, page_hdr.FirstChunkIndex, mfs_buffer_init[page_start:page_start + page_size]])
	else :
		for i in range(len(mfs_page_init)) : # Parse all MFS unsorted System & Data Pages
			if mfs_page_init[i][1] == 0 : sys_page_sorted.append([mfs_page_init[i][0], mfs_page_init[i][2]]) # System Pages are sorted via Page Number
			else : dat_page_sorted.append([mfs_page_init[i][1], mfs_page_init[i][2]]) # Data Pages are sorted via Page First Chunk Index
		sys_page_sorted = [i[1] for i in sorted(sys_page_sorted, key=lambda sys: sys[0])] # Store System Pages after Page Number sorting
		dat_page_sorted = [i[1] for i in sorted(dat_page_sorted, key=lambda dat: dat[0])] # Store Data Pages after Page First Chunk Index sorting
		mfs_sorted = sys_page_sorted + dat_page_sorted # Store total MFS sorted System & Data Pages
		for data in mfs_sorted : mfs_buffer_sorted += data # Store MFS sorted Pages Contents Buffer
	
	mfs_pages_pt = ext_table([col_y + 'Type' + col_e, col_y + 'Signature' + col_e, col_y + 'Number' + col_e, col_y + 'Erase Count' + col_e,
				   col_y + 'Next Erase' + col_e, col_y + 'First Chunk' + col_e, col_y + 'CRC-8' + col_e, col_y + 'Reserved' + col_e], True, 1)
	mfs_pages_pt.title = col_y + 'MFS Page Records' + col_e
	
	# Parse each MFS Page sequentially
	for mfs_page in mfs_sorted :
		page_hdr = get_struct(mfs_page, 0, MFS_Page_Header, file_end) # Page Header Structure
		page_hdr_data = mfs_page[:page_hdr_size] # Page Header Data
		page_tag = page_hdr.Signature # Page Signature Tag
		page_number = page_hdr.PageNumber # Page Number starting from 1
		page_erase_count = page_hdr.EraseCount # Counter of Page Erases
		page_erase_next = page_hdr.NextErasePage # Page Number to be Erased Next
		page_chunk_first = page_hdr.FirstChunkIndex # Index number of Data Pages' 1st Chunk from total MFS Chunks (MFS start)
		page_hdr_crc8_int = page_hdr.CRC8 # Intel CRC-8 of Page Header (0x12) with initial value of 1
		page_reserved = page_hdr.Reserved # Page Reserved Data
		page_type = 'System' if page_chunk_first == 0 else 'Data' # Page System or Data Type
		
		# MEA CRC-8 of System/Data/Scratch Page Header (0x12) with initial value of 1
		if page_tag == 0xAA557887 :
			page_hdr_crc8_mea = crccheck.crc.Crc8.calc(page_hdr_data[:-2] + bytes(page_hdr_data[-1]), initvalue = 1)
		else :
			page_type = 'Scratch' # Only one Scratch Page initially exists at the MFS
			if not page_number : page_hdr_crc8_mea = 0 # Workaround only for Alpha CSME 11.0.0.1100 firmware (completely empty MFS Page Header)
			else : page_hdr_crc8_mea = crccheck.crc.Crc8.calc(b'\x87\x78\x55\xAA' + page_hdr_data[4:-2] + bytes(page_hdr_data[-1]), initvalue = 1) # Add MFS Signature
		
		mfs_pages_pt.add_row([page_type, '%0.8X' % page_tag, page_number, page_erase_count, page_erase_next, page_chunk_first, '0x%0.2X' % page_hdr_crc8_int, '0x%X' % page_reserved])
		
		# Verify System/Data/Scratch Page CRC-8
		if page_hdr_crc8_mea != page_hdr_crc8_int :
			mfs_tmp_page = mfs_anl_msg(col_r + 'Error: MFS %s Page %d Header CRC-8 is INVALID!' % (page_type, page_number) + col_e, 'error', True, False, mfs_tmp_page)
		else :
			mfs_tmp_page = mfs_anl_msg(col_g + 'MFS %s Page %d Header CRC-8 is VALID' % (page_type, page_number) + col_e, '', True, False, mfs_tmp_page)
		
		if page_tag != 0xAA557887 : continue # Skip Scratch Page after CRC-8 check
		
		# MFS System Page
		if page_type == 'System' :
			chunk_count = (page_size - page_hdr_size - index_size_sys) // (index_size_sys + chunk_size) # System Page Chunks have a 2-byte Index after Page Header
			index_size = chunk_count * index_size_sys + index_size_sys # System Page Total Chunk Indexes size is Chunk Count * Index Byte Length + Index Byte Length
			index_data_obf = mfs_page[page_hdr_size:page_hdr_size + index_size] # System Page Total Obfuscated Chunk Indexes Buffer
			index_values_obf = struct.unpack('%dH' % (chunk_count + 1), index_data_obf) # System Page Total Obfuscated Chunk Indexes List, each Index is 2 bytes
			chunk_start = page_hdr_size + index_size # System Page First Chunk Offset
			
			# Calculate actual System Page Chunk Indexes
			chunk_index = 0 # Unobfuscated System Page Chunk Index
			chunk_indexes = [] # Unobfuscated System Page Chunk Indexes
			for i in range(len(index_values_obf)) :
				# Obfuscated Index Bit 0 = 0 (0x8000) for Next Usable Entry, Obfuscated Index Bit 1 = 0 (0x4000) for Used Entry
				if index_values_obf[i] & 0xC000 : break # Skip all the Unused System Page Chunks when Bits 0-1 = 1 (0xC000) = Unused Entry
				chunk_index = Crc16_14(chunk_index) ^ index_values_obf[i] # Unobfuscated System Page Chunk Index via reverse CRC-16 14-bit (no 0 and 1)
				chunk_indexes.append(chunk_index) # Store all Unobfuscated System Page Chunk Indexes (subset of index_values_obf when Unused Entries exist)
			
			# Parse all Used System Page Chunks
			chunk_healthy = 0 # System Page Healthy Chunks Count
			chunk_used_count = len(chunk_indexes) # System Page Total Used Chunks Count
			for i in range(chunk_used_count) :
				chunk_index = chunk_indexes[i] # Index of used System Page Chunk from total MFS Chunks (MFS start)
				chunk_all = mfs_page[chunk_start + chunk_size * i:chunk_start + chunk_size * i + chunk_size] # System Page Chunk with CRC-16 (0x42)
				chunk_raw = chunk_all[:-2] # System Page Chunk without CRC-16 (0x40)
				all_chunks_dict[chunk_index] = chunk_raw # Store System Page Chunk Index & Contents
				
				chunk_crc16_int = int.from_bytes(chunk_all[0x40:0x42], 'little') # Intel CRC-16 of Chunk (0x40) with initial value of 0xFFFF
				chunk_crc16_mea = crccheck.crc.Crc16.calc(chunk_raw + struct.pack('<H', chunk_index), initvalue = 0xFFFF) # MEA CRC-16 of Chunk (0x40) with initial value of 0xFFFF
				
				if chunk_crc16_mea != chunk_crc16_int :
					mfs_tmp_page = mfs_anl_msg(col_r + 'Error: MFS %s Page %d > Chunk %d CRC-16 is INVALID!' % (page_type, page_number, chunk_index) + col_e, 'error', True, True, mfs_tmp_page)
				else :
					chunk_healthy += 1 #mfs_tmp_page = mfs_anl_msg(col_g + 'MFS %s Page %d > Chunk %d CRC-16 is VALID' % (page_type, page_number, chunk_index) + col_e, '', True, True, mfs_tmp_page)
			
			if chunk_used_count and chunk_used_count == chunk_healthy :
				mfs_tmp_page = mfs_anl_msg(col_g + 'All MFS %s Page %d Chunks (%d) CRC-16 are VALID' % (page_type, page_number, chunk_used_count) + col_e, '', True, True, mfs_tmp_page)
		
		# MFS Data Page
		elif page_type == 'Data' :
			chunk_count = (page_size - page_hdr_size) // (index_size_dat + chunk_size) # Data Page Chunks have a 1-byte Index after Page Header
			index_size = chunk_count * index_size_dat # Data Page Total Chunk Indexes size is Chunk Count * Index Byte Length
			index_data = mfs_page[page_hdr_size:page_hdr_size + index_size] # Data Page Total Chunk Indexes Buffer
			index_values = struct.unpack('%dB' % chunk_count, index_data) # Data Page Total Chunk Indexes List, each index is 1 byte
			chunk_start = page_hdr_size + index_size # Data Page First Chunk Offset
			
			# Parse all Used Data Page Chunks
			chunk_healthy = 0 # Data Page Healthy Chunks Count
			chunk_used_count = 0 # Data Page Total Used Chunks Count
			for i in range(len(index_values)) :
				if index_values[i] == 0 : # Used Data Page Chunk Index = 0x00, Unused = 0xFF
					chunk_used_count += 1 # Add Used Data Page Chunk to Total Used Count
					chunk_index = page_chunk_first + i # Index of used Data Page Chunk from total MFS Chunks (MFS start)
					chunk_all = mfs_page[chunk_start + chunk_size * i:chunk_start + chunk_size * i + chunk_size] # Data Page Chunk with CRC-16 (0x42)
					chunk_raw = chunk_all[:-2] # Data Page Chunk without CRC-16 (0x40)
					all_chunks_dict[chunk_index] = chunk_raw # Store Data Page Chunk Index & Contents
					chunk_crc16_int = int.from_bytes(chunk_all[0x40:0x42], 'little') # Intel CRC-16 of Chunk (0x40) with initial value of 0xFFFF
					chunk_crc16_mea = crccheck.crc.Crc16.calc(chunk_raw + struct.pack('<H', chunk_index), initvalue = 0xFFFF) # MEA CRC-16 of Chunk (0x40) with initial value of 0xFFFF
					
					if chunk_crc16_mea != chunk_crc16_int :
						mfs_tmp_page = mfs_anl_msg(col_r + 'Error: MFS %s Page %d > Chunk %d CRC-16 is INVALID!' % (page_type, page_number, chunk_index) + col_e, 'error', True, True, mfs_tmp_page)
					else :
						chunk_healthy += 1 #mfs_tmp_page = mfs_anl_msg(col_g + 'MFS %s Page %d > Chunk %d CRC-16 is VALID' % (page_type, page_number, chunk_index) + col_e, '', True, True, mfs_tmp_page)
			
			if chunk_used_count and chunk_used_count == chunk_healthy :
				mfs_tmp_page = mfs_anl_msg(col_g + 'All MFS %s Page %d Chunks (%d) CRC-16 are VALID' % (page_type, page_number, chunk_used_count) + col_e, '', True, True, mfs_tmp_page)
	
	# Print/Store MFS Page Records during CSE Unpacking
	if param.me11_mod_extr :
		print('\n%s' % mfs_pages_pt) # Show MFS Page Records Log before messages
		for page_msg in mfs_tmp_page : # Print MFS Page Records Messages after Log
			if page_msg[1] == 'error' and param.me11_mod_bug : input('\n%s' % page_msg[0])
			else : print('\n%s' % page_msg[0])
		mfs_info.append(mfs_pages_pt) # Store MFS Page Records Log during CSE Unpacking
	
	# Build MFS Total System Chunks Buffer
	all_mfs_sys = bytearray(chunks_count_sys * (chunk_size - 2)) # Empty System Area Buffer
	for i in range(chunks_count_sys) :
		# The final System Area Buffer must include all empty chunks for proper File Allocation Table parsing
		if i in all_chunks_dict : all_mfs_sys[i * (chunk_size - 2):(i + 1) * (chunk_size - 2)] = bytearray(all_chunks_dict[i])
	
	# Parse MFS System Volume Structure
	if not all_chunks_dict :
		mfs_anl_msg(col_r + 'Error: MFS final System Area Buffer is empty!' + col_e, 'error', False, False, [])
		return mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final # The final System Area Buffer must not be empty
	vol_hdr = get_struct(all_chunks_dict[0], 0, MFS_Volume_Header, file_end) # System Volume is at the LAST Index 0 Chunk (the dictionary does that automatically)
	if param.me11_mod_extr :
		print('\n%s' % vol_hdr.mfs_print()) # Print System Volume Structure Info during CSE Unpacking
		mfs_info.append(vol_hdr.mfs_print()) # Store System Volume Structure Info during CSE Unpacking
	vol_ftbl_id = vol_hdr.Unknown0 # File Table Dictionary ID ?
	vol_file_rec = vol_hdr.FileRecordCount # Number of File Records in Volume
	vol_total_size = vol_hdr.VolumeSize # Size of MFS System & Data Volume via Volume
	mea_total_size = chunks_count_sys * (chunk_size - 2) + chunks_max_dat * (chunk_size - 2) # Size of MFS System & Data Volume via MEA
	
	if vol_total_size != mea_total_size : mfs_tmp_page = mfs_anl_msg(col_r + 'Error: Detected MFS System Volume Size missmatch!' + col_e, 'error', False, False, [])
	else : mfs_tmp_page = mfs_anl_msg(col_g + 'MFS System Volume Size is VALID' + col_e, '', False, False, [])
	
	# Parse MFS File Allocation Table
	fat_count = vol_file_rec + chunks_max_dat # MFS FAT Value Count (Low Level Files + their Data Chunks)
	fat_trail = len(all_mfs_sys) - fat_count * 2 - vol_hdr_size # MFS FAT Value End Trail Count
	fat_values = struct.unpack_from('<%dH' % fat_count, all_mfs_sys, vol_hdr_size) # MFS FAT Values are 2 bytes each
	for index in range(vol_file_rec) : # Parse all MFS Volume (Low Level File) FAT Values
		if fat_values[index] in (0x0000,0xFFFE,0xFFFF) : # 0x0000 = Unused, 0xFFFE = Erased, 0xFFFF = Used but Empty
			mfs_files.append([index, None]) # Store MFS Low Level File Index & Contents
		else :
			file_chunks = b'' # Initial MFS Low Level File Contents Buffer
			fat_value = fat_values[index] # Initial Used File FAT Value
			
			# Parse Data/Chunk FAT Values for each Used Low Level File
			while True :
				# Data FAT Values (Low Level File Chunks) start after Volume FAT Values (Low Level File Numbers/1st Chunk)
				if fat_value < vol_file_rec :
					mfs_tmp_page = mfs_anl_msg(col_r + 'Error: Detected MFS File %d > FAT Value %d less than Volume Files Count %d!' % (index,fat_value,vol_file_rec) + col_e, 'error', False, False, [])
					break # Critical error while parsing Used File FAT Value
				
				# Data Page Chunks start after System Page Chunks and their Volume FAT Values
				file_chunk_index = chunks_count_sys + fat_value - vol_file_rec # Determine File Chunk Index for MFS Chunk Index & Data Dictionary use
				if file_chunk_index not in all_chunks_dict : # The File Chunk index/key must exist at the MFS Chunk Index & Data Dictionary
					mfs_tmp_page = mfs_anl_msg(col_r + 'Error: Detected MFS File %d > Chunk %d not in Total Chunk Index/Data Area!' % (index,file_chunk_index) + col_e, 'error', False, False, [])
					break # Critical error while parsing Used File FAT Value
				
				file_chunk = all_chunks_dict[file_chunk_index] # Get File Chunk contents from the MFS Chunk Index & Data Dictionary
				fat_value = fat_values[fat_value] # Get Next Chunk FAT Value by using the current value as List index (starts from 0)
				
				# Small FAT Values (1 - 64) are markers for both EOF and Size of last Chunk
				if 1 <= fat_value <= (chunk_size - 2) :
					file_chunks += file_chunk[:fat_value] # Append the last File Chunk with its size adjusted based on the EOF FAT Value marker
					break # File ends when the Next FAT Value is between 1 and 64 (EOF marker)
				
				file_chunks += file_chunk # Append File Chunk Contents to the MFS Low Level File Contents Buffer
			
			mfs_files.append([index, file_chunks]) # Store MFS Low Level File Index & Contents
	
	if all_mfs_sys[vol_hdr_size + fat_count * 2:] != b'\x00' * fat_trail : # MFS FAT End Trail Contents should be all zeros
		mfs_tmp_page = mfs_anl_msg(col_r + 'Error: Detected additional MFS System Buffer contents after FAT ending!' + col_e, 'error', False, False, [])
	
	# Parse MFS Low Level Files
	for mfs_file in mfs_files :
		# Parse MFS Low Level Files 1 (Unknown), 2-3 (Anti-Replay) and 4 (SVN Migration)
		if mfs_file[1] and mfs_file[0] in (1,2,3,4) :
			mfs_file_name = {1:'Unknown', 2:'Anti-Replay', 3:'Anti-Replay', 4:'SVN Migration'}
			if param.me11_mod_extr : print(col_g + '\n    Analyzing MFS Low Level File %d (%s) ...' % (mfs_file[0], mfs_file_name[mfs_file[0]]) + col_e)
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level File as Parsed
			file_folder = os.path.join(mea_dir, mfs_folder, '%0.3d %s' % (mfs_file[0], mfs_file_name[mfs_file[0]]), '')
			file_data = mfs_file[1][:-sec_hdr_size] # MFS Low Level File Contents without Integrity
			file_sec = mfs_file[1][-sec_hdr_size:] # MFS Low Level File Integrity without Contents
			file_sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size], file_end) # MFS Low Level File Integrity Structure
			if param.me11_mod_ext :
				file_sec_ptv = file_sec_hdr.mfs_print() # MFS Low Level File Integrity Structure Info
				file_sec_ptv.title = 'MFS %0.3d %s Integrity' % (mfs_file[0], mfs_file_name[mfs_file[0]]) # Adjust Integrity Structure Verbose Info Title
				print('\n%s' % file_sec_ptv) # Print Integrity Structure Info during Verbose CSE Unpacking
			file_data_path = os.path.join(file_folder, 'Contents.bin') # MFS Low Level File Contents Path
			file_sec_path = os.path.join(file_folder, 'Integrity.bin') # MFS Low Level File Integrity Path
			mfs_write(file_folder, file_data_path, file_data) # Store MFS Low Level File Contents
			mfs_write(file_folder, file_sec_path, file_sec) # Store MFS Low Level File Integrity
			mfs_txt(file_sec_hdr.mfs_print(), file_folder, file_sec_path, 'w', False) # Store/Print MFS Low Level File Integrity Info
		
		# Parse MFS Low Level File 5 (Quota Storage)
		elif mfs_file[1] and mfs_file[0] == 5 :
			if param.me11_mod_extr : print(col_g + '\n    Analyzing MFS Low Level File 5 (Quota Storage) ...' + col_e)
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level File 5 as Parsed
			file_folder = os.path.join(mea_dir, mfs_folder, '005 Quota Storage', '')
			file_data_path = os.path.join(file_folder, 'Contents.bin') # MFS Low Level File 5 Contents Path
			file_sec_path = os.path.join(file_folder, 'Integrity.bin') # MFS Low Level File 5 Integrity Path
			
			# Detect MFS Low Level File 5 (Quota Storage) Integrity
			if variant == 'CSME' and major >= 12 :
				file_data = mfs_file[1][:-sec_hdr_size] # MFS Low Level File 5 Contents without Integrity
				file_sec = mfs_file[1][-sec_hdr_size:] # MFS Low Level File 5 Integrity without Contents
				mfs_write(file_folder, file_sec_path, file_sec) # Store MFS Low Level File 5 Integrity
				file_sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size], file_end) # MFS Low Level File 5 Integrity Structure
				mfs_txt(file_sec_hdr.mfs_print(), file_folder, file_sec_path, 'w', False) # Store/Print MFS Low Level File 5 Integrity Info
				if param.me11_mod_ext :
					file_sec_ptv = file_sec_hdr.mfs_print() # MFS Low Level File 5 Integrity Structure Info
					file_sec_ptv.title = 'MFS 005 Quota Storage Integrity' # Adjust Integrity Structure Verbose Info Title
					print('\n%s' % file_sec_ptv) # Print Integrity Structure Info during Verbose CSE Unpacking
			else :
				file_data = mfs_file[1][:] # MFS Low Level File 5 Contents
			
			mfs_write(file_folder, file_data_path, file_data) # Store MFS Low Level File 5 Contents
		
		# Parse MFS Low Level File 6 (Intel Configuration) and 7 (OEM Configuration)
		elif mfs_file[1] and mfs_file[0] in (6,7) :	
			
			'''
			# Create copy of firmware with clean/unconfigured MFS (Linux only)
			# MFSTool by Peter Bosch (https://github.com/peterbjornx/meimagetool)
			if mfs_file[0] == 6 :
				import subprocess
				
				temp_dir = os.path.join(mea_dir, 'temp', '')
				out_dir = os.path.join(mea_dir, 'output', '')
				if os.path.isdir(temp_dir) : shutil.rmtree(temp_dir)
				os.mkdir(temp_dir)
				if not os.path.isdir(out_dir) : os.mkdir(out_dir)
				
				intl_cfg = os.path.join(temp_dir, 'intel.cfg')
				with open(intl_cfg, 'wb') as o : o.write(mfs_file[1])
				
				mfs_tmpl = {0x40000 : '256K.bin', 0x64000 : '400K.bin', 0x13E000 : '1272K.bin'}[mfs_size]
				
				clean_mfs_path = os.path.join(mea_dir, 'MFS_INTEL.bin')
				mfstool_path = os.path.join(mea_dir, 'mfstool')
				
				# The temp_dir for MFSTool must not include files other than intel.cfg and fitc.cfg
				mfstool = subprocess.run([mfstool_path, 'c', clean_mfs_path, mfs_tmpl, temp_dir])

				final = os.path.join(out_dir, os.path.basename(file_in))				

				if os.path.isfile(clean_mfs_path) :
					with open(clean_mfs_path, 'rb') as mfs_rgn : clean_mfs = mfs_rgn.read()
					if len(clean_mfs) != mfs_size : input('Error: MFS size mismatch!')
					new_mfs = reading[:mfs_start] + clean_mfs + reading[mfs_end:]
					with open(final, 'wb') as o : o.write(new_mfs)

				shutil.rmtree(temp_dir)
				os.remove(clean_mfs_path)
			'''
			
			mfs_file_name = {6:'Intel Configuration', 7:'OEM Configuration'}
			if param.me11_mod_extr : print(col_g + '\n    Analyzing MFS Low Level File %d (%s) ...' % (mfs_file[0], mfs_file_name[mfs_file[0]]) + col_e)
			if mfs_file[0] == 6 : intel_cfg_hash_mfs = [get_hash(mfs_file[1], 0x20), get_hash(mfs_file[1], 0x30)] # Store MFS Intel Configuration Hashes
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level Files 6,7 as Parsed
			rec_folder = os.path.join(mea_dir, mfs_folder, '%0.3d %s' % (mfs_file[0], mfs_file_name[mfs_file[0]]), '')
			root_folder = rec_folder # Store File Root Folder for Local Path printing
			
			pch_init_info = mfs_cfg_anl(mfs_file[0], mfs_file[1], rec_folder, root_folder, config_rec_size, pch_init_info, vol_ftbl_id) # Parse MFS Configuration Records
			pch_init_final = pch_init_anl(pch_init_info) # Parse MFS Initialization Tables and store their Platforms/Steppings
		
		# Parse MFS Low Level File 8 (Home Directory)
		elif mfs_file[1] and mfs_file[0] == 8 :	
			if param.me11_mod_extr : print(col_g + '\n    Analyzing MFS Low Level File 8 (Home Directory) ...' + col_e)
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level File 8 as Parsed
			root_folder = os.path.join(mea_dir, mfs_folder, '008 Home Directory', 'home', '') # MFS Home Directory Root/Start folder is called "home"
			init_folder = os.path.join(mea_dir, mfs_folder, '008 Home Directory', '') # MFS Home Directory Parent folder for printing
			
			# Detect MFS Home Directory Record Size
			home_rec_patt = list(re.compile(br'\x2E[\x00\xAA]{10}').finditer(mfs_file[1][:])) # Find the first Current (.) & Parent (..) directory markers
			if len(home_rec_patt) < 2 : mfs_tmp_page = mfs_anl_msg(col_r + 'Error: Detected unknown Home Directory Record Structure!' + col_e, 'error', False, False, [])
			home_rec_size = home_rec_patt[1].start() - home_rec_patt[0].start() - 1 # Determine MFS Home Directory Record Size via pattern offset difference
			file_8_data = mfs_file[1][:-sec_hdr_size] # MFS Home Directory Root/Start (Low Level File 8) Contents
			if divmod(len(file_8_data), home_rec_size)[1] != 0 :
				mfs_tmp_page = mfs_anl_msg(col_r + 'Error: Detected unknown Home Directory Record or Integrity Size!' + col_e, 'error', False, False, [])
				home_rec_size = 0x0 # Crash at next step due to division by 0
			
			file_8_records = divmod(len(file_8_data), home_rec_size)[0] # MFS Home Directory Root/Start (Low Level File 8) Records Count
			
			# Generate MFS Home Directory Records Log
			if sec_hdr_size == 0x34 :
				mfs_pt = ext_table([col_y + 'Index' + col_e, col_y + 'Path' + col_e, col_y + 'Type' + col_e, col_y + 'Size' + col_e, col_y + 'Integrity' + col_e, col_y + 'IR Salt' + col_e,
				col_y + 'Encryption' + col_e, col_y + 'SVN' + col_e, col_y + 'Nonce' + col_e, col_y + 'AntiReplay' + col_e, col_y + 'AR Index' + col_e, col_y + 'AR Random' + col_e,
				col_y + 'AR Counter' + col_e, col_y + 'Keys' + col_e, col_y + 'Rights' + col_e, col_y + 'User ID' + col_e, col_y + 'Group ID' + col_e, col_y + 'Unknown Access' + col_e,
				col_y + 'Unknown Integrity 1' + col_e, col_y + 'HMAC SHA-256' + col_e, col_y + 'Unknown Integrity 2' + col_e], True, 1)
				mfs_pt.title = col_y + 'MFS 008 Home Directory Records' + col_e
			elif sec_hdr_size == 0x28 :
				mfs_pt = ext_table([col_y + 'Index' + col_e, col_y + 'Path' + col_e, col_y + 'Type' + col_e, col_y + 'Size' + col_e, col_y + 'Integrity' + col_e, col_y + 'IR Salt' + col_e,
				col_y + 'Encryption' + col_e, col_y + 'SVN' + col_e, col_y + 'AntiReplay' + col_e, col_y + 'AR Index' + col_e, col_y + 'AR Random' + col_e, col_y + 'AR Counter' + col_e,
				col_y + 'Keys' + col_e, col_y + 'Rights' + col_e, col_y + 'User ID' + col_e, col_y + 'Group ID' + col_e, col_y + 'Unknown Access' + col_e, col_y + 'Unknown Integrity 1' + col_e,
				col_y + 'HMAC MD5' + col_e, col_y + 'Unknown Integrity 2' + col_e, col_y + 'Unknown Integrity 3' + col_e], True, 1)
				mfs_pt.title = col_y + 'MFS 008 Home Directory Records' + col_e
			else :
				mfs_pt = None
			
			mfs_home_anl(mfs_files, file_8_data, file_8_records, root_folder, home_rec_size, sec_hdr_size, mfs_parsed_idx, init_folder, mfs_pt) # Parse MFS Home Directory Root/Start Records
			
			mfs_txt(mfs_pt, init_folder, os.path.join(init_folder + 'home_records'), 'w', True) # Store/Print MFS Home Directory Records Log
		
		# Parse MFS Low Level File 9 (Manifest Backup), if applicable
		elif mfs_file[1] and mfs_file[0] == 9 and man_pat.search(mfs_file[1][:0x20]) :
			if param.me11_mod_extr : print(col_g + '\n    Analyzing MFS Low Level File 9 (Manifest Backup) ...' + col_e)
			mfs_parsed_idx.append(mfs_file[0]) # Set MFS Low Level File 9 as Parsed
			file_9_folder = os.path.join(mea_dir, mfs_folder, '009 Manifest Backup', '') # MFS Manifest Backup root folder
			file_9_data_path = os.path.join(file_9_folder, 'FTPR.man') # MFS Manifest Backup Contents Path
			mfs_write(file_9_folder, file_9_data_path, mfs_file[1]) # Store MFS Manifest Backup Contents
			# noinspection PyTypeChecker
			ext_print = ext_anl(mfs_file[1], '$MN2', 0x1B, file_end, [variant,major,minor,hotfix,build], 'FTPR.man', [mfs_parsed_idx,intel_cfg_hash_mfs]) # Get Manifest Backup Extension Info
			for man_pt in ext_print[1] : mfs_txt(man_pt, file_9_folder, os.path.join(file_9_folder + 'FTPR.man'), 'a', False) # Store MFS Manifest Backup Extension Info
		
	# Store all Non-Parsed MFS Low Level Files
	for mfs_file in mfs_files :
		if mfs_file[1] and mfs_file[0] not in mfs_parsed_idx : # Check if MFS Low Level File has Contents but it has not been Parsed
			mfs_tmp_page = mfs_anl_msg(col_r + 'Error: Detected MFS Low Level File %d which has not been parsed!' % (mfs_file[0]) + col_e, 'error', False, False, [])
			mfs_file_path = os.path.join(mfs_folder, '%0.3d.bin' % mfs_file[0])
			mfs_write(mfs_folder, mfs_file_path, mfs_file[1]) # Store MFS Low Level File
		
	# Remember to also update any prior function return statements
	return mfs_parsed_idx, intel_cfg_hash_mfs, mfs_info, pch_init_final

# Parse all MFS Home Directory Records Recursively
# noinspection PyUnusedLocal
def mfs_home_anl(mfs_files, file_buffer, file_records, root_folder, home_rec_size, sec_hdr_size, mfs_parsed_idx, init_folder, mfs_pt) :
	for record in range(file_records) : # Process MFS Home Directory Record
		file_rec = get_struct(file_buffer, record * home_rec_size, home_rec_struct[home_rec_size], file_end) # MFS Home Directory Record Structure
		file_name = file_rec.FileName.decode('utf-8') # MFS Home Directory Record Name
		user_id = '0x%0.4X' % file_rec.OwnerUserID # MFS Home Directory Record Owner User ID
		group_id = '0x%0.4X' % file_rec.OwnerGroupID # MFS Home Directory Record Owner Group ID
		unk_salt = file_rec.UnknownSalt # MFS Home Directory Record Unknown Integrity Salt
		file_index,integrity_salt,fs_id,unix_rights,integrity,encryption,anti_replay,acc_unk0,key_type,rec_type,acc_unk1 = file_rec.get_flags() # Get MFS Home Directory Record Flags
		
		file_data = mfs_files[file_index][1] if mfs_files[file_index][1] else b'' # MFS Home Directory Record Contents
		
		acc_unk_flags = '{0:01b}b'.format(acc_unk0) + ' {0:01b}b'.format(acc_unk1) # Store Unknown Record Access Flags
		
		unix_rights = ''.join(map(str, file_rec.get_rights(unix_rights))) # Store Record Access Unix Rights
		
		integrity_salt = '' if not integrity and not integrity_salt else '0x%0.4X' % integrity_salt # Initialize Integrity Salt
		
		# Initialize Unknown Integrity Salt
		if not integrity and not unk_salt : unk_salt = ''
		elif home_rec_size == 0x18 : unk_salt = '0x%0.4X' % file_rec.UnknownSalt 
		elif home_rec_size == 0x1C : unk_salt = '0x' + ''.join('%0.4X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(file_rec.UnknownSalt))
		else : unk_salt = '0x%X' % unk_salt
		
		# Initialize Integrity related variables
		sec_hmac, sec_encr_nonce, sec_ar_random, sec_ar_counter, sec_svn, sec_ar_idx, sec_res, sec_unk, sec_unk_flags = [''] * 9
		sec_unk0, sec_ar, sec_encr, sec_unk1, sec_unk2, sec_unk3, sec_unk4 = [0] * 7
		sec_hdr = None
		file_sec = b''
		
		# Perform Integrity related actions
		if integrity :
			# Split MFS Home Directory Record Contents & Integrity, if Integrity Protection is present
			file_data = mfs_files[file_index][1][:-sec_hdr_size] if mfs_files[file_index][1] else b'' # MFS Home Directory Record Contents without Integrity
			file_sec = mfs_files[file_index][1][-sec_hdr_size:] if mfs_files[file_index][1] else b'' # MFS Home Directory Record Integrity without Contents
			
			# Parse MFS Home Directory Record Integrity Info
			if file_sec : 
				sec_hdr = get_struct(file_sec, 0, sec_hdr_struct[sec_hdr_size], file_end) # MFS Home Directory Record/File or Record/Folder Integrity Structure
				
				if sec_hdr_size == 0x34 :
					sec_unk0, sec_ar, sec_encr, sec_unk1, sec_ar_idx, sec_unk2, sec_svn, sec_unk3 = sec_hdr.get_flags()
					
					sec_unk_flags = '{0:01b}b'.format(sec_unk0) + ' {0:07b}b'.format(sec_unk1) + ' {0:03b}b'.format(sec_unk2) + ' {0:01b}b'.format(sec_unk3)
					sec_hmac = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(sec_hdr.HMACSHA256))
					sec_encr_nonce = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(sec_hdr.ARValues_Nonce)) if sec_encr else ''
					sec_ar_random = '0x%0.8X' % struct.unpack_from('<I', sec_hdr.ARValues_Nonce, 0)[0] if sec_ar else ''
					sec_ar_counter = '0x%0.8X' % struct.unpack_from('<I', sec_hdr.ARValues_Nonce, 4)[0] if sec_ar else ''
					if not sec_encr : sec_svn = ''
					if not sec_ar : sec_ar_idx = ''
				
				elif sec_hdr_size == 0x28 :
					sec_unk0, sec_ar, sec_unk1, sec_encr, sec_unk2, sec_ar_idx, sec_unk3, sec_svn, sec_unk4 = sec_hdr.get_flags()
					
					sec_unk_flags = '{0:01b}b'.format(sec_unk0) + ' {0:01b}b'.format(sec_unk1) + ' {0:07b}b'.format(sec_unk2) + ' {0:01b}b'.format(sec_unk3) + ' {0:02b}b'.format(sec_unk4)
					sec_hmac = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(sec_hdr.HMACMD5))
					sec_unk = '0x' + ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(sec_hdr.Unknown))
					sec_ar_random = '0x%0.8X' % sec_hdr.ARRandom if sec_ar else ''
					sec_ar_counter = '0x%0.8X' % sec_hdr.ARCounter if sec_ar else ''
					if not sec_encr : sec_svn = ''
					if not sec_ar : sec_ar_idx = ''
		
		# Store & Print MFS Home Directory Root/Start (8) Record Contents & Integrity Info
		if file_index == 8 and file_name == '.' : # MFS Low Level File 8 at Current (.) directory
			home_path = os.path.normpath(os.path.join(root_folder, '..', 'home')) # Set MFS Home Directory Root/Start Record Path
			file_rec_8 = file_rec # Duplicate MFS Home Directory Root/Start Record for adjustments
			file_rec_8.FileName = b'home' # Adjust MFS Home Directory Root/Start Record File Name from "." to "home" for printing
			file_rec_p = file_rec_8.mfs_print() # Get MFS Home Directory Root/Start Record PrettyTable Object after adjustment
			file_rec_p.add_row(['Path', 'home']) # Add MFS Home Directory Root/Start Record Local Path "home" for printing
			mfs_txt(file_rec_p, home_path, home_path, 'w', False) # Store/Print MFS Home Directory Root/Start Record Info
			sec_path = os.path.normpath(os.path.join(init_folder, 'home_integrity')) # Set MFS Home Directory Root/Start Record Integrity Path
			mfs_write(os.path.normpath(os.path.join(init_folder)), sec_path, file_sec) # Store MFS Home Directory Root/Start Record Integrity Contents
			mfs_txt(sec_hdr.mfs_print(), home_path, home_path + '_integrity', 'w', False) # Store/Print MFS Home Directory Root/Start Record Integrity Info
			
		# Set current Low Level File as Parsed, skip Folder Marker Records
		if file_name not in ('.','..') : mfs_parsed_idx.append(file_index)
		
		# Detect File System ID mismatch within MFS Home Directory
		if file_index >= 8 and fs_id != 1 : # File System ID for MFS Home Directory (Low Level File >= 8) is 1 (home)
			mfs_tmp_page = mfs_anl_msg(col_r + 'Error: Detected bad File System ID %d at MFS Home Directory > %0.3d %s' % (fs_id, file_index, file_name) + col_e, 'error', False, False, [])
		
		# MFS Home Directory Record Nested Records Count
		file_records = divmod(len(file_data), home_rec_size)[0]
		
		# MFS Home Directory Record is a Folder Marker
		if file_name in ('.','..') :
			folder_path = os.path.normpath(os.path.join(root_folder, file_name, '')) # Set currently working MFS Home Directory Record/Folder Path
			rec_path = os.path.relpath(folder_path, start=init_folder) if file_index >= 8 else mfs_type[fs_id] # Set actual Record Path for printing
			
			if mfs_parsed_idx[-1] != 8 : continue # Skip logging & further parsing for Current (.) & Parent (..) directories of Low Level Files after 8 (home)
			
			# Append MFS Home Directory Record/Folder Info to Log
			if sec_hdr_size == 0x34 :
				# noinspection PyUnboundLocalVariable
				mfs_pt.add_row([file_index, rec_path, 'Folder', '', ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, sec_encr_nonce, ['No','Yes'][anti_replay], 
				sec_ar_idx, sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_unk_flags])
			
			elif sec_hdr_size == 0x28 :
				# noinspection PyUnboundLocalVariable
				mfs_pt.add_row([file_index, rec_path, 'Folder', '', ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, ['No','Yes'][anti_replay], sec_ar_idx,
				sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_unk_flags, sec_unk])
			
			continue # Log but skip further parsing of Current (.) & Parent (..) Low Level File 8 (home) directories
		
		# MFS Home Directory Record is a File (Type 0)
		if rec_type == 0 :
			file_path = os.path.normpath(os.path.join(root_folder, file_name)) # Set MFS Home Directory Record/File Path
			rec_path = os.path.relpath(file_path, start=init_folder) if file_index >= 8 else mfs_type[fs_id] # Set actual Record Path for printing
			mfs_write(os.path.normpath(os.path.join(root_folder)), file_path, file_data) # Store MFS Home Directory Record/File Contents
			file_rec_p = file_rec.mfs_print() # Get MFS Home Directory Record/File PrettyTable Object for printing adjustments
			file_rec_p.add_row(['Path', rec_path]) # Add MFS Home Directory Record/File Local Path for printing
			mfs_txt(file_rec_p, os.path.normpath(os.path.join(root_folder)), file_path, 'w', False) # Store/Print MFS Home Directory Record/File Info
			
			if integrity : # Store & Print MFS Home Directory Record/File Integrity
				sec_path = os.path.normpath(os.path.join(root_folder, file_name + '_integrity')) # Set MFS Home Directory Record/File Integrity Path
				mfs_write(os.path.normpath(os.path.join(root_folder)), sec_path, file_sec) # Store MFS Home Directory Record/File Integrity Contents
				mfs_txt(sec_hdr.mfs_print(), os.path.normpath(os.path.join(root_folder)), sec_path, 'w', False) # Store/Print MFS Home Directory Record/File Integrity Info
			
			# Append MFS Home Directory Record/File Info to Log
			if sec_hdr_size == 0x34 :
				mfs_pt.add_row([file_index, rec_path, 'File', '0x%X' % len(file_data), ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, sec_encr_nonce,
				['No','Yes'][anti_replay], sec_ar_idx, sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_unk_flags])
			
			elif sec_hdr_size == 0x28 :
				mfs_pt.add_row([file_index, rec_path, 'File', '0x%X' % len(file_data), ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, ['No','Yes'][anti_replay],
				sec_ar_idx, sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_unk_flags, sec_unk])
		
		# MFS Home Directory Record is a Folder (Type 1)
		else :
			folder_path = os.path.normpath(os.path.join(root_folder, file_name, '')) # Set currently working MFS Home Directory Record/Folder Path
			rec_path = os.path.relpath(folder_path, start=init_folder) if file_index >= 8 else mfs_type[fs_id] # Set actual Record Path for printing
			file_rec_p = file_rec.mfs_print() # Get MFS Home Directory Record/Folder PrettyTable Object for printing adjustments
			file_rec_p.add_row(['Path', rec_path]) # Add MFS Home Directory Record/File Local Path for printing
			mfs_txt(file_rec_p, folder_path, folder_path, 'w', False) # Store/Print MFS Home Directory Record/Folder Info
			
			if integrity : # Store & Print MFS Home Directory Record/Folder Integrity
				sec_path = os.path.normpath(os.path.join(root_folder, file_name + '_integrity')) # Set MFS Home Directory Record/Folder Integrity Path
				mfs_write(os.path.normpath(os.path.join(root_folder)), sec_path, file_sec) # Store MFS Home Directory Record/Folder Integrity Contents
				mfs_txt(sec_hdr.mfs_print(), folder_path, folder_path + '_integrity', 'w', False) # Store/Print MFS Home Directory Record/Folder Integrity Info
			
			# Append MFS Home Directory Record/Folder Info to Log
			if sec_hdr_size == 0x34 :
				mfs_pt.add_row([file_index, rec_path, 'Folder', '', ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, sec_encr_nonce, ['No','Yes'][anti_replay],
				sec_ar_idx, sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_unk_flags])
			
			elif sec_hdr_size == 0x28 :
				mfs_pt.add_row([file_index, rec_path, 'Folder', '', ['No','Yes'][integrity], integrity_salt, ['No','Yes'][encryption], sec_svn, ['No','Yes'][anti_replay], sec_ar_idx,
				sec_ar_random, sec_ar_counter, ['Intel','Other'][key_type], unix_rights, user_id, group_id, acc_unk_flags, unk_salt, sec_hmac, sec_unk_flags, sec_unk])
			
			mfs_home_anl(mfs_files, file_data, file_records, folder_path, home_rec_size, sec_hdr_size, mfs_parsed_idx, init_folder, mfs_pt) # Recursively parse all Folder Records
	
# Parse all MFS Configuration (Low Level Files 6 & 7) Records
# noinspection PyUnusedLocal
def mfs_cfg_anl(mfs_file, buffer, rec_folder, root_folder, config_rec_size, pch_init_info, vol_ftbl_id) :
	mfs_pt = None
	ftbl_dict = {}
	ftbl_json = os.path.join(mea_dir, 'FileTable.dat')
	
	# Generate MFS Configuration Records Log
	if config_rec_size == 0x1C :
		mfs_pt = ext_table([col_y + 'Path' + col_e, col_y + 'Type' + col_e, col_y + 'Size' + col_e, col_y + 'Integrity' + col_e, col_y + 'Encryption' + col_e,
				 col_y + 'AntiReplay' + col_e, col_y + 'Rights' + col_e, col_y + 'User ID' + col_e, col_y + 'Group ID' + col_e, col_y + 'FIT' + col_e,
				 col_y + 'MCA' + col_e, col_y + 'Reserved' + col_e, col_y + 'Unknown Access' + col_e, col_y + 'Unknown Options' + col_e], True, 1)
	elif config_rec_size == 0xC :
		mfs_pt = ext_table([col_y + 'Path' + col_e, col_y + 'ID' + col_e, col_y + 'Size' + col_e, col_y + 'FIT' + col_e, col_y + 'Unknown Flags' + col_e], True, 1)
		
		# Check if MFS File Table Dictionary file exists
		if os.path.isfile(ftbl_json) :
			with open(ftbl_json, 'r') as json_file : ftbl_dict = json.load(json_file)
		else :
			mfs_tmp_page = mfs_anl_msg(col_r + 'Error: MFS File Table Dictionary file is missing!' + col_e, 'error', False, False, [])
		
	mfs_pt.title = col_y + 'MFS %s Configuration Records' % ('006 Intel' if mfs_file == 6 else '007 OEM') + col_e
	
	rec_count = int.from_bytes(buffer[:4], 'little') # MFS Configuration Records Count
	for rec in range(rec_count) : # Parse all MFS Configuration Records
		rec_hdr = get_struct(buffer[4:], rec * config_rec_size, config_rec_struct[config_rec_size], file_end) # MFS Configuration Record Structure
		rec_hdr_pt = rec_hdr.mfs_print() # MFS Configuration Record PrettyTable Object
		
		if config_rec_size == 0x1C :
			rec_name = rec_hdr.FileName.decode('utf-8') # File or Folder Name
			rec_size = rec_hdr.FileSize # File Size
			rec_res = '0x%0.4X' % rec_hdr.Reserved # Reserved
			rec_offset = rec_hdr.FileOffset # File Offset relative to MFS Low Level File start
			rec_user_id = '0x%0.4X' % rec_hdr.OwnerUserID # Owner User ID
			rec_group_id = '0x%0.4X' % rec_hdr.OwnerGroupID # Owner Group ID
			unix_rights,integrity,encryption,anti_replay,record_type,acc_unk,fitc_cfg,mca_upd,opt_unk = rec_hdr.get_flags() # Get Record Flags
			
			rec_size_p = '' if (record_type,rec_size) == (1,0) else '0x%X' % rec_size # Set Folder/File Size value for printing
			
			if record_type == 1 : # Set currently working Folder (Name or ..)
				rec_folder = os.path.normpath(os.path.join(rec_folder, rec_name, '')) # Add Folder name to path and adjust it automatically at ..
				local_mfs_path = os.path.relpath(rec_folder, start=root_folder) # Create Local MFS Folder Path
				rec_hdr_pt.add_row(['Path', local_mfs_path]) # Add Local MFS Folder Path to MFS Configuration Record Structure Info
				if rec_name not in ('.','..') : mfs_txt(rec_hdr_pt, rec_folder, rec_folder, 'w', False) # Store/Print MFS Configuration Record Info, skip folder markers
			else : # Set & Store currently working File (Name & Contents)
				rec_file = os.path.join(rec_folder, rec_name) # Add File name to currently working Folder path
				rec_data = buffer[rec_offset:rec_offset + rec_size] # Get File Contents from MFS Low Level File
				mfs_write(rec_folder, rec_file, rec_data) # Store File to currently working Folder
				local_mfs_path = os.path.relpath(rec_file, start=root_folder) # Create Local MFS File Path
				rec_hdr_pt.add_row(['Path', local_mfs_path]) # Add Local MFS File Path to MFS Configuration Record Structure Info
				mfs_txt(rec_hdr_pt, rec_folder, rec_file, 'w', False) # Store/Print MFS Configuration Record Info
				
				# Get PCH info via MFS Intel Configuration > PCH Initialization Table
				if mfs_file == 6 and rec_name.startswith('mphytbl') : pch_init_info = mphytbl(mfs_file, rec_data, pch_init_info)
			
			if rec_name == '..' : continue # Parse but skip logging of Parent (..) directory
		
			# Append MFS Configuration Record Info to Log
			mfs_pt.add_row([local_mfs_path, ['File','Folder'][record_type], rec_size_p, ['No','Yes'][integrity], ['No','Yes'][encryption], ['No','Yes'][anti_replay],
			''.join(map(str, rec_hdr.get_rights(unix_rights))), rec_user_id, rec_group_id, ['No','Yes'][fitc_cfg], ['No','Yes'][mca_upd], rec_res,
			'{0:03b}b'.format(acc_unk), '{0:014b}b'.format(opt_unk)])
			
		elif config_rec_size == 0xC :
			rec_id = rec_hdr.FileID # File ID relative to MFS System Volume FTBL Dictionary
			rec_offset = rec_hdr.FileOffset # File Offset relative to MFS Low Level File start
			rec_size = rec_hdr.FileSize # File Size
			fitc_cfg,flag_unk = rec_hdr.get_flags() # Get Record Flags
			
			if '%0.2X' % vol_ftbl_id not in ftbl_dict :
				if ftbl_dict : mfs_tmp_page = mfs_anl_msg(col_r + 'Error: File Table Dictionary %0.2X does not exist!' % vol_ftbl_id + col_e, 'error', False, False, [])
				rec_path = os.path.normpath(os.path.join('/Unknown', '%0.8X.bin' % rec_id)) # Set generic/unknown File local path when errors occur
				rec_file = os.path.normpath(rec_folder + rec_path) # Set generic/unknown File actual path when errors occur
				rec_parent = os.path.normpath(os.path.join(rec_folder, 'Unknown')) # Set generic/unknown parent Folder actual path when errors occur
			elif '%0.8X' % rec_id not in ftbl_dict['%0.2X' % vol_ftbl_id] :
				if ftbl_dict : mfs_tmp_page = mfs_anl_msg(col_r + 'Error: File Table Dictionary %0.2X does not contain ID %0.8X!' % (vol_ftbl_id,rec_id) + col_e, 'error', False, False, [])
				rec_path = os.path.normpath(os.path.join('/Unknown', '%0.8X.bin' % rec_id)) # Set generic/unknown File local path when errors occur
				rec_file = os.path.normpath(rec_folder + rec_path) # Set generic/unknown File actual path when errors occur
				rec_parent = os.path.normpath(os.path.join(rec_folder, 'Unknown')) # Set generic/unknown parent Folder actual path when errors occur
			else :
				rec_path = os.path.normpath(ftbl_dict['%0.2X' % vol_ftbl_id]['%0.8X' % rec_id]) # Get File local path from FTBL Dictionary
				rec_file = os.path.normpath(rec_folder + rec_path) # Set File actual path from FTBL Dictionary
				rec_parent = os.path.normpath(os.path.dirname(rec_file)) # Adjust parent Folder actual path from FTBL Dictionary
			
			rec_name = os.path.basename(rec_file) # Get File Name
			rec_data = buffer[rec_offset:rec_offset + rec_size] # Get File Contents from MFS Low Level File
			mfs_write(rec_parent, rec_file, rec_data) # Store File to currently working Folder
			rec_hdr_pt.add_row(['Path', rec_path]) # Add Local MFS File Path to MFS Configuration Record Structure Info
			mfs_txt(rec_hdr_pt, rec_parent, rec_file, 'w', False) # Store/Print MFS Configuration Record Info
			
			# Get PCH info via MFS Intel Configuration > PCH Initialization Table
			if mfs_file == 6 and rec_name.startswith('mphytbl') : pch_init_info = mphytbl(mfs_file, rec_data, pch_init_info)
			
			# Append MFS Configuration Record Info to Log
			mfs_pt.add_row([rec_path, '0x%0.8X' % rec_id, '0x%0.4X' % rec_size, ['No','Yes'][fitc_cfg], '{0:015b}b'.format(flag_unk)])
		
	mfs_txt(mfs_pt, root_folder, os.path.join(root_folder + 'home_records'), 'w', True) # Store/Print MFS Configuration Records Log
	
	return pch_init_info
	
# Analyze MFS Intel Configuration > PCH Initialization Table
def mphytbl(mfs_file, rec_data, pch_init_info) :
	pch_init_plt = pch_dict[rec_data[3] >> 4] if rec_data[3] >> 4 in pch_dict else 'Unknown' # Actual PCH SKU Platform (CNP-H, ICP-LP etc)
	pch_init_stp = rec_data[3] & 0xF # Raw PCH Stepping(s), Absolute or Bitfield depending on firmware
	pch_init_rev = rec_data[2] # PCH Initialization Table Revision
	pch_true_stp = '' # Actual PCH Stepping(s) (A, B, C etc)
	
	if rec_data[0x2:0x6] == b'\xFF' * 4 : return pch_init_info # FUI!
	
	# Detect Actual PCH Stepping(s) for CSME 11 & CSSPS 4
	if (variant,major) in [('CSME',11),('CSSPS',4)] :
		if mn2_ftpr_hdr.Year > 0x2015 or (mn2_ftpr_hdr.Year == 0x2015 and mn2_ftpr_hdr.Month > 0x05) \
		or (mn2_ftpr_hdr.Year == 0x2015 and mn2_ftpr_hdr.Month == 0x05 and mn2_ftpr_hdr.Day >= 0x19) :
			# Absolute for CSME >=~ 11.0.0.1140 @ 2015-05-19 (0 = A, 1 = B, 2 = C, 3 = D etc)
			pch_true_stp = {0:'A',1:'B',2:'C',3:'D',4:'E'}[pch_init_stp]
		else :
			# Unreliable for CSME ~< 11.0.0.1140 @ 2015-05-19 (always 80 --> SPT/KBP-LP A)
			pass
	
	# Detect Actual PCH Stepping(s) for CSME 12-14 & CSSPS 5
	elif (variant,major) in [('CSME',12),('CSME',13),('CSME',14),('CSSPS',5)] :
		if mn2_ftpr_hdr.Year > 0x2018 or (mn2_ftpr_hdr.Year == 0x2018 and mn2_ftpr_hdr.Month > 0x01) \
		or (mn2_ftpr_hdr.Year == 0x2018 and mn2_ftpr_hdr.Month == 0x01 and mn2_ftpr_hdr.Day >= 0x25) :
			# Bitfield for CSME >=~ 12.0.0.1058 @ 2018-01-25 (0011 = --BA, 0110 = -CB-)
			for i in range(4) : pch_true_stp += 'DCBA'[i] if pch_init_stp & (1<<(4-1-i)) else ''
		else :
			# Absolute for CSME ~< 12.0.0.1058 @ 2018-01-25 (0 = A, 1 = B, 2 = C, 3 = D etc)
			pch_true_stp = {0:'A',1:'B',2:'C',3:'D',4:'E'}[pch_init_stp]
		
	pch_init_info.append([mfs_file, pch_init_plt, pch_true_stp, pch_init_rev]) # Output PCH Initialization Table Info
	
	return pch_init_info
	
# MFS 14-bit CRC-16 for System Page Chunk Indexes (from parseMFS by Dmitry Sklyarov)
def Crc16_14(w, crc=0x3FFF) :
	CRC16tab = [0]*256
	for i in range(256):
		r = i << 8
		for j in range(8): r = (r << 1) ^ (0x1021 if r & 0x8000 else 0)
		CRC16tab[i] = r & 0xFFFF
	
	for b in bytearray(struct.pack('<H', w)): crc = (CRC16tab[b ^ (crc >> 8)] ^ (crc << 8)) & 0x3FFF
	
	return crc
	
# Write/Print MFS Structures Information
def mfs_txt(struct_print, folder_path, file_path_wo_ext, mode, is_log) :
	if param.me11_mod_extr : # Write Text File during CSE Unpacking
		struct_txt = ansi_escape.sub('', str(struct_print)) # Ignore Colorama ANSI Escape Character Sequences
		
		os.makedirs(folder_path, exist_ok=True) # Create the Text File's parent Folder, if needed
		
		if param.me11_mod_ext and is_log : print('\n%s' % struct_txt) # Print Structure Info
		
		with open(file_path_wo_ext + '.txt', mode, encoding = 'utf-8') as txt : txt.write('\n%s' % struct_txt) # Store Structure Info Text File
		if param.write_html :
			with open(file_path_wo_ext + '.html', mode, encoding = 'utf-8') as html : html.write('\n<br/>\n%s' % pt_html(struct_print)) # Store Structure Info HTML File
		if param.write_json :
			with open(file_path_wo_ext + '.json', mode, encoding = 'utf-8') as html : html.write('\n%s' % pt_json(struct_print)) # Store Structure Info JSON File
	
# Write MFS File Contents
def mfs_write(folder_path, file_path, data) :
	if param.me11_mod_extr or param.me11_mod_bug : # Write File during CSE Unpacking
		os.makedirs(folder_path, exist_ok=True) # Create the File's parent Folder, if needed
		
		with open(file_path, 'wb') as file : file.write(data)
		
# Store and show MFS Analysis Errors
def mfs_anl_msg(mfs_err_msg, msg_type, is_page, is_chunk_crc, mfs_tmp_page) :
	if msg_type == 'error' : err_stor.append([mfs_err_msg, True])
	
	if param.me11_mod_extr and not is_page :
		if msg_type == 'error' and param.me11_mod_bug : input('\n    %s' % mfs_err_msg)
		else : print('\n    %s' % mfs_err_msg)
		
	if is_page :
		if is_chunk_crc : mfs_err_msg = '    ' + mfs_err_msg # Extra Tab at Page Chunk CRC messages for visual purposes (-unp86)
		mfs_tmp_page.append(('    ' + mfs_err_msg, msg_type)) # Pause on error (-bug86) handled by caller
		
	return mfs_tmp_page
	
# Analyze CSE PCH Initialization Table Platforms/Steppings
def pch_init_anl(pch_init_info) :
	pch_init_final = []
	final_print = ''
	final_db = ''
	
	# pch_init_info = [[MFS File, Chipset, Stepping, Patch], etc]
	# pch_init_final = [[Chipset, Steppings], etc, [Total Platforms/Steppings, Total DB Steppings]]
	
	# Skip analysis if no Initialization Table or Stepping was detected
	if not pch_init_info or pch_init_info[0][2] == '' : return pch_init_final
	
	# Store each Chipset once
	for info in pch_init_info :
		skip = False
		for final in pch_init_final :
			if info[1] == final[0] : skip = True
		if not skip : pch_init_final.append([info[1], ''])
	
	# Store all Steppings for each Chipset
	for info in pch_init_info :
		for final in pch_init_final :
			if info[1] == final[0] :
				final[1] = final[1] + info[2]
		
	# Sort each Chipset Steppings in reverse order (i.e. DCBA) & build total Print values
	for final_idx in range(len(pch_init_final)) :	
		pch_init_final[final_idx][1] = ''.join(sorted(list(dict.fromkeys(pch_init_final[final_idx][1])), reverse=True))
		final_print += '%s %s' % (pch_init_final[final_idx][0], ','.join(map(str, list(pch_init_final[final_idx][1]))))
		if final_idx < len(pch_init_final) - 1 : final_print += '\n' # No new line after last print
		final_db += pch_init_final[final_idx][1]
		
	# Add total Platforms/Steppings and Steppings for printing at last list cell, pch_init_final[-1]
	pch_init_final.append([final_print, ''.join(sorted(list(dict.fromkeys(final_db)), reverse=True))])
				
	return pch_init_final
	

# CSE Huffman Dictionary Loader by IllegalArgument
# Dictionaries by Dmitry Sklyarov & IllegalArgument
# Message Verbosity: All | Error | None
def cse_huffman_dictionary_load(cse_variant, cse_major, verbosity) :
	HUFFMAN_SHAPE = []
	HUFFMAN_SYMBOLS = {}
	HUFFMAN_UNKNOWNS = {}
	mapping_types = {'code' : 0x20, 'data' : 0x60}
	huffman_dict = os.path.join(mea_dir, 'Huffman.dat')
	
	# Check if Huffman dictionary version is supported
	if (cse_variant, cse_major) in [('CSME', 11), ('CSSPS', 4)] : dict_version = 11
	elif (cse_variant, cse_major) in [('CSME', 12), ('CSME', 13), ('CSME', 14), ('CSSPS', 5)] : dict_version = 12
	else :
		# CSTXE & PMC firmware do not use Huffman compression, skip error message
		if cse_variant != 'CSTXE' and not cse_variant.startswith('PMC') and verbosity in ['all','error'] :
			if param.me11_mod_bug : input(col_r + '\nNo Huffman dictionary for {0} {1}'.format(cse_variant, cse_major) + col_e)
			else : print(col_r + '\nNo Huffman dictionary for {0} {1}'.format(cse_variant, cse_major) + col_e)
		
		return HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS
	
	# Check if supported Huffman dictionary file exists
	if not os.path.isfile(huffman_dict) :
		if verbosity in ['all','error'] :
			if param.me11_mod_bug : input(col_r + '\nHuffman dictionary file is missing!' + col_e)
			else : print(col_r + '\nHuffman dictionary file is missing!' + col_e)
		
		return HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS
	
	with open(huffman_dict, 'r') as dict_file :
		dict_json = json.load(dict_file)
		
		dict_mappings = dict_json[str(dict_version)]
		mapping_codeword_ranges = {}
		
		for mapping_type_string, mapping in dict_mappings.items() :
			mapping_type = mapping_types[mapping_type_string]
			grouped_codeword_strings = itertools.groupby(sorted(list(mapping.keys()), key=len), key=len)
			# noinspection PyTypeChecker
			grouped_codewords = { codeword_len : [int(codeword, 2) for codeword in codewords] for codeword_len, codewords in grouped_codeword_strings}
			mapping_codeword_ranges[mapping_type] = {codeword_len : (min(codewords), max(codewords)) for codeword_len, codewords in grouped_codewords.items()}
		
		if len(set([frozenset(x.items()) for x in mapping_codeword_ranges.values()])) > 1 and verbosity in ['all','error'] :
			if param.me11_mod_bug : input(col_r + '\n    Mismatched mappings in the same dictionary' + col_e)
			else : print(col_r + '\n    Mismatched mappings in the same dictionary' + col_e)
		
		codeword_ranges = list(mapping_codeword_ranges.values())[0]
		
		for i, j in zip(list(codeword_ranges.keys())[:-1], list(codeword_ranges.keys())[1:]) :
			if 2 * codeword_ranges[i][0] - 1 != codeword_ranges[j][1] and verbosity in ['all','error'] :
				if param.me11_mod_bug : input(col_r + '\n    Discontinuity between codeword lengths {0} and {1}'.format(i, j) + col_e)
				else : print(col_r + '\n    Discontinuity between codeword lengths {0} and {1}'.format(i, j) + col_e)
				
		HUFFMAN_SHAPE = [(codeword_len, codeword_min << (32 - codeword_len), codeword_max) for codeword_len, (codeword_min, codeword_max) in codeword_ranges.items()]
			
		for mapping_type_string, mapping in dict_mappings.items() :
			mapping_type = mapping_types[mapping_type_string]
			
			HUFFMAN_SYMBOLS[mapping_type] = {}
			HUFFMAN_UNKNOWNS[mapping_type] = {}
			
			for codeword_len, (codeword_min, codeword_max) in codeword_ranges.items() :
				HUFFMAN_UNKNOWNS[mapping_type][codeword_len] = set()
				
				def parse_symbol(codeword) :
					codeword_binary = format(codeword, '0' + str(codeword_len) + 'b')
					symbol = mapping[codeword_binary].strip()
					if symbol == '' :
						HUFFMAN_UNKNOWNS[mapping_type][codeword_len].add(codeword)
						return [0x7F]
					elif re.match('^(\?\?)+$', symbol) :
						HUFFMAN_UNKNOWNS[mapping_type][codeword_len].add(codeword)
						return list(itertools.repeat(0x7F, int(len(symbol) / 2)))
					else :
						return [x for x in bytes.fromhex(symbol)]
				
				HUFFMAN_SYMBOLS[mapping_type][codeword_len] = [parse_symbol(codeword) for codeword in range(codeword_max, codeword_min - 1, -1)]
			
	return HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS
	
# CSE Huffman Decompressor by IllegalArgument
# Message Verbosity: All | Error | None
def cse_huffman_decompress(module_contents, compressed_size, decompressed_size, HUFFMAN_SHAPE, HUFFMAN_SYMBOLS, HUFFMAN_UNKNOWNS, verbosity) :
	CHUNK_SIZE = 0x1000
	huff_error = False
	decompressed_array = []
	
	if not HUFFMAN_SHAPE : return module_contents # Failed to load required Huffman dictionary
	
	chunk_count = int(decompressed_size / CHUNK_SIZE)
	header_size = chunk_count * 0x4
	
	module_buffer = bytearray(module_contents)
	header_buffer = module_buffer[0:header_size]
	compressed_buffer = module_buffer[header_size:compressed_size]
	
	header_entries = struct.unpack('<{:d}I'.format(chunk_count), header_buffer)
	start_offsets, flags = zip(*[(x & 0x1FFFFFF, (x >> 25) & 0x7F) for x in header_entries])
	end_offsets = itertools.chain(start_offsets[1:], [compressed_size - header_size])
	
	for index, dictionary_type, compressed_position, compressed_limit in zip(range(chunk_count), flags, start_offsets, end_offsets) :
		if verbosity == 'all' :
			print(col_r + '\n    ==Processing chunk 0x{:X} at compressed offset 0x{:X} with dictionary 0x{:X}=='.format(index, compressed_position, dictionary_type) + col_e)
			
		dictionary = HUFFMAN_SYMBOLS[dictionary_type]
		unknowns = HUFFMAN_UNKNOWNS[dictionary_type]
		
		decompressed_position, decompressed_limit = index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE
		
		bit_buffer = 0
		available_bits = 0
		
		while decompressed_position < decompressed_limit :
			while available_bits <= 24 and compressed_position < compressed_limit :
				bit_buffer = bit_buffer | compressed_buffer[compressed_position] << (24 - available_bits)
				compressed_position = compressed_position + 1
				available_bits = available_bits + 8
			
			codeword_length, base_codeword = 0, 0
			for length, shape, base in HUFFMAN_SHAPE :
				if bit_buffer >= shape :
					codeword_length, base_codeword = length, base
					break
			
			if available_bits >= codeword_length :
				codeword = bit_buffer >> (32 - codeword_length)
				bit_buffer = (bit_buffer << codeword_length) & 0xFFFFFFFF
				available_bits = available_bits - codeword_length
				
				symbol = dictionary[codeword_length][base_codeword - codeword]
				symbol_length = len(symbol)
				
				if decompressed_limit - decompressed_position >= symbol_length :
					if codeword in unknowns[codeword_length] and verbosity in ['all','error'] :
						print(col_r + '\n    Unknown codeword {: <15s} (dictionary 0x{:X}, codeword length {: >2d}, codeword {: >5s}, symbol length {:d}) at decompressed offset 0x{:X}'.format(
							('{:0>' + str(codeword_length) + 'b}').format(codeword), dictionary_type, codeword_length, "0x{:X}".format(codeword), symbol_length, decompressed_position) + col_e)
						huff_error = True
					decompressed_array.extend(symbol)
					decompressed_position = decompressed_position + symbol_length
				else :
					if verbosity in ['all','error'] :
						print(col_r + '\n    Skipping overflowing codeword {: <15s} (dictionary 0x{:X}, codeword length {: >2d}, codeword {: >5s}, symbol length {:d}) at decompressed offset 0x{:X}'.format(
							('{:0>' + str(codeword_length) + 'b}').format(codeword), dictionary_type, codeword_length, '0x{:X}'.format(codeword), symbol_length, decompressed_position) + col_e)
						huff_error = True
					filler = itertools.repeat(0x7F, decompressed_limit - decompressed_position)
					decompressed_array.extend(filler)
					decompressed_position = decompressed_limit
			else :
				if verbosity in ['all','error'] :
					print(col_r + '\n    Reached end of compressed stream early at decompressed offset 0x{:X}'.format(decompressed_position) + col_e)
					huff_error = True
				filler = itertools.repeat(0x7F, decompressed_limit - decompressed_position)
				decompressed_array.extend(filler)
				decompressed_position = decompressed_limit
				
	return bytearray(decompressed_array), huff_error
	
# Detect CSE Partition Instance Identifier
def cse_part_inid(buffer, cpd_offset, ext_dictionary, file_end, variant):
	cpd_hdr_struct, cpd_hdr_size = get_cpd(buffer, cpd_offset)
	cpd_hdr = get_struct(buffer, cpd_offset, cpd_hdr_struct, file_end)
	cse_in_id = 0
	in_id_step = 0
	in_id_stop = 0
	cse_part_size = 0
	cse_part_name = ''
	
	if cpd_hdr.Tag == b'$CPD' : # Sanity check
		mn2_start = cpd_offset + cpd_hdr_size + cpd_entry_num_fix(buffer, cpd_offset, cpd_hdr.NumModules, cpd_hdr_size) * 0x18
		
		mn2_hdr = get_struct(buffer, mn2_start, get_manifest(buffer, mn2_start, variant), file_end)
		
		if mn2_hdr.Tag == b'$MN2' : # Sanity check
			mn2_size = mn2_hdr.HeaderLength * 4
			
			# Detected $CPD + $MN2, search for Instance ID at CSE_Ext_03 or CSE_Ext_16
			while int.from_bytes(buffer[mn2_start + mn2_size + in_id_step:mn2_start + mn2_size + in_id_step + 0x4], 'little') not in [0x3,0x16] :
				in_id_stop += 1
				if in_id_stop > 10 : break
				in_id_step += int.from_bytes(buffer[mn2_start + mn2_size + in_id_step + 0x4:mn2_start + mn2_size + in_id_step + 0x8], 'little')
			else :
				in_id_ext = 'CSE_Ext_%0.2X' % int.from_bytes(buffer[mn2_start + mn2_size + in_id_step:mn2_start + mn2_size + in_id_step + 0x4], 'little')
				if in_id_ext in ext_dictionary :
					cse_ext_hdr = get_struct(buffer, mn2_start + mn2_size + in_id_step, ext_dictionary[in_id_ext], file_end)
					cse_in_id = cse_ext_hdr.InstanceID # Partition Instance Identifier
					cse_part_name = cse_ext_hdr.PartitionName # Partition Name (for uncharted $FPT code, no need for almost duplicate function)
					cse_part_size = cse_ext_hdr.PartitionSize # Partition Size (for uncharted $FPT code, no need for almost duplicate function)
								
	return cse_in_id, cse_part_name, cse_part_size
