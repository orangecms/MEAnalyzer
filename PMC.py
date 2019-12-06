from db import *
	
# Fix early PRE firmware which are wrongly reported as PRD
def release_fix(release, rel_db, rsa_key_hash) :
	rsa_pre_keys = [
	'C3416BFF2A9A85414F584263CE6BC0083979DC90FC702FCB671EA497994BA1A7',
	'86C0E5EF0CFEFF6D810D68D83D8C6ECB68306A644C03C0446B646A3971D37894',
	'BA93EEE4B70BAE2554FF8B5B9B1556341E5E5E3E41D7A2271AB00E65B560EC76'
	]
	
	if release == 'Production' and rsa_key_hash in rsa_pre_keys :
		release = 'Pre-Production'
		rel_db = 'PRE'
	
	return release, rel_db

# Analyze CSE PMC firmware
def pmc_anl(mn2_info, cpd_mod_info) :
	pmc_variant = 'Unknown'
	pmc_pch_sku = 'Unknown'
	pmc_pch_rev = 'Unknown'
	pmc_platform = 'Unknown'
	pmcp_upd_found = False
	pch_sku_val = {1: 'LP', 2: 'H'}
	pch_sku_old = {0: 'H', 2: 'LP'}
	pmc_variants = {2: 'PMCAPLA', 3: 'PMCAPLB', 4: 'PMCGLKA', 5: 'PMCBXTC', 6: 'PMCGLKB'}
	pch_rev_val = {0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E', 5: 'F', 6: 'G', 7: 'H', 8: 'I', 9: 'J'}
	
	# mn2_info = [Major/PCH, Minor/SKU, Hotfix/Compatibility-Maintenance, Build, Release, RSA Key Hash, RSA Sig Hash, Date, SVN, PV bit]
	
	# $MN2 Manifest SVN = CSE_Ext_0F ARBSVN. The value is used for Anti-Rollback (ARB) and not Trusted Computing Base (TCB) purposes.
	
	# Detect PMC Variant from $CPD Module Names and/or Major Version
	for mod in cpd_mod_info :
		if mod[0].startswith('PMCC00') :
			pmcc_version = int(mod[0][-1], 16) # PMCC006 = PMC GLK B etc
			
			# Remember to also adjust get_variant for PMC Variants
			
			if pmcc_version in pmc_variants :
				pmc_variant = pmc_variants[pmcc_version]
			elif pmcc_version == 0 and (mn2_info[0] in (300,3232) or mn2_info[0] < 130) : # 0 CNP
				pmc_variant = 'PMCCNP'
			elif pmcc_version == 0 and mn2_info[0] in (400,130) : # 0 ICP
				pmc_variant = 'PMCICP'
			elif pmcc_version == 0 and mn2_info[0] == 140 : # 0 CMP
				pmc_variant = 'PMCCMP'
			
			break # Found PMC Code Module, skip the rest
	
	if pmc_variant == 'PMCCMP' :
		pmc_platform = 'CMP'
		
		if mn2_info[0] == 140 :
			# 140.2.01.1009 = CMP + H + PCH Compatibility A + PMC Maintenance 1 + PMC Revision 1009
			if mn2_info[1] in pch_sku_val : pmc_pch_sku = pch_sku_val[mn2_info[1]] # 1 LP, 2 H, 3 V (?)
			pmc_pch_rev = '%s%d' % (pch_rev_val[mn2_info[2] // 10], mn2_info[2] % 10) # 21 = PCH C PMC 1
		
		# Check if PMCCMP firmware is the latest
		db_pch,db_sku,db_rev,db_rel = check_upd(('Latest_PMCCMP_%s_%s' % (pmc_pch_sku, pch_rev_val[mn2_info[2] // 10])))
		if mn2_info[2] < db_rev or (mn2_info[2] == db_rev and mn2_info[3] < db_rel) : pmcp_upd_found = True
	
	elif pmc_variant == 'PMCICP' :
		pmc_platform = 'ICP'
		
		if mn2_info[0] in (400,130) :
			# 400.1.30.1063 = ICP + LP + PCH Compatibility D + PMC Maintenance 0 + PMC Revision 1063
			if mn2_info[1] in pch_sku_val : pmc_pch_sku = pch_sku_val[mn2_info[1]] # 1 LP, 2 H, 3 N (?)
			pmc_pch_rev = '%s%d' % (pch_rev_val[mn2_info[2] // 10], mn2_info[2] % 10) # 21 = PCH C PMC 1
		
		# Check if PMCICP firmware is the latest
		db_pch,db_sku,db_rev,db_rel = check_upd(('Latest_PMCICP_%s_%s' % (pmc_pch_sku, pch_rev_val[mn2_info[2] // 10])))
		if mn2_info[2] < db_rev or (mn2_info[2] == db_rev and mn2_info[3] < db_rel) : pmcp_upd_found = True
	
	elif pmc_variant == 'PMCCNP' :
		pmc_platform = 'CNP'
		
		if mn2_info[0] == 300 :
			# CSME 12.0.0.1033 - 12.0.5.1117 --> 300.2.01.1012 = CNP + H + PCH Stepping A1 + PMC Revision 1012 (POR)
			# CSME >= 12.0.6.1120 --> 300.2.11.1014 = CNP + H + PCH Compatibility B + PMC Maintenance 1 + PMC Revision 1014 (POR)
			if mn2_info[1] in pch_sku_val : pmc_pch_sku = pch_sku_val[mn2_info[1]] # 1 LP, 2 H
			pmc_pch_rev = '%s%d' % (pch_rev_val[mn2_info[2] // 10], mn2_info[2] % 10) # 21 = PCH C PMC 1 (>= 12.0.6.1120) or PCH C1 (<= 12.0.0.1033)
		else :
			# CSME < 12.0.0.1033 --> 01.7.0.1022 = PCH Stepping A1 + PMC Hotfix 7 + PCH-H + PMC Build 1022 (Guess)
			# CSME < 12.0.0.1033 --> 10.0.2.1021 = PCH Stepping B0 + PMC Hotfix 0 + PCH-LP + PMC Build 1021 (Guess)
			if mn2_info[2] in pch_sku_old : pmc_pch_sku = pch_sku_old[mn2_info[2]] # 0 H, 2 LP
			try : pmc_pch_rev = '%s%d' % (pch_rev_val[mn2_info[0] // 10], mn2_info[0] % 10) # 00 = PCH A0, 10 = PCH B0, 21 = PCH C1 etc
			except : pass # Do not crash at any weird alpha CNP A Major/PCH numbers such as 3232 or similar 
		
		# Check if PMCCNP firmware is the latest
		db_pch,db_sku,db_rev,db_rel = check_upd(('Latest_PMCCNP_%s_%s' % (pmc_pch_sku, pch_rev_val[mn2_info[2] // 10])))
		if mn2_info[2] < db_rev or (mn2_info[2] == db_rev and mn2_info[3] < db_rel) : pmcp_upd_found = True
			
	elif pmc_variant.startswith(('PMCAPL','PMCBXT','PMCGLK')) :
		pmc_platform = pmc_variant[3:6]
		pmc_pch_rev = pmc_variant[-1]
	
	pmc_mn2_signed = 'Pre-Production' if mn2_info[4] == 'Debug' else 'Production'
	pmc_mn2_signed_db = 'PRD' if pmc_mn2_signed == 'Production' else 'PRE'
	
	# Fix Release of PRE firmware which are wrongly reported as PRD
	pmc_mn2_signed, pmc_mn2_signed_db = release_fix(pmc_mn2_signed, pmc_mn2_signed_db, mn2_info[5])
	
	if pmc_platform in ('CNP','ICP','CMP') :
		if mn2_info[0] < 130 or mn2_info[0] == 3232 :
			pmc_fw_ver = '%0.2d.%s.%s.%s' % (mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3])
			pmc_name_db = '%s_%s_%s_%s_%s_%s_%s' % (pmc_platform, pmc_fw_ver, pmc_pch_sku, pmc_pch_rev[0], mn2_info[7], pmc_mn2_signed_db, mn2_info[6])
		else :
			pmc_fw_ver = '%s.%s.%0.2d.%0.4d' % (mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3])
			pmc_name_db = '%s_%s_%s_%s_%s_%s' % (pmc_platform, pmc_fw_ver, pmc_pch_sku, pmc_pch_rev[0], pmc_mn2_signed_db, mn2_info[6])
	else :
		pmc_fw_ver = '%s.%s.%s.%s' % (mn2_info[0], mn2_info[1], mn2_info[2], mn2_info[3])
		pmc_name_db = '%s_%s_%s_%s_%s_%s' % (pmc_platform, pmc_fw_ver, pmc_pch_rev[0], mn2_info[7], pmc_mn2_signed_db, mn2_info[6])
	
	# Search DB for PMC firmware
	fw_db = db_open()
	for line in fw_db :
		if pmc_name_db in line :
			break # Break loop at 1st hash match
	else :
		note_stor.append([col_g + 'Note: This PMC %s firmware was not found at the database, please report it!' % pmc_platform + col_e, True])
	fw_db.close()
	
	return pmc_fw_ver, mn2_info[0], pmc_pch_sku, pmc_pch_rev, mn2_info[3], pmc_mn2_signed, pmc_mn2_signed_db, pmcp_upd_found, pmc_platform, \
		   mn2_info[7], mn2_info[8], mn2_info[9]
		   
# Verify CSE FTPR/OPR & stitched PMC compatibility (PCH/SoC & SKU)
def pmc_chk(pmc_mn2_signed, release, pmc_pch_gen, pmc_gen_list, pmc_pch_sku, sku_result, sku_stp, pmc_pch_rev, pmc_platform) :
	if pmc_mn2_signed != release or pmc_pch_gen not in pmc_gen_list or pmc_pch_sku != sku_result or (sku_stp != 'NaN' and pmc_pch_rev[0] not in sku_stp) :
		warn_stor.append([col_m + 'Warning: Incompatible PMC %s firmware detected!' % pmc_platform + col_e, False])
