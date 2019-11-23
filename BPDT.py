import ctypes

from struct_types import char, uint8_t, uint16_t, uint32_t, uint64_t
		
class BPDT_Header_1(ctypes.LittleEndianStructure) : # Boot Partition Descriptor Table 1.6 & 2.0 (PrimaryBootPartition, SecondaryBootPartition, PrimaryBootPartitionNC, BootPartitionLayout)
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00 AA550000 Boot/Green, AA55AA00 Recovery/Yellow
		('DescCount',		uint16_t),		# 0x04 Minimum 6 Entries
		('BPDTVersion',		uint16_t),		# 0x06 1 IFWI 1.6 & 2.0, 2 IFWI 1.7
		('Reserved',		uint16_t),		# 0x08
		('Checksum',		uint16_t),		# 0x0A
		('IFWIVersion',		uint32_t),		# 0x0C Unique mark from build server
		('FitMajor',		uint16_t),		# 0x10
		('FitMinor',		uint16_t),		# 0x12
		('FitHotfix',		uint16_t),		# 0x14
		('FitBuild',		uint16_t),		# 0x16
		# 0x18 (0x200 <= Header + Entries <= 0x1000)
	]
	
	# Used at IFWI 1.6 (CNP/ICP/CMP) & IFWI 2.0 (APL/GLK) platforms
	
	# XOR Checksum of the redundant block (from the beginning of the BPDT structure, up to and including the S-BPDT) such that
	# the XOR Checksum of the redundant block including Checksum field is 0. If no redundancy is supported, Checksum field is 0
	
	# https://github.com/coreboot/coreboot/blob/master/util/cbfstool/ifwitool.c
	
	def hdr_print(self) :
		bpdt_ver = {1 : '1.6 & 2.0', 2 : '1.7'}
		
		fit_ver = '%d.%d.%d.%d' % (self.FitMajor,self.FitMinor,self.FitHotfix,self.FitBuild)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Boot Partition Descriptor Table 1.6 & 2.0 Header' + col_e
		pt.add_row(['Signature', '0x%0.8X' % self.Signature])
		pt.add_row(['Descriptor Count', '%d' % self.DescCount])
		pt.add_row(['BPDT Version', bpdt_ver[self.BPDTVersion] if self.BPDTVersion in bpdt_ver else 'Unknown'])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		pt.add_row(['IFWI Version', '%d' % self.IFWIVersion])
		pt.add_row(['Flash Image Tool', 'N/A' if self.FitMajor in [0,0xFFFF] else fit_ver])
		
		return pt
		
class BPDT_Header_2(ctypes.LittleEndianStructure) : # Boot Partition Descriptor Table 1.7 (PrimaryBootPartition, PrimaryBootPartitionNC)
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00 AA550000 Boot/Green, AA55AA00 Recovery/Yellow
		('DescCount',		uint16_t),		# 0x04 Minimum 6 Entries
		('BPDTVersion',		uint8_t),		# 0x06 1 IFWI 1.6 & 2.0, 2 IFWI 1.7
		('BPDTConfig',		uint8_t),		# 0x07 0 BPDT Redundancy Support, 1-7 Reserved
		('Checksum',		uint32_t),		# 0x08 CRC32 of entire BPDT (Header + Entries) without Signature
		('IFWIVersion',		uint32_t),		# 0x0C Unique mark from build server
		('FitMajor',		uint16_t),		# 0x10
		('FitMinor',		uint16_t),		# 0x12
		('FitHotfix',		uint16_t),		# 0x14
		('FitBuild',		uint16_t),		# 0x16
		# 0x18 (0x200 <= Header + Entries <= 0x1000)
	]
	
	# Used at IFWI 1.7 (LKF) platforms
	
	def hdr_print(self) :
		bpdt_ver = {1 : '1.6 & 2.0', 2 : '1.7'}
		f1,f2 = self.get_flags()
		
		fit_ver = '%d.%d.%d.%d' % (self.FitMajor,self.FitMinor,self.FitHotfix,self.FitBuild)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Boot Partition Descriptor Table 1.7 Header' + col_e
		pt.add_row(['Signature', '0x%0.8X' % self.Signature])
		pt.add_row(['Descriptor Count', '%d' % self.DescCount])
		pt.add_row(['BPDT Version', bpdt_ver[self.BPDTVersion] if self.BPDTVersion in bpdt_ver else 'Unknown'])
		pt.add_row(['BPDT Redundancy', ['No','Yes'][f1]])
		pt.add_row(['BPDT Config Reserved', '0x%X' % f2])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		pt.add_row(['IFWI Version', '0x%X' % self.IFWIVersion])
		pt.add_row(['Flash Image Tool', 'N/A' if self.FitMajor in [0,0xFFFF] else fit_ver])
		
		return pt
		
	def get_flags(self) :
		flags = BPDT_Header_2_GetFlags()
		flags.asbytes = self.BPDTConfig
		
		return flags.b.BPDT_R_S, flags.b.Reserved
	
class BPDT_Header_2_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('BPDT_R_S', uint8_t, 1),
		('Reserved', uint8_t, 7),
	]

class BPDT_Header_2_GetFlags(ctypes.Union):
	_fields_ = [
		('b', BPDT_Header_2_Flags),
		('asbytes', uint8_t)
	]

class BPDT_Entry(ctypes.LittleEndianStructure) : # (BpdtEntry)
	_pack_ = 1
	_fields_ = [
		("Type",			uint16_t),		# 0x00 dword at CNP/GLK IFWI 1.6 & 2.0 (?)
		("Flags",			uint16_t),		# 0x02 only at APL IFWI 2.0 (?)
		("Offset",			uint32_t),		# 0x04
		("Size",			uint32_t),		# 0x08
		# 0xC
	]
	
	# It is probable that Flags field is relevant to APL (IFWI 2.0) platform only
	# At CNP/GLK (IFWI 1.6 & 2.0) and LKF (IFWI 1.7), Type is uint32_t without Flags
	
	def info_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Boot Partition Descriptor Table Entry' + col_e
		pt.add_row(['Type', bpdt_dict[self.Type] if self.Type in bpdt_dict else 'Unknown'])
		pt.add_row(['Split Sub-Partition 1st Part', fvalue[f1]])
		pt.add_row(['Split Sub-Partition 2nd Part', fvalue[f2]])
		pt.add_row(['Code Sub-Partition', fvalue[f3]])
		pt.add_row(['UMA Cacheable', fvalue[f4]])
		pt.add_row(['Flags Reserved', '0x%X' % f5])
		pt.add_row(['Offset', '0x%X' % self.Offset])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt
	
	def get_flags(self) :
		flags = BPDT_Entry_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.SplitSubPartitionFirstPart, flags.b.SplitSubPartitionSecondPart, flags.b.CodeSubPartition,\
		       flags.b.UMACachable, flags.b.Reserved
	
class BPDT_Entry_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('SplitSubPartitionFirstPart', uint16_t, 1), # 1st part in this LBP, 2nd part in other LBP (for up to 1 non-critical Sub-Partition)
		('SplitSubPartitionSecondPart', uint16_t, 1), # 1st part in other LBP, 2nd part in this LBP (for up to 1 non-critical Sub-Partition)
		('CodeSubPartition', uint16_t, 1), # Sub-Partition Contains Directory Structure
		('UMACachable', uint16_t, 1), # Copied to DRAM cache if required for a reset flow (for all Sub-Partition except BIOS-based)
		('Reserved', uint16_t, 12)
	]

class BPDT_Entry_GetFlags(ctypes.Union):
	_fields_ = [
		('b', BPDT_Entry_Flags),
		('asbytes', uint16_t)
	]
