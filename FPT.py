import ctypes

from struct_types import char, uint8_t, uint16_t, uint32_t, uint64_t

class FPT_Pre_Header(ctypes.LittleEndianStructure) : # (ROM_BYPASS)
	_pack_ = 1
	_fields_ = [
		('ROMB_Instr_0',	uint32_t),		# 0x00
		('ROMB_Instr_1',	uint32_t),		# 0x04
		('ROMB_Instr_2',	uint32_t),		# 0x08
		('ROMB_Instr_3',	uint32_t),		# 0x0C
		# 0x10
	]
	
	def hdr_print_cse(self) :
		NA = [0,0xFFFFFFFF] # Non-ROMB or IFWI EXTR
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Flash Partition Table ROM-Bypass' + col_e
		pt.add_row(['Instruction 0', 'N/A' if self.ROMB_Instr_0 in NA else '0x%X' % self.ROMB_Instr_0])
		pt.add_row(['Instruction 1', 'N/A' if self.ROMB_Instr_1 in NA else '0x%X' % self.ROMB_Instr_1])
		pt.add_row(['Instruction 2', 'N/A' if self.ROMB_Instr_2 in NA else '0x%X' % self.ROMB_Instr_2])
		pt.add_row(['Instruction 3', 'N/A' if self.ROMB_Instr_3 in NA else '0x%X' % self.ROMB_Instr_3])
		
		return pt

# noinspection PyTypeChecker
class FPT_Header(ctypes.LittleEndianStructure) : # Flash Partition Table v1.0 & v2.0 (FPT_HEADER)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('NumPartitions',	uint32_t),		# 0x04
		('HeaderVersion',	uint8_t),		# 0x08
		('EntryVersion',	uint8_t),		# 0x09
		('HeaderLength',	uint8_t),		# 0x0A
		('HeaderChecksum',	uint8_t),		# 0x0B
		('FlashCycleLife',	uint16_t),		# 0x0C TicksToAdd at CSE
		('FlashCycleLimit',	uint16_t),		# 0x0E TokensToAdd at CSE
		('UMASize',			uint32_t),		# 0x10 Reserved at CSE
		('Flags',			uint32_t),		# 0x14 FlashLayout at CSE (FLASH_LAYOUT_TYPES)
		('FitMajor',		uint16_t),		# 0x18
		('FitMinor',		uint16_t),		# 0x1A
		('FitHotfix',		uint16_t),		# 0x1C
		('FitBuild',		uint16_t),		# 0x1E
		# 0x20
	]
	
	def hdr_print_cse(self) :
		NA = 0xFFFFFFFF # IFWI EXTR
		sector_types = {0:'4K', 2:'8K', 4:'64K', 8:'64K-8K Mixed'}
		
		fit_ver = '%d.%d.%d.%d' % (self.FitMajor,self.FitMinor,self.FitHotfix,self.FitBuild)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Flash Partition Table 2.0 Header' + col_e
		pt.add_row(['Tag', '%s' % self.Tag.decode('utf-8')])
		pt.add_row(['Partition Count', '%d' % self.NumPartitions])
		pt.add_row(['Header Version', '0x%X' % self.HeaderVersion])
		pt.add_row(['Entry Version', '0x%X' % self.EntryVersion])
		pt.add_row(['Header Size', '0x%X' % self.HeaderLength])
		pt.add_row(['Header Checksum', '0x%X' % self.HeaderChecksum])
		pt.add_row(['Ticks To Add', '0x%X' % self.FlashCycleLife])
		pt.add_row(['Tokens To Add', '0x%X' % self.FlashCycleLimit])
		pt.add_row(['Reserved', 'N/A' if self.UMASize == NA else '0x%X' % self.UMASize])
		pt.add_row(['Flash Layout', 'N/A' if self.Flags == NA else '%s' % sector_types[self.Flags]])
		pt.add_row(['Flash Image Tool', 'N/A' if self.FitMajor in [0,0xFFFF] else fit_ver])
		pt.add_row([col_g + 'FIT version' + col_e, col_c + fit_ver + col_e])
		
		return pt
		
# noinspection PyTypeChecker
class FPT_Header_21(ctypes.LittleEndianStructure) : # Flash Partition Table v2.1 (FPT_HEADER)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('NumPartitions',	uint32_t),		# 0x04
		('HeaderVersion',	uint8_t),		# 0x08 21
		('EntryVersion',	uint8_t),		# 0x09
		('HeaderLength',	uint8_t),		# 0x0A
		('Flags',			uint8_t),		# 0x0B 0 FPT Backup Present, 1-7 Reserved
		('TicksToAdd',		uint16_t),		# 0x0C
		('TokensToAdd',		uint16_t),		# 0x0E
		('SPSFlags',		uint32_t),		# 0x10 (Unknown/Unused)
		('HeaderChecksum',	uint32_t),		# 0x14 CRC-32
		('FitMajor',		uint16_t),		# 0x18
		('FitMinor',		uint16_t),		# 0x1A
		('FitHotfix',		uint16_t),		# 0x1C
		('FitBuild',		uint16_t),		# 0x1E
		# 0x20
	]
	
	# Used at Lake Field (LKF) IFWI 1.7 platform
	
	def hdr_print(self) :
		f1,f2 = self.get_flags()
		
		fit_ver = '%d.%d.%d.%d' % (self.FitMajor,self.FitMinor,self.FitHotfix,self.FitBuild)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Flash Partition Table 2.1 Header' + col_e
		pt.add_row(['Tag', '%s' % self.Tag.decode('utf-8')])
		pt.add_row(['Partition Count', '%d' % self.NumPartitions])
		pt.add_row(['Header Version', '0x%X' % self.HeaderVersion])
		pt.add_row(['Entry Version', '0x%X' % self.EntryVersion])
		pt.add_row(['Header Size', '0x%X' % self.HeaderLength])
		pt.add_row(['Header Backup', ['No','Yes'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Ticks To Add', '0x%X' % self.TicksToAdd])
		pt.add_row(['Tokens To Add', '0x%X' % self.TokensToAdd])
		pt.add_row(['SPS Flags', '0x%X' % self.SPSFlags])
		pt.add_row(['Header Checksum', '0x%X' % self.HeaderChecksum])
		pt.add_row(['Flash Image Tool', 'N/A' if self.FitMajor in [0,0xFFFF] else fit_ver])
		
		return pt
		
	def get_flags(self) :
		flags = FPT_Header_21_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.FPTB, flags.b.Reserved

class FPT_Header_21_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('FPTB', uint8_t, 1),
		('Reserved', uint8_t, 7),
	]

class FPT_Header_21_GetFlags(ctypes.Union):
	_fields_ = [
		('b', FPT_Header_21_Flags),
		('asbytes', uint8_t)
	]

# noinspection PyTypeChecker
class FPT_Entry(ctypes.LittleEndianStructure) : # (FPT_ENTRY)
	_pack_ = 1
	_fields_ = [
		('Name',			char*4),		# 0x00
		('Owner',			char*4),		# 0x04 Reserved at CSE
		('Offset',			uint32_t),		# 0x08
		('Size',			uint32_t),		# 0x0C
		('StartTokens',		uint32_t),		# 0x10 Reserved at CSE
		('MaxTokens',		uint32_t),		# 0x14 Reserved at CSE
		('ScratchSectors',	uint32_t),		# 0x18 Reserved at CSE
		('Flags',			uint32_t),		# 0x1C (FPT_ENTRY_ATTRIBUTES)
		# 0x20
	]
	
	def hdr_print_cse(self) :
		f1,f2,f3,f4,f5,f6,f7 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Flash Partition Table Entry' + col_e
		pt.add_row(['Name', '%s' % self.Name.decode('utf-8')])
		pt.add_row(['Reserved 0', '0x%X' % int.from_bytes(self.Owner, 'little')])
		pt.add_row(['Offset', '0x%X' % self.Offset])
		pt.add_row(['Reserved 1', '0x%X' % self.StartTokens])
		pt.add_row(['Reserved 2', '0x%X' % self.MaxTokens])
		pt.add_row(['Reserved 3', '0x%X' % self.ScratchSectors])
		pt.add_row(['Type', ['Code','Data'][f1]])
		pt.add_row(['Copy To DRAM Cache', ['No','Yes'][f2]])
		pt.add_row(['Reserved 4', '0x%X' % f3])
		pt.add_row(['Built With Length 0', '0x%X' % f4])
		pt.add_row(['Built With Length 1', '0x%X' % f5])
		pt.add_row(['Reserved 5', '0x%X' % f6])
		pt.add_row(['Entry Valid', 'No' if f7 == 0xFF else 'Yes'])
		
		return pt
	
	def get_flags(self) :
		flags = FPT_Entry_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.Type, flags.b.CopyToDramCache, flags.b.Reserved0, flags.b.BuiltWithLength0, flags.b.BuiltWithLength1, \
			   flags.b.Reserved1, flags.b.EntryValid

class FPT_Entry_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('Type', uint32_t, 7), # (PARTITION_TYPES)
		('CopyToDramCache', uint32_t, 1),
		('Reserved0', uint32_t, 7),
		('BuiltWithLength0', uint32_t, 1),
		('BuiltWithLength1', uint32_t, 1),
		('Reserved1', uint32_t, 7),
		('EntryValid', uint32_t, 8)
	]

class FPT_Entry_GetFlags(ctypes.Union):
	_fields_ = [
		('b', FPT_Entry_Flags),
		('asbytes', uint32_t)
	]
