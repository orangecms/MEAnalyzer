import ctypes

from col_lib import *
from tbl_lib import ext_table

from struct_types import char, uint8_t, uint16_t, uint32_t, uint64_t

# noinspection PyTypeChecker
class CPD_Header_R1(ctypes.LittleEndianStructure) : # Code Partition Directory R1 (CPD_HEADER)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('NumModules',		uint32_t),		# 0x04
		('HeaderVersion',	uint8_t),		# 0x08 1
		('EntryVersion',	uint8_t),		# 0x09
		('HeaderLength',	uint8_t),		# 0x0A
		('Checksum',		uint8_t),		# 0x0B Checksum-8 of Header + Entries with Checksum field = 0
		('PartitionName',	char*4),		# 0x0C
		# 0x10
	]
	
	def hdr_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Code Partition Directory Header' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Module Count', '%d' % self.NumModules])
		pt.add_row(['Header Version', '%d' % self.HeaderVersion])
		pt.add_row(['Entry Version', '%d' % self.EntryVersion])
		pt.add_row(['Header Size', '0x%X' % self.HeaderLength])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		
		return pt

# noinspection PyTypeChecker
class CPD_Header_R2(ctypes.LittleEndianStructure) : # Code Partition Directory R2 (CPD_HEADER)
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('NumModules',		uint32_t),		# 0x04
		('HeaderVersion',	uint8_t),		# 0x08 2
		('EntryVersion',	uint8_t),		# 0x09
		('HeaderLength',	uint8_t),		# 0x0A
		('Reserved',		uint8_t),		# 0x0B
		('PartitionName',	char*4),		# 0x0C
		('Checksum',		uint32_t),		# 0x10 CRC-32 of Header + Entries with Checksum field = 0
		# 0x14
	]
	
	def hdr_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Code Partition Directory Header' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Module Count', '%d' % self.NumModules])
		pt.add_row(['Header Version', '%d' % self.HeaderVersion])
		pt.add_row(['Entry Version', '%d' % self.EntryVersion])
		pt.add_row(['Header Size', '0x%X' % self.HeaderLength])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		
		return pt
		
# noinspection PyTypeChecker
class CPD_Entry(ctypes.LittleEndianStructure) : # (CPD_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("OffsetAttrib",	uint32_t),		# 0x0C
		("Size",			uint32_t),		# 0x10 Uncompressed for LZMA/Huffman, Compressed at CSE_Ext_0A instead
		("Reserved",		uint32_t),		# 0x14
		# 0x18
	]
	
	def hdr_print(self) :
		f1,f2,f3 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Code Partition Directory Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Offset from $CPD', '0x%X' % f1])
		pt.add_row(['Huffman Compression', ['No','Yes'][f2]])
		pt.add_row(['Offset Reserved', '0x%X' % f3])
		pt.add_row(['Size Uncompressed', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
	
	def get_flags(self) :
		flags = CPD_Entry_GetOffsetAttrib()
		flags.asbytes = self.OffsetAttrib
		
		return flags.b.OffsetCPD, flags.b.IsHuffman, flags.b.Reserved

class CPD_Entry_OffsetAttrib(ctypes.LittleEndianStructure):
	_fields_ = [
		('OffsetCPD', uint32_t, 25),
		('IsHuffman', uint32_t, 1),
		('Reserved', uint32_t, 6)
	]
	
class CPD_Entry_GetOffsetAttrib(ctypes.Union):
	_fields_ = [
		('b', CPD_Entry_OffsetAttrib),
		('asbytes', uint32_t)
	]
