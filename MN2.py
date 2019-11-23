import ctypes
import struct

from col_lib import *
from tbl_lib import ext_table

from struct_types import char, uint8_t, uint16_t, uint32_t, uint64_t

# noinspection PyTypeChecker
class MN2_Manifest_R0(ctypes.LittleEndianStructure) : # Manifest $MAN/$MN2 Pre-CSE R0 (MANIFEST_HEADER)
	_pack_ = 1
	_fields_ = [
		("HeaderType",		uint32_t),		# 0x00
		("HeaderLength",	uint32_t),		# 0x04 dwords
		("HeaderVersion",	uint32_t),		# 0x08 0x10000
		("Flags",			uint32_t),		# 0x0C
		("VEN_ID",			uint32_t),		# 0x10 0x8086
		("Day",				uint8_t),		# 0x14
		("Month",			uint8_t),		# 0x15
		("Year",			uint16_t),		# 0x16
		("Size",			uint32_t),		# 0x18 dwords (0x2000 max)
		("Tag",				char*4),		# 0x1C
		("NumModules",		uint32_t),		# 0x20
		("Major",			uint16_t),		# 0x24
		("Minor",			uint16_t),		# 0x26
		("Hotfix",			uint16_t),		# 0x28
		("Build",			uint16_t),		# 0x2A
		("SVN",				uint32_t),		# 0x2C ME9+ (LSByte derives keys)
		("SVN_8",			uint32_t),		# 0x30 ME8
		("VCN",				uint32_t),		# 0x34 ME8-10
		("Reserved",		uint32_t*16),	# 0x38
		("PublicKeySize",	uint32_t),		# 0x78 dwords (PKCS #1 v1.5)
		("ExponentSize",	uint32_t),		# 0x7C dwords (PKCS #1 v1.5)
		("RSAPublicKey",	uint32_t*64),	# 0x80
		("RSAExponent",		uint32_t),		# 0x180
		("RSASignature",	uint32_t*64),	# 0x184 2048-bit (PKCS #1 v1.5)
		# 0x284
	]
	
	def get_flags(self) :
		flags = MN2_Manifest_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.PVBit, flags.b.Reserved, flags.b.PreProduction, flags.b.DebugSigned
	
# noinspection PyTypeChecker
class MN2_Manifest_R1(ctypes.LittleEndianStructure) : # Manifest $MN2 CSE R1 (MANIFEST_HEADER)
	_pack_ = 1
	_fields_ = [
		('HeaderType',		uint16_t),		# 0x00
		('HeaderSubType',	uint16_t),		# 0x02
		('HeaderLength',	uint32_t),		# 0x04 dwords
		('HeaderVersion',	uint32_t),		# 0x08 0x10000
		('Flags',			uint32_t),		# 0x0C
		('VEN_ID',			uint32_t),		# 0x10 0x8086
		('Day',				uint8_t),		# 0x14
		('Month',			uint8_t),		# 0x15
		('Year',			uint16_t),		# 0x16
		('Size',			uint32_t),		# 0x18 dwords (0x2000 max)
		('Tag',				char*4),		# 0x1C
		('InternalInfo',	uint32_t),		# 0x20 Internal Info of FTPR > Kernel
		('Major',			uint16_t),		# 0x24
		('Minor',			uint16_t),		# 0x26
		('Hotfix',			uint16_t),		# 0x28
		('Build',			uint16_t),		# 0x2A
		('SVN',				uint32_t),		# 0x2C LS Byte derives keys
		('MEU_Major',		uint16_t),		# 0x30
		('MEU_Minor',		uint16_t),		# 0x32
		('MEU_Hotfix',		uint16_t),		# 0x34
		('MEU_Build',		uint16_t),		# 0x36
		('MEU_Man_Ver',		uint16_t),		# 0x38
		('MEU_Man_Res',		uint16_t),		# 0x3A
		('Reserved',		uint32_t*15),	# 0x3C
		('PublicKeySize',	uint32_t),		# 0x78 dwords
		('ExponentSize',	uint32_t),		# 0x7C dwords
		('RSAPublicKey',	uint32_t*64),	# 0x80
		('RSAExponent',		uint32_t),		# 0x180
		('RSASignature',	uint32_t*64),	# 0x184 2048-bit (PKCS #1 v1.5)
		# 0x284
	]
	
	def hdr_print_cse(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4 = self.get_flags()
		
		version = '%d.%d.%d.%d' % (self.Major,self.Minor,self.Hotfix,self.Build)
		meu_version = '%d.%d.%d.%d' % (self.MEU_Major,self.MEU_Minor,self.MEU_Hotfix,self.MEU_Build)
		
		RSAPublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSAPublicKey))
		RSASignature = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSASignature))
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Partition Manifest Header' + col_e
		pt.add_row(['Header Type', '%d' % self.HeaderType])
		pt.add_row(['Header Sub Type', '%d' % self.HeaderSubType])
		pt.add_row(['Header Size', '0x%X' % (self.HeaderLength * 4)])
		pt.add_row(['Header Version', '0x%X' % self.HeaderVersion])
		pt.add_row(['Production Ready', fvalue[f1]])
		pt.add_row(['Flags Reserved', '0x%X' % (f2 + f3)])
		pt.add_row(['Debug Signed', fvalue[f4]])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year,self.Month,self.Day)])
		pt.add_row(['Manifest Size', '0x%X' % (self.Size * 4)])
		pt.add_row(['Manifest Tag', '%s' % self.Tag.decode('utf-8')])
		pt.add_row(['Unique Build Tag', '0x%X' % self.InternalInfo])
		pt.add_row(['Version', 'N/A' if self.Major in [0,0xFFFF] else version])
		pt.add_row(['TCB Security Version Number', '%d' % self.SVN])
		pt.add_row(['MEU Version', 'N/A' if self.MEU_Major in [0,0xFFFF] else meu_version])
		pt.add_row(['MEU Manifest Version', '%d' % self.MEU_Man_Ver])
		pt.add_row(['MEU Manifest Reserved', '0x%X' % self.MEU_Man_Res])
		pt.add_row(['Reserved', '0x0' if Reserved == '00000000' * 15 else Reserved])
		pt.add_row(['RSA Public Key Size', '0x%X' % (self.PublicKeySize * 4)])
		pt.add_row(['RSA Exponent Size', '0x%X' % (self.ExponentSize * 4)])
		pt.add_row(['RSA Public Key', '%s [...]' % RSAPublicKey[:8]])
		pt.add_row(['RSA Exponent', '0x%X' % self.RSAExponent])
		pt.add_row(['RSA Signature', '%s [...]' % RSASignature[:8]])
		
		return pt
	
	def get_flags(self) :
		flags = MN2_Manifest_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.PVBit, flags.b.Reserved, flags.b.PreProduction, flags.b.DebugSigned

# noinspection PyTypeChecker
class MN2_Manifest_R2(ctypes.LittleEndianStructure) : # Manifest $MN2 CSE R2 (MANIFEST_HEADER)
	_pack_ = 1
	_fields_ = [
		('HeaderType',		uint16_t),		# 0x00
		('HeaderSubType',	uint16_t),		# 0x02
		('HeaderLength',	uint32_t),		# 0x04 dwords
		('HeaderVersion',	uint32_t),		# 0x08 0x21000
		('Flags',			uint32_t),		# 0x0C
		('VEN_ID',			uint32_t),		# 0x10 0x8086
		('Day',				uint8_t),		# 0x14
		('Month',			uint8_t),		# 0x15
		('Year',			uint16_t),		# 0x16
		('Size',			uint32_t),		# 0x18 dwords (0x2000 max)
		('Tag',				char*4),		# 0x1C
		('InternalInfo',	uint32_t),		# 0x20 Internal Info of FTPR > Kernel
		('Major',			uint16_t),		# 0x24
		('Minor',			uint16_t),		# 0x26
		('Hotfix',			uint16_t),		# 0x28
		('Build',			uint16_t),		# 0x2A
		('SVN',				uint32_t),		# 0x2C LS Byte derives keys
		('MEU_Major',		uint16_t),		# 0x30
		('MEU_Minor',		uint16_t),		# 0x32
		('MEU_Hotfix',		uint16_t),		# 0x34
		('MEU_Build',		uint16_t),		# 0x36
		('MEU_Man_Ver',		uint16_t),		# 0x38
		('MEU_Man_Res',		uint16_t),		# 0x3A
		('Reserved',		uint32_t*15),	# 0x3C
		('PublicKeySize',	uint32_t),		# 0x78 dwords
		('ExponentSize',	uint32_t),		# 0x7C dwords
		('RSAPublicKey',	uint32_t*96),	# 0x80
		('RSAExponent',		uint32_t),		# 0x180
		('RSASignature',	uint32_t*96),	# 0x184 3072-bit (SSA-PSS)
		# 0x284
	]
	
	def hdr_print_cse(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4 = self.get_flags()
		
		version = '%d.%d.%d.%d' % (self.Major,self.Minor,self.Hotfix,self.Build)
		meu_version = '%d.%d.%d.%d' % (self.MEU_Major,self.MEU_Minor,self.MEU_Hotfix,self.MEU_Build)
		
		RSAPublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSAPublicKey))
		RSASignature = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSASignature))
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Partition Manifest Header' + col_e
		pt.add_row(['Header Type', '%d' % self.HeaderType])
		pt.add_row(['Header Sub Type', '%d' % self.HeaderSubType])
		pt.add_row(['Header Size', '0x%X' % (self.HeaderLength * 4)])
		pt.add_row(['Header Version', '0x%X' % self.HeaderVersion])
		pt.add_row(['Production Ready', fvalue[f1]])
		pt.add_row(['Flags Reserved', '0x%X' % (f2 + f3)])
		pt.add_row(['Debug Signed', fvalue[f4]])
		pt.add_row(['Vendor ID', '0x%X' % self.VEN_ID])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year,self.Month,self.Day)])
		pt.add_row(['Manifest Size', '0x%X' % (self.Size * 4)])
		pt.add_row(['Manifest Tag', '%s' % self.Tag.decode('utf-8')])
		pt.add_row(['Unique Build Tag', '0x%X' % self.InternalInfo])
		pt.add_row(['Version', 'N/A' if self.Major in [0,0xFFFF] else version])
		pt.add_row(['TCB Security Version Number', '%d' % self.SVN])
		pt.add_row(['MEU Version', 'N/A' if self.MEU_Major in [0,0xFFFF] else meu_version])
		pt.add_row(['MEU Manifest Version', '%d' % self.MEU_Man_Ver])
		pt.add_row(['MEU Manifest Reserved', '0x%X' % self.MEU_Man_Res])
		pt.add_row(['Reserved', '0x0' if Reserved == '00000000' * 15 else Reserved])
		pt.add_row(['RSA Public Key Size', '0x%X' % (self.PublicKeySize * 4)])
		pt.add_row(['RSA Exponent Size', '0x%X' % (self.ExponentSize * 4)])
		pt.add_row(['RSA Public Key', '%s [...]' % RSAPublicKey[:8]])
		pt.add_row(['RSA Exponent', '0x%X' % self.RSAExponent])
		pt.add_row(['RSA Signature', '%s [...]' % RSASignature[:8]])
		
		return pt
	
	def get_flags(self) :
		flags = MN2_Manifest_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.PVBit, flags.b.Reserved, flags.b.PreProduction, flags.b.DebugSigned
		
class MN2_Manifest_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('PVBit', uint32_t, 1), # CSE
		('Reserved', uint32_t, 29),
		('PreProduction', uint32_t, 1), # Reserved at CSE
		('DebugSigned', uint32_t, 1)
	]
	
class MN2_Manifest_GetFlags(ctypes.Union):
	_fields_ = [
		('b', MN2_Manifest_Flags),
		('asbytes', uint32_t)
	]
