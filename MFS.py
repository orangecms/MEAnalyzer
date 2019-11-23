import ctypes

from struct_types import char, uint8_t, uint16_t, uint32_t, uint64_t

# noinspection PyTypeChecker
class MFS_Page_Header(ctypes.LittleEndianStructure) : # MFS Page Header
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00
		('PageNumber',		uint32_t),		# 0x04
		('EraseCount',		uint32_t),		# 0x08
		('NextErasePage',	uint16_t),		# 0x0C
		('FirstChunkIndex',	uint16_t),		# 0x0E
		('CRC8',			uint8_t),		# 0x10
		('Reserved',		uint8_t),  		# 0x11
		# 0x12
	]
	
	def mfs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Page Header' + col_e
		pt.add_row(['Signature', '%0.8X' % self.Signature])
		pt.add_row(['Page Number', '%d' % self.PageNumber])
		pt.add_row(['Erase Count', '%d' % self.EraseCount])
		pt.add_row(['Next Erase Page Index', '%d' % self.NextErasePage])
		pt.add_row(['First Chunk Index', '%d' % self.FirstChunkIndex])
		pt.add_row(['CRC-8', '0x%0.2X' % self.CRC8])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
# noinspection PyTypeChecker
class MFS_Volume_Header(ctypes.LittleEndianStructure) : # MFS Volume Header
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00
		('Unknown0',		uint8_t),		# 0x04 FTBL Dictionary?
		('Unknown1',		uint8_t*3),		# 0x05
		('VolumeSize',		uint32_t),		# 0x08 (System + Data)
		('FileRecordCount',	uint16_t),		# 0x0C Supported by FAT
		# 0x0E
	]
	
	def mfs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		Unknown1 = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown1))
		
		pt.title = col_y + 'MFS Volume Header' + col_e
		pt.add_row(['Signature', '%0.8X' % self.Signature])
		pt.add_row(['Unknown 0', '0x%0.2X' % self.Unknown0])
		pt.add_row(['Unknown 1', '0x' + Unknown1])
		pt.add_row(['Volume Size', '0x%X' % self.VolumeSize])
		pt.add_row(['File Record Count', '%d' % self.FileRecordCount])
		
		return pt
		
# noinspection PyTypeChecker
class MFS_Config_Record_0x1C(ctypes.LittleEndianStructure) : # MFS Configuration Record 0x1C
	_pack_ = 1
	_fields_ = [
		('FileName',		char*12),		# 0x00
		('Reserved',		uint16_t),		# 0x0C
		('AccessMode',		uint16_t),		# 0x0E
		('DeployOptions',	uint16_t),		# 0x10
		('FileSize',		uint16_t),		# 0x12
		('OwnerUserID',		uint16_t),		# 0x14
		('OwnerGroupID',	uint16_t),		# 0x16
		('FileOffset',		uint32_t),		# 0x18
		# 0x1C
	]
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Configuration Record' + col_e
		pt.add_row(['Name', self.FileName.decode('utf-8')])
		pt.add_row(['Type', ['File','Folder'][f5]])
		pt.add_row(['Size', '0x%X' % self.FileSize])
		#pt.add_row(['Offset', '0x%X' % self.FileOffset])
		pt.add_row(['Access Rights', ''.join(map(str, self.get_rights(f1)))])
		pt.add_row(['Owner User ID', '%0.4X' % self.OwnerUserID])
		pt.add_row(['Owner Group ID', '%0.4X' % self.OwnerGroupID])
		pt.add_row(['OEM Configurable', fvalue[f7]])
		pt.add_row(['MCA Configurable', fvalue[f8]])
		pt.add_row(['Integrity Protection', fvalue[f2]])
		pt.add_row(['Encryption Protection', fvalue[f3]])
		pt.add_row(['Anti-Replay Protection', fvalue[f4]])
		pt.add_row(['Access Mode Unknown', '{0:03b}b'.format(f6)])
		pt.add_row(['Deploy Options Unknown', '{0:014b}b'.format(f9)])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
	@staticmethod
	def get_rights(f1) :
		bits = format(f1, '09b')
		for i in range(len(bits)) :
			yield 'rwxrwxrwx'[i] if bits[i] == '1' else '-'
	
	def get_flags(self) :
		a_flags = MFS_Config_Record_GetAccess()
		a_flags.asbytes = self.AccessMode
		o_flags = MFS_Config_Record_GetOptions()
		o_flags.asbytes = self.DeployOptions
		
		return a_flags.b.UnixRights, a_flags.b.Integrity, a_flags.b.Encryption, a_flags.b.AntiReplay, a_flags.b.RecordType,\
		       a_flags.b.Unknown, o_flags.b.OEMConfigurable, o_flags.b.MCAConfigurable, o_flags.b.Unknown
			   
class MFS_Config_Record_Access(ctypes.LittleEndianStructure):
	_fields_ = [
		('UnixRights', uint16_t, 9),
		('Integrity', uint16_t, 1), # HMAC
		('Encryption', uint16_t, 1),
		('AntiReplay', uint16_t, 1),
		('RecordType', uint16_t, 1), # 0 File, 1 Folder
		('Unknown', uint16_t, 3)
	]
	
class MFS_Config_Record_GetAccess(ctypes.Union):
	_fields_ = [
		('b', MFS_Config_Record_Access),
		('asbytes', uint16_t)
	]
	
class MFS_Config_Record_Options(ctypes.LittleEndianStructure):
	_fields_ = [
		('OEMConfigurable', uint16_t, 1), # OEM fitc.cfg setting can overwrite Intel intl.cfg equivalent setting via Flash Image Tool
		('MCAConfigurable', uint16_t, 1), # Manufacturing Configuration Architecture module can configure MFS CVARs in Manufacturing Mode
		('Unknown', uint16_t, 14)
	]
	
class MFS_Config_Record_GetOptions(ctypes.Union):
	_fields_ = [
		('b', MFS_Config_Record_Options),
		('asbytes', uint16_t)
	]
	
# noinspection PyTypeChecker
class MFS_Config_Record_0xC(ctypes.LittleEndianStructure) : # MFS Configuration Record 0xC
	_pack_ = 1
	_fields_ = [
		('FileID',			uint32_t),		# 0x00
		('FileOffset',		uint32_t),		# 0x04
		('FileSize',		uint16_t),		# 0x08
		('Flags',			uint16_t),		# 0x0A
		# 0x0C
	]
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Configuration Record' + col_e
		pt.add_row(['File ID', '0x%0.8X' % self.FileID])
		#pt.add_row(['Offset', '0x%X' % self.FileOffset])
		pt.add_row(['Size', '0x%X' % self.FileSize])
		pt.add_row(['OEM Configurable', fvalue[f1]])
		pt.add_row(['Unknown Flags', '{0:015b}b'.format(f2)])
		
		return pt
		
	def get_flags(self) :
		flags = MFS_Config_Record_0xC_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.OEMConfigurable, flags.b.Unknown
			   
class MFS_Config_Record_0xC_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('OEMConfigurable', uint16_t, 1), # OEM fitc.cfg setting can overwrite Intel intl.cfg equivalent setting via Flash Image Tool
		('Unknown', uint16_t, 15)
	]
	
class MFS_Config_Record_0xC_GetFlags(ctypes.Union):
	_fields_ = [
		('b', MFS_Config_Record_0xC_Flags),
		('asbytes', uint16_t)
	]
	
# noinspection PyTypeChecker
class MFS_Home_Record_0x18(ctypes.LittleEndianStructure) : # MFS Home Directory Record 0x18
	_pack_ = 1
	_fields_ = [
		('FileInfo',		uint32_t),		# 0x00
		('AccessMode',		uint16_t),		# 0x04
		('OwnerUserID',		uint16_t),		# 0x06
		('OwnerGroupID',	uint16_t),		# 0x08
		('UnknownSalt',		uint16_t),		# 0x0A
		('FileName',		char*12),		# 0x0C
		# 0x18
	]
	
	# Remember to also adjust MFS_Home_Record_0x1C for common fields
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Home Record' + col_e
		pt.add_row(['Index', '%d' % f1])
		pt.add_row(['Name', self.FileName.decode('utf-8')])
		pt.add_row(['Type', ['File','Folder'][f10]])
		pt.add_row(['Keys', ['Intel','Other'][f9]])
		pt.add_row(['File System', mfs_type[f3]])
		pt.add_row(['Access Rights', ''.join(map(str, self.get_rights(f4)))])
		pt.add_row(['Owner User ID', '%0.4X' % self.OwnerUserID])
		pt.add_row(['Owner Group ID', '%0.4X' % self.OwnerGroupID])
		pt.add_row(['Integrity Protection', fvalue[f5]])
		pt.add_row(['Encryption Protection', fvalue[f6]])
		pt.add_row(['Anti-Replay Protection', fvalue[f7]])
		pt.add_row(['Access Mode Unknown 0', '{0:01b}b'.format(f8)])
		pt.add_row(['Access Mode Unknown 1', '{0:01b}b'.format(f11)])
		pt.add_row(['Integrity Salt', '0x%0.4X' % f2])
		pt.add_row(['Unknown Salt', '0x%X' % self.UnknownSalt])
		
		return pt
		
	@staticmethod
	def get_rights(f4) :
		bits = format(f4, '09b')
		for i in range(len(bits)) :
			yield 'rwxrwxrwx'[i] if bits[i] == '1' else '-'
	
	def get_flags(self) :
		f_flags = MFS_Home_Record_GetFileInfo()
		f_flags.asbytes = self.FileInfo
		a_flags = MFS_Home_Record_GetAccess()
		a_flags.asbytes = self.AccessMode
		
		return f_flags.b.FileIndex, f_flags.b.IntegritySalt, f_flags.b.FileSystemID, a_flags.b.UnixRights, a_flags.b.Integrity, \
		       a_flags.b.Encryption, a_flags.b.AntiReplay, a_flags.b.Unknown0, a_flags.b.KeyType, a_flags.b.RecordType, a_flags.b.Unknown1
			   
# noinspection PyTypeChecker
class MFS_Home_Record_0x1C(ctypes.LittleEndianStructure) : # MFS Home Directory Record 0x1C
	_pack_ = 1
	_fields_ = [
		('FileInfo',		uint32_t),		# 0x00
		('AccessMode',		uint16_t),		# 0x04
		('OwnerUserID',		uint16_t),		# 0x06
		('OwnerGroupID',	uint16_t),		# 0x08
		('UnknownSalt',		uint16_t*3),	# 0x0A
		('FileName',		char*12),		# 0x10
		# 0x1C
	]
	
	# Remember to also adjust MFS_Home_Record_0x18 for common fields
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11 = self.get_flags()
		
		UnknownSalt = ''.join('%0.4X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.UnknownSalt))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Home Record' + col_e
		pt.add_row(['Index', '%d' % f1])
		pt.add_row(['Name', self.FileName.decode('utf-8')])
		pt.add_row(['Type', ['File','Folder'][f10]])
		pt.add_row(['Keys', ['Intel','Other'][f9]])
		pt.add_row(['File System', mfs_type[f3]])
		pt.add_row(['Access Rights', ''.join(map(str, self.get_rights(f4)))])
		pt.add_row(['Owner User ID', '%0.4X' % self.OwnerUserID])
		pt.add_row(['Owner Group ID', '%0.4X' % self.OwnerGroupID])
		pt.add_row(['Integrity Protection', fvalue[f5]])
		pt.add_row(['Encryption Protection', fvalue[f6]])
		pt.add_row(['Anti-Replay Protection', fvalue[f7]])
		pt.add_row(['Access Mode Unknown 0', '{0:01b}b'.format(f8)])
		pt.add_row(['Access Mode Unknown 1', '{0:01b}b'.format(f11)])
		pt.add_row(['Integrity Salt', '0x%0.4X' % f2])
		pt.add_row(['Unknown Salt', '0x%s' % UnknownSalt])
		
		return pt
		
	@staticmethod
	def get_rights(f4) :
		bits = format(f4, '09b')
		for i in range(len(bits)) :
			yield 'rwxrwxrwx'[i] if bits[i] == '1' else '-'
	
	def get_flags(self) :
		f_flags = MFS_Home_Record_GetFileInfo()
		f_flags.asbytes = self.FileInfo
		a_flags = MFS_Home_Record_GetAccess()
		a_flags.asbytes = self.AccessMode
		
		return f_flags.b.FileIndex, f_flags.b.IntegritySalt, f_flags.b.FileSystemID, a_flags.b.UnixRights, a_flags.b.Integrity, \
		       a_flags.b.Encryption, a_flags.b.AntiReplay, a_flags.b.Unknown0, a_flags.b.KeyType, a_flags.b.RecordType, a_flags.b.Unknown1

class MFS_Home_Record_FileInfo(ctypes.LittleEndianStructure):
	_fields_ = [
		('FileIndex', uint32_t, 12), # MFS Low Level File Index
		('IntegritySalt', uint32_t, 16), # For MFS_Integrity_Table.HMAC
		('FileSystemID', uint32_t, 4) # 0 root, 1 home, 2 bin, 3 susram, 4 fpf, 5 dev, 6 umafs
	]
	
class MFS_Home_Record_GetFileInfo(ctypes.Union):
	_fields_ = [
		('b', MFS_Home_Record_FileInfo),
		('asbytes', uint32_t)
	]			   
			 
class MFS_Home_Record_Access(ctypes.LittleEndianStructure):
	_fields_ = [
		('UnixRights', uint16_t, 9),
		('Integrity', uint16_t, 1), # HMAC
		('Encryption', uint16_t, 1),
		('AntiReplay', uint16_t, 1),
		('Unknown0', uint16_t, 1),
		('KeyType', uint16_t, 1), # 0 Intel, 1 Other
		('RecordType', uint16_t, 1), # 0 File, 1 Folder
		('Unknown1', uint16_t, 1)
	]
	
class MFS_Home_Record_GetAccess(ctypes.Union):
	_fields_ = [
		('b', MFS_Home_Record_Access),
		('asbytes', uint16_t)
	]

# noinspection PyTypeChecker
class MFS_Integrity_Table_0x34(ctypes.LittleEndianStructure) : # MFS Integrity Table 0x34
	_pack_ = 1
	_fields_ = [
		('HMACSHA256',		uint32_t*8),	# 0x00 HMAC SHA-256
		('Flags',			uint32_t),		# 0x20
		('ARValues_Nonce',	uint32_t*4),	# 0x2C Anti-Replay Random Value (32-bit) + Counter Value (32-bit) or AES-CTR Nonce (128-bit)
		# 0x34
	]
	
	# HMAC = File Contents + MFS_Integrity_Table with HMACSHA256 = 0, MFS_Home_Record.FileInfo.FileIndex + MFS_Home_Record.FileInfo.IntegritySalt (32-bit).
	# For MFS Low Level Files without MFS_Home_Record (2 Anti-Replay, 3 Anti-Replay, 8 Home): FileIndex = 0x10000000 + 2|3|8 and IntegritySalt = 0.
	# The MFS_Integrity_Table HMAC SHA-256 Integrity value cannot be verified by 3rd-party entities without Intel's Secret Key within the CSE.
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8 = self.get_flags()
		
		HMACSHA256 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.HMACSHA256))
		ARValues_Nonce = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.ARValues_Nonce))
		ARRandom, ARCounter = struct.unpack_from('<II', self.ARValues_Nonce, 0)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Integrity Table' + col_e
		pt.add_row(['HMAC SHA-256', HMACSHA256])
		pt.add_row(['Flags Unknown 0', '{0:01b}b'.format(f1)])
		pt.add_row(['Anti-Replay Protection', fvalue[f2]])
		pt.add_row(['Encryption Protection', fvalue[f3]])
		pt.add_row(['Flags Unknown 1', '{0:07b}b'.format(f4)])
		pt.add_row(['Anti-Replay Index', '%d' % f5])
		pt.add_row(['Flags Unknown 2', '{0:01b}b'.format(f6)])
		pt.add_row(['Security Version Number', '%d' % f7])
		pt.add_row(['Flags Unknown 3', '{0:03b}b'.format(f8)])
		pt.add_row(['Anti-Replay Random Value', '0x%0.8X' % ARRandom])
		pt.add_row(['Anti-Replay Counter Value', '0x%0.8X' % ARCounter])
		pt.add_row(['Encryption Nonce', ARValues_Nonce])
		
		return pt
	
	def get_flags(self) :
		i_flags = MFS_Integrity_Table_GetFlags_0x34()
		i_flags.asbytes = self.Flags
		
		return i_flags.b.Unknown0, i_flags.b.AntiReplay, i_flags.b.Encryption, i_flags.b.Unknown1, i_flags.b.ARIndex, \
			   i_flags.b.Unknown2, i_flags.b.SVN, i_flags.b.Unknown3

class MFS_Integrity_Table_Flags_0x34(ctypes.LittleEndianStructure):
	_fields_ = [
		('Unknown0', uint32_t, 1),
		('AntiReplay', uint32_t, 1),
		('Encryption', uint32_t, 1), # 0 Non-Encrypted, 1 Encrypted
		('Unknown1', uint32_t, 7),
		('ARIndex', uint32_t, 10), # Anti-Replay Index (0 < MFS Volume Records <= 1023, 1023 = 1111111111 or 10-bit length)
		('Unknown2', uint32_t, 1),
		('SVN', uint32_t, 8), # Security Version Number (0 < SVN <= 255, 255 = 11111111 or 8-bit length)
		('Unknown3', uint32_t, 3)
	]
	
class MFS_Integrity_Table_GetFlags_0x34(ctypes.Union):
	_fields_ = [
		('b', MFS_Integrity_Table_Flags_0x34),
		('asbytes', uint32_t)
	]
			   
# noinspection PyTypeChecker
class MFS_Integrity_Table_0x28(ctypes.LittleEndianStructure) : # MFS Integrity Table 0x28
	_pack_ = 1
	_fields_ = [
		('HMACMD5',			uint32_t*4),	# 0x00 HMAC MD5
		('Flags',			uint32_t),		# 0x10
		('ARRandom',		uint32_t),		# 0x14 Anti-Replay Random Value
		('ARCounter',		uint32_t),		# 0x18 Anti-Replay Counter Value
		('Unknown',			uint32_t*3),	# 0x1C AES-CTR Nonce ?
		# 0x28
	]
	
	def mfs_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9 = self.get_flags()
		
		HMACMD5 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.HMACMD5))
		Unknown = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Integrity Table' + col_e
		pt.add_row(['HMAC MD5', HMACMD5])
		pt.add_row(['Flags Unknown 0', '{0:01b}b'.format(f1)])
		pt.add_row(['Anti-Replay Protection', fvalue[f2]])
		pt.add_row(['Flags Unknown 1', '{0:01b}b'.format(f3)])
		pt.add_row(['Encryption Protection', fvalue[f4]])
		pt.add_row(['Flags Unknown 2', '{0:07b}b'.format(f5)])
		pt.add_row(['Anti-Replay Index', '%d' % f6])
		pt.add_row(['Flags Unknown 3', '{0:01b}b'.format(f7)])
		pt.add_row(['Security Version Number', '%d' % f8])
		pt.add_row(['Flags Unknown 4', '{0:02b}b'.format(f9)])
		pt.add_row(['Anti-Replay Random Value', '0x%0.8X' % self.ARRandom])
		pt.add_row(['Anti-Replay Counter Value', '0x%0.8X' % self.ARCounter])
		pt.add_row(['Unknown', '0x%s' % Unknown])
		
		return pt
		
	def get_flags(self) :
		i_flags = MFS_Integrity_Table_GetFlags_0x28()
		i_flags.asbytes = self.Flags
		
		return i_flags.b.Unknown0, i_flags.b.AntiReplay, i_flags.b.Unknown1, i_flags.b.Encryption, i_flags.b.Unknown2, \
			   i_flags.b.ARIndex, i_flags.b.Unknown3, i_flags.b.SVN, i_flags.b.Unknown4
			   
class MFS_Integrity_Table_Flags_0x28(ctypes.LittleEndianStructure):
	_fields_ = [
		('Unknown0', uint32_t, 1),
		('AntiReplay', uint32_t, 1),
		('Unknown1', uint32_t, 1),
		('Encryption', uint32_t, 1), # 0 Non-Encrypted or Encrypted w/o Size, 1 Encrypted
		('Unknown2', uint32_t, 7), # 0100111b for Encrypted, 0010111b for Non-Encrypted
		('ARIndex', uint32_t, 10), # Anti-Replay Index (0 < MFS Volume Records <= 1023, 1023 = 1111111111 or 10-bit length)
		('Unknown3', uint32_t, 1),
		('SVN', uint32_t, 8), # Security Version Number (0 < SVN <= 255, 255 = 11111111 or 8-bit length)
		('Unknown4', uint32_t, 2)
	]
	
class MFS_Integrity_Table_GetFlags_0x28(ctypes.Union):
	_fields_ = [
		('b', MFS_Integrity_Table_Flags_0x28),
		('asbytes', uint32_t)
	]
	
# noinspection PyTypeChecker
class MFS_Quota_Storage_Header(ctypes.LittleEndianStructure) : # MFS Quota Storage Header
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00
		('Revision',		uint16_t),		# 0x04
		('EntryCount',		uint16_t),		# 0x06 Should match FTPR/NFTP > vfs.met > Extension 13 Entries
		# 0x08
	]
	
	def mfs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Quota Storage Header' + col_e
		pt.add_row(['Signature', '0x%0.8X' % self.Signature])
		pt.add_row(['Revision', '%d' % self.Revision])
		pt.add_row(['Entry Count', '%d' % self.EntryCount])
		
		return pt
		
# noinspection PyTypeChecker
class MFS_Backup_Header(ctypes.LittleEndianStructure) : # MFS Backup
	_pack_ = 1
	_fields_ = [
		('Signature',		uint32_t),		# 0x00 MFSB
		('CRC32',			uint32_t),		# 0x04
		('Reserved',		uint32_t*6),	# 0x08 FF * 24
		# 0x20
	]
	
	def mfs_print(self) :
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'MFS Backup Header' + col_e
		pt.add_row(['Signature', '0x%0.8X' % self.Signature])
		pt.add_row(['CRC-32', '0x%0.8X' % self.CRC32])
		pt.add_row(['Reserved', '0xFF * 24' if Reserved == 'FFFFFFFF' * 6 else Reserved])
		
		return pt
