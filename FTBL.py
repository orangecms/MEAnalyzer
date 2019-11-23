import ctypes

from struct_types import char, uint8_t, uint16_t, uint32_t, uint64_t

# noinspection PyTypeChecker
class FTBL_Header(ctypes.LittleEndianStructure) : # File Tables Header
	_pack_ = 1
	_fields_ = [
		('Signature',		char*4),		# 0x00
		('Unknown',			uint32_t),		# 0x04 Reserved ?
		('HeaderSize',		uint32_t),		# 0x08
		('TableCount',		uint32_t),		# 0x0C
		# 0x10
	]
	
	def mfs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'File Tables Header' + col_e
		pt.add_row(['Signature', self.Signature.decode('utf-8')])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		pt.add_row(['Header Size', '0x%X' % self.HeaderSize])
		pt.add_row(['Table Count', '%d' % self.TableCount])
		
		return pt
		
# noinspection PyTypeChecker
class FTBL_Table(ctypes.LittleEndianStructure) : # File Table Header
	_pack_ = 1
	_fields_ = [
		('Dictionary',		uint32_t),		# 0x00
		('Offset',			uint32_t),		# 0x04
		('EntryCount',		uint32_t),		# 0x08
		('Size',			uint32_t),		# 0x0C
		# 0x10
	]
	
	def mfs_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'File Table Header' + col_e
		pt.add_row(['Dictionary', '0x%0.2X' % self.Dictionary])
		pt.add_row(['Offset', '0x%X' % self.Offset])
		pt.add_row(['Entry Count', '%d' % self.EntryCount])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt
		
# noinspection PyTypeChecker
class FTBL_Entry(ctypes.LittleEndianStructure) : # File Table Entry
	_pack_ = 1
	_fields_ = [
		('Path',			char*48),		# 0x00
		('FileID',			uint32_t),		# 0x30
		('Unknown0',		uint16_t),		# 0x34
		('GroudID',			uint16_t),		# 0x36
		('UserID',			uint16_t),		# 0x38
		('Unknown1',		uint16_t),		# 0x3A
		('Access',			uint32_t),		# 0x3C
		('Options',			uint32_t),		# 0x40
		# 0x44
	]
	
	def mfs_print(self) :
		f1,f2,f3 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'File Table Entry' + col_e
		pt.add_row(['Path', self.Path.decode('utf-8')])
		pt.add_row(['File ID', '0x%X' % self.FileID])
		pt.add_row(['Unknown 0', '0x%0.4X' % self.Unknown0])
		pt.add_row(['Group ID', '0x%0.4X' % self.GroudID])
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Unknown 1', '0x%0.4X' % self.Unknown1])
		pt.add_row(['Access Rights', ''.join(map(str, self.get_rights(f1)))])
		pt.add_row(['Access Unknown', '{0:023b}b'.format(f2)])
		pt.add_row(['Options Unknown', '{0:032b}b'.format(f3)])
		
		return pt
		
	@staticmethod
	def get_rights(f1) :
		bits = format(f1, '09b')
		for i in range(len(bits)) :
			yield 'rwxrwxrwx'[i] if bits[i] == '1' else '-'
	
	def get_flags(self) :
		a_flags = FTBL_Entry_GetAccess()
		a_flags.asbytes = self.Access
		o_flags = FTBL_Entry_GetOptions()
		o_flags.asbytes = self.Options
		
		return a_flags.b.UnixRights, a_flags.b.Unknown, o_flags.b.Unknown
			   
class FTBL_Entry_Access(ctypes.LittleEndianStructure):
	_fields_ = [
		('UnixRights', uint32_t, 9),
		('Unknown', uint32_t, 23)
	]
	
class FTBL_Entry_GetAccess(ctypes.Union):
	_fields_ = [
		('b', FTBL_Entry_Access),
		('asbytes', uint32_t)
	]
	
class FTBL_Entry_Options(ctypes.LittleEndianStructure):
	_fields_ = [
		('Unknown', uint32_t, 32)
	]
	
class FTBL_Entry_GetOptions(ctypes.Union):
	_fields_ = [
		('b', FTBL_Entry_Options),
		('asbytes', uint32_t)
	]
