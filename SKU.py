import ctypes

from struct_types import char, uint8_t, uint16_t, uint32_t, uint64_t

# noinspection PyTypeChecker
class SKU_Attributes(ctypes.LittleEndianStructure) : # Pre-CSE $SKU
	_pack_ = 1
	_fields_ = [
		('Tag',				char*4),		# 0x00
		('Size',			uint32_t),		# 0x04 dwords
		('FWSKUAttrib',		uint64_t),		# 0x08 (uint32_t for ME 2-6 & SPS 1-3)
		# 0x10 (0xC for ME 2-6 & SPS 1-3)
	]
	
	def hdr_print(self) :
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + '$SKU New' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Size', '0x%X' % (self.Size * 4)])
		pt.add_row(['Value 1', '0x%X' % f1])
		pt.add_row(['Value 2', f2])
		pt.add_row(['Value 3', f3])
		pt.add_row(['Value 4', f4])
		pt.add_row(['Value 5', f5])
		pt.add_row(['Value 6', f6])
		pt.add_row(['Value 7', f7])
		pt.add_row(['Value 8', f8])
		pt.add_row(['Value 9', f9])
		pt.add_row(['Patsburg', ['No','Yes'][f10]])
		pt.add_row(['SKU Type', ['Corporate','Consumer','Slim'][f11]])
		pt.add_row(['SKU Size', '%0.1f MB' % (f12 * 0.5)])
		pt.add_row(['Value 10', '0x%X' % f13])
		
		return pt
	
	def get_flags(self) :
		flags = SKU_Attributes_GetFlags()
		flags.asbytes = self.FWSKUAttrib
		
		return flags.b.Value1, flags.b.Value2, flags.b.Value3, flags.b.Value4, flags.b.Value5, flags.b.Value6, \
		flags.b.Value7, flags.b.Value8, flags.b.Value9, flags.b.Patsburg, flags.b.SKUType, flags.b.SKUSize, flags.b.Value10

class SKU_Attributes_Flags(ctypes.BigEndianStructure):
	_fields_ = [
		('Value1', uint64_t, 24),
		('Value2', uint64_t, 1), # Slim (ME 7)
		('Value3', uint64_t, 1),
		('Value4', uint64_t, 1),
		('Value5', uint64_t, 1),
		('Value6', uint64_t, 1),
		('Value7', uint64_t, 1),
		('Value8', uint64_t, 1),
		('Value9', uint64_t, 1),
		('Patsburg', uint64_t, 1), # 0 No, 1 Yes (ME 7-8)
		('SKUType', uint64_t, 3), # 0 Corporate, 1 Consumer, 2 Slim (ME 9-10)
		('SKUSize', uint64_t, 4), # Size * 0.5MB (ME 7-10, TXE 0-2)
		('Value10', uint64_t, 24)
	]
	
class SKU_Attributes_GetFlags(ctypes.Union):
	_fields_ = [
		('b', SKU_Attributes_Flags),
		('asbytes', uint64_t)
	]
