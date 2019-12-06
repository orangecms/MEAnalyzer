import ctypes

from MFS import *

from struct_types import char, uint8_t, uint16_t, uint32_t, uint64_t

class CSE_Layout_Table_16(ctypes.LittleEndianStructure) : # IFWI 1.6 (CseLayoutTable, IfwiRegionData)
	_pack_ = 1
	_fields_ = [
		('ROMBInstr0',		uint32_t),		# 0x00 ROM-Bypass Vector 0
		('ROMBInstr1',		uint32_t),		# 0x04
		('ROMBInstr2',		uint32_t),		# 0x08
		('ROMBInstr3',		uint32_t),		# 0x0C
		('DataOffset',		uint32_t),		# 0x10 Data Partition Base Address
		('DataSize',		uint32_t),		# 0x14 Data Partition Size
		('BP1Offset',		uint32_t),		# 0x18 Boot Partition 1 Base Address
		('BP1Size',			uint32_t),		# 0x1C Boot Partition 1 Size
		('BP2Offset',		uint32_t),		# 0x20
		('BP2Size',			uint32_t),		# 0x24
		('BP3Offset',		uint32_t),		# 0x28
		('BP3Size',			uint32_t),		# 0x2C
		('BP4Offset',		uint32_t),		# 0x30 Reserved
		('BP4Size',			uint32_t),		# 0x34
		('BP5Offset',		uint32_t),		# 0x38 Reserved
		('BP5Size',			uint32_t),		# 0x3C
		('Checksum',		uint64_t),		# 0x40 2's complement of CSE Layout Table (w/o ROMB), sum of the CSE LT + Checksum = 0
		# 0x48
	]
	
	# Used at Cannon Point (CNP) IFWI 1.6 platform
	
	def hdr_print(self) :
		NA = [0,0xFFFFFFFF] # Non-ROMB or IFWI EXTR
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'CSE Layout Table 1.6 & 2.0' + col_e
		pt.add_row(['ROMB Instruction 0', 'N/A' if self.ROMBInstr0 in NA else '0x%X' % self.ROMBInstr0])
		pt.add_row(['ROMB Instruction 1', 'N/A' if self.ROMBInstr1 in NA else '0x%X' % self.ROMBInstr1])
		pt.add_row(['ROMB Instruction 2', 'N/A' if self.ROMBInstr2 in NA else '0x%X' % self.ROMBInstr2])
		pt.add_row(['ROMB Instruction 3', 'N/A' if self.ROMBInstr3 in NA else '0x%X' % self.ROMBInstr3])
		pt.add_row(['Data Partition Offset', '0x%X' % self.DataOffset])
		pt.add_row(['Data Partition Size', '0x%X' % self.DataSize])
		pt.add_row(['Boot Partition 1 Offset', '0x%X' % self.BP1Offset])
		pt.add_row(['Boot Partition 1 Size', '0x%X' % self.BP1Size])
		pt.add_row(['Boot Partition 2 Offset', '0x%X' % self.BP2Offset])
		pt.add_row(['Boot Partition 2 Size', '0x%X' % self.BP2Size])
		pt.add_row(['Boot Partition 3 Offset', '0x%X' % self.BP3Offset])
		pt.add_row(['Boot Partition 3 Size', '0x%X' % self.BP3Size])
		pt.add_row(['Boot Partition 4 Offset', '0x%X' % self.BP4Offset])
		pt.add_row(['Boot Partition 4 Size', '0x%X' % self.BP4Size])
		pt.add_row(['Boot Partition 5 Offset', '0x%X' % self.BP5Offset])
		pt.add_row(['Boot Partition 5 Size', '0x%X' % self.BP5Size])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		
		return pt

class CSE_Layout_Table_17(ctypes.LittleEndianStructure) : # IFWI 1.7 (CseLayoutTable, IfwiRegionData)
	_pack_ = 1
	_fields_ = [
		('ROMBInstr0',		uint32_t),		# 0x00 ROM-Bypass Vector 0
		('ROMBInstr1',		uint32_t),		# 0x04
		('ROMBInstr2',		uint32_t),		# 0x08
		('ROMBInstr3',		uint32_t),		# 0x0C
		('Size',			uint16_t),		# 0x10
		('Flags',			uint8_t),		# 0x12 0 CSE Pointer Redundancy, 1-7 Reserved
		('Reserved',		uint8_t),		# 0x13
		('Checksum',		uint32_t),		# 0x14 CRC-32 of CSE LT pointers w/o ROMB (DataOffset - TempPagesSize)
		('DataOffset',		uint32_t),		# 0x18 Data Partition Base Address
		('DataSize',		uint32_t),		# 0x1C Data Partition Size
		('BP1Offset',		uint32_t),		# 0x20 Boot Partition 1 Base Address
		('BP1Size',			uint32_t),		# 0x24 Boot Partition 1 Size
		('BP2Offset',		uint32_t),		# 0x28
		('BP2Size',			uint32_t),		# 0x2C
		('BP3Offset',		uint32_t),		# 0x30
		('BP3Size',			uint32_t),		# 0x34
		('BP4Offset',		uint32_t),		# 0x38
		('BP4Size',			uint32_t),		# 0x3C
		('BP5Offset',		uint32_t),		# 0x40
		('BP5Size',			uint32_t),		# 0x44
		('TempPagesOffset',	uint32_t),		# 0x48 Temporary Pages for DRAM cache, 0 for NVM
		('TempPagesSize',	uint32_t),		# 0x4C
		# 0x50
	]
	
	# Used at Lake Field (LKF) IFWI 1.7 platform
	# When CSE Pointer Redundancy is set, the entire (?) structure is duplicated
	
	def hdr_print(self) :
		f1,f2 = self.get_flags()
		NA = [0,0xFFFFFFFF] # Non-ROMB or IFWI EXTR
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'CSE Layout Table 1.7' + col_e
		pt.add_row(['ROMB Instruction 0', 'N/A' if self.ROMBInstr0 in NA else '0x%X' % self.ROMBInstr0])
		pt.add_row(['ROMB Instruction 1', 'N/A' if self.ROMBInstr1 in NA else '0x%X' % self.ROMBInstr1])
		pt.add_row(['ROMB Instruction 2', 'N/A' if self.ROMBInstr2 in NA else '0x%X' % self.ROMBInstr2])
		pt.add_row(['ROMB Instruction 3', 'N/A' if self.ROMBInstr3 in NA else '0x%X' % self.ROMBInstr3])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['CSE Pointer Redundancy', ['No','Yes'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Checksum', '0x%X' % self.Checksum])
		pt.add_row(['Data Partition Offset', '0x%X' % self.DataOffset])
		pt.add_row(['Data Partition Size', '0x%X' % self.DataSize])
		pt.add_row(['Boot Partition 1 Offset', '0x%X' % self.BP1Offset])
		pt.add_row(['Boot Partition 1 Size', '0x%X' % self.BP1Size])
		pt.add_row(['Boot Partition 2 Offset', '0x%X' % self.BP2Offset])
		pt.add_row(['Boot Partition 2 Size', '0x%X' % self.BP2Size])
		pt.add_row(['Boot Partition 3 Offset', '0x%X' % self.BP3Offset])
		pt.add_row(['Boot Partition 3 Size', '0x%X' % self.BP3Size])
		pt.add_row(['Boot Partition 4 Offset', '0x%X' % self.BP4Offset])
		pt.add_row(['Boot Partition 4 Size', '0x%X' % self.BP4Size])
		pt.add_row(['Boot Partition 5 Offset', '0x%X' % self.BP5Offset])
		pt.add_row(['Boot Partition 5 Size', '0x%X' % self.BP5Size])
		pt.add_row(['Temporary Pages Offset', '0x%X' % self.TempPagesOffset])
		pt.add_row(['Temporary Pages Size', '0x%X' % self.TempPagesSize])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Layout_Table_17_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.CSE_P_R, flags.b.Reserved
		
class CSE_Layout_Table_17_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('CSE_P_R', uint8_t, 1),
		('Reserved', uint8_t, 7),
	]

class CSE_Layout_Table_17_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Layout_Table_17_Flags),
		('asbytes', uint8_t)
	]

############
	
# noinspection PyTypeChecker
class CSE_Ext_00(ctypes.LittleEndianStructure) : # R1 - System Information (SYSTEM_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("MinUMASize",		uint32_t),		# 0x08
		("ChipsetVersion",	uint32_t),		# 0x0C
		("IMGDefaultHash",	uint32_t*8),	# 0x10 SHA-256, CSME/SPS MFS > Low Level File 6 or CSTXE FTPR > intl.cfg
		("PageableUMASize",	uint32_t),		# 0x30
		("Reserved0",		uint64_t),		# 0x34
		("Reserved1",		uint32_t),		# 0x3C
		# 0x40
	]
	
	# The MFS Intel Configuration (Low Level File 6) Hash is only checked at first boot, before the MFS is Initialized.
	# After the MFS Home Directory (Low Level Files 8+) is generated, MFS Intel Configuration is no longer used or checked.
	# The initial MFS Intel Configuration remains the same even after FWUpdate is executed so the FTPR Manifest Hash is wrong.
	# Thus, the MFS Intel Configuration Hash must only be checked at non-Initialized MFS before any possible FWUpdate operations.
	
	def ext_print(self) :
		IMGDefaultHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.IMGDefaultHash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 0, System Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minimum UMA Size', '0x%X' % self.MinUMASize])
		pt.add_row(['Chipset Version', '0x%X' % self.ChipsetVersion])
		pt.add_row(['Intel Config Hash', '%s' % IMGDefaultHash])
		pt.add_row(['Pageable UMA Size', '0x%X' % self.PageableUMASize])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_00_R2(ctypes.LittleEndianStructure) : # R2 - System Information (SYSTEM_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("MinUMASize",		uint32_t),		# 0x08
		("ChipsetVersion",	uint32_t),		# 0x0C
		("IMGDefaultHash",	uint32_t*12),	# 0x10 SHA-384, CSME/SPS MFS > Low Level File 6 or CSTXE FTPR > intl.cfg
		("PageableUMASize",	uint32_t),		# 0x40
		("Reserved0",		uint64_t),		# 0x44
		("Reserved1",		uint32_t),		# 0x4C
		# 0x50
	]
	
	# The MFS Intel Configuration (Low Level File 6) Hash is only checked at first boot, before the MFS is Initialized.
	# After the MFS Home Directory (Low Level Files 8+) is generated, MFS Intel Configuration is no longer used or checked.
	# The initial MFS Intel Configuration remains the same even after FWUpdate is executed so the FTPR Manifest Hash is wrong.
	# Thus, the MFS Intel Configuration Hash must only be checked at non-Initialized MFS before any possible FWUpdate operations.
	
	def ext_print(self) :
		IMGDefaultHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.IMGDefaultHash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 0, System Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minimum UMA Size', '0x%X' % self.MinUMASize])
		pt.add_row(['Chipset Version', '0x%X' % self.ChipsetVersion])
		pt.add_row(['Intel Config Hash', '%s' % IMGDefaultHash])
		pt.add_row(['Pageable UMA Size', '0x%X' % self.PageableUMASize])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_00_Mod(ctypes.LittleEndianStructure) : # R1 - (INDEPENDENT_PARTITION_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*4),		# 0x00
		("Version",			uint32_t),		# 0x04
		("UserID",			uint16_t),		# 0x08
		("Reserved",		uint16_t),		# 0x0A
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 0, Independent Partition' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Version', '0x%X' % self.Version])
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_00_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (INDEPENDENT_PARTITION_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*4),		# 0x00
		("Version",			uint32_t),		# 0x04
		("UserID",			uint16_t),		# 0x08
		("Reserved0",		uint16_t),		# 0x0A
		("Reserved1",		uint16_t),		# 0x0C
		("Reserved2",		uint16_t),		# 0x0E
		# 0x10
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 0, Independent Partition' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Version', '0x%X' % self.Version])
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['Reserved 2', '0x%X' % self.Reserved2])
		
		return pt

class CSE_Ext_01(ctypes.LittleEndianStructure) : # R1 - Initialization Script (InitScript)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Reserved",		uint32_t),		# 0x08
		("ModuleCount",		uint32_t),		# 0x0C
		# 0x10
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 1, Initialization Script' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Module Count', '%d' % self.ModuleCount])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_01_Mod(ctypes.LittleEndianStructure) : # R1 - (InitScriptEntry)
	_pack_ = 1
	_fields_ = [
		("PartitionName",	char*4),		# 0x00
		("ModuleName",		char*12),		# 0x0C
		("InitFlowFlags",	uint32_t),		# 0x10
		("BootTypeFlags",	uint32_t),		# 0x14
		# 0x18
	]
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 1, Entry' + col_e
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Module Name', self.ModuleName.decode('utf-8')])
		pt.add_row(['IBL', fvalue[f1]])
		pt.add_row(['Removable', fvalue[f2]])
		pt.add_row(['Init Immediately', fvalue[f3]])
		pt.add_row(['Restart Policy', ['Not Allowed','Immediately','On Next Boot'][f4]])
		pt.add_row(['CM0 with UMA', fvalue[f5]])
		pt.add_row(['CM0 without UMA', fvalue[f6]])
		pt.add_row(['CM3', fvalue[f7]])
		pt.add_row(['Init Flow Reserved', '0x%X' % f8])
		pt.add_row(['Normal', fvalue[f9]])
		pt.add_row(['HAP', fvalue[f10]])
		pt.add_row(['HMRFPO', fvalue[f11]])
		pt.add_row(['Temp Disable', fvalue[f12]])
		pt.add_row(['Recovery', fvalue[f13]])
		pt.add_row(['Safe Mode', fvalue[f14]])
		pt.add_row(['FWUpdate', fvalue[f15]])
		pt.add_row(['Boot Type Reserved', '0x%X' % f16])
		
		return pt
	
	def get_flags(self) :
		i_flags = CSE_Ext_01_GetInitFlowFlags()
		b_flags = CSE_Ext_01_GetBootTypeFlags()
		i_flags.asbytes = self.InitFlowFlags
		b_flags.asbytes = self.BootTypeFlags
		
		return i_flags.b.IBL, i_flags.b.Removable, i_flags.b.InitImmediately, i_flags.b.RestartPolicy, i_flags.b.CM0_UMA,\
		       i_flags.b.CM0_NO_UMA, i_flags.b.CM3, i_flags.b.Reserved, b_flags.b.Normal, b_flags.b.HAP, b_flags.b.HMRFPO,\
			   b_flags.b.TempDisable, b_flags.b.Recovery, b_flags.b.SafeMode, b_flags.b.FWUpdate, b_flags.b.Reserved

# noinspection PyTypeChecker
class CSE_Ext_01_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (InitScriptEntry)
	_pack_ = 1
	_fields_ = [
		("PartitionName",	char*4),		# 0x00
		("ModuleName",		char*12),		# 0x0C
		("InitFlowFlags",	uint32_t),		# 0x10
		("BootTypeFlags",	uint32_t),		# 0x14
		("UnknownFlags",	uint32_t),		# 0x18 (Unknown)
		# 0x2C
	]
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 1, Entry' + col_e
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Module Name', self.ModuleName.decode('utf-8')])
		pt.add_row(['IBL', fvalue[f1]])
		pt.add_row(['Removable', fvalue[f2]])
		pt.add_row(['Init Immediately', fvalue[f3]])
		pt.add_row(['Restart Policy', ['Not Allowed','Immediately','On Next Boot'][f4]])
		pt.add_row(['CM0 with UMA', fvalue[f5]])
		pt.add_row(['CM0 without UMA', fvalue[f6]])
		pt.add_row(['CM3', fvalue[f7]])
		pt.add_row(['Init Flow Reserved', '{0:025b}b'.format(f8)])
		pt.add_row(['Normal', fvalue[f9]])
		pt.add_row(['HAP', fvalue[f10]])
		pt.add_row(['HMRFPO', fvalue[f11]])
		pt.add_row(['Temp Disable', fvalue[f12]])
		pt.add_row(['Recovery', fvalue[f13]])
		pt.add_row(['Safe Mode', fvalue[f14]])
		pt.add_row(['FWUpdate', fvalue[f15]])
		pt.add_row(['Boot Type Reserved', '{0:025b}b'.format(f15)])
		pt.add_row(['Unknown Flags', '{0:032b}b'.format(self.UnknownFlags)])
		
		return pt
	
	def get_flags(self) :
		i_flags = CSE_Ext_01_GetInitFlowFlags()
		b_flags = CSE_Ext_01_GetBootTypeFlags()
		i_flags.asbytes = self.InitFlowFlags
		b_flags.asbytes = self.BootTypeFlags
		
		return i_flags.b.IBL, i_flags.b.Removable, i_flags.b.InitImmediately, i_flags.b.RestartPolicy, i_flags.b.CM0_UMA,\
		       i_flags.b.CM0_NO_UMA, i_flags.b.CM3, i_flags.b.Reserved, b_flags.b.Normal, b_flags.b.HAP, b_flags.b.HMRFPO,\
			   b_flags.b.TempDisable, b_flags.b.Recovery, b_flags.b.SafeMode, b_flags.b.FWUpdate, b_flags.b.Reserved
			   
class CSE_Ext_01_InitFlowFlags(ctypes.LittleEndianStructure):
	_fields_ = [
		('IBL', uint32_t, 1),
		('Removable', uint32_t, 1),
		('InitImmediately', uint32_t, 1),
		('RestartPolicy', uint32_t, 1), # (InitScriptRestartPolicy)
		('CM0_UMA', uint32_t, 1),
		('CM0_NO_UMA', uint32_t, 1),
		('CM3', uint32_t, 1),
		('Reserved', uint32_t, 25)
	]
	
class CSE_Ext_01_GetInitFlowFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_01_InitFlowFlags),
		('asbytes', uint32_t)
	]
	
class CSE_Ext_01_BootTypeFlags(ctypes.LittleEndianStructure):
	_fields_ = [
		('Normal', uint32_t, 1),
		('HAP', uint32_t, 1),
		('HMRFPO', uint32_t, 1),
		('TempDisable', uint32_t, 1),
		('Recovery', uint32_t, 1),
		('SafeMode', uint32_t, 1),
		('FWUpdate', uint32_t, 1),
		('Reserved', uint32_t, 25)
	]

class CSE_Ext_01_GetBootTypeFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_01_BootTypeFlags),
		('asbytes', uint32_t)
	]

class CSE_Ext_02(ctypes.LittleEndianStructure) : # R1 - Feature Permissions (FEATURE_PERMISSIONS_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("ModuleCount",		uint32_t),		# 0x08
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 2, Feature Permissions' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Feature Count', '%d' % self.ModuleCount])
		
		return pt

class CSE_Ext_02_Mod(ctypes.LittleEndianStructure) : # R1 - (FEATURE_PERMISION_ENTRY)
	_pack_ = 1
	_fields_ = [
		("UserID",			uint16_t),		# 0x00
		("Reserved",		uint16_t),		# 0x02
		# 0x04
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 2, Entry' + col_e
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_03(ctypes.LittleEndianStructure) : # R1 - Partition Information (MANIFEST_PARTITION_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('PartitionSize',	uint32_t),		# 0x0C Complete original/RGN size before any process have been removed by the OEM or firmware update process
		('Hash',			uint32_t*8),	# 0x10 SHA-256, Complete original/RGN partition covering everything except for the Manifest ($CPD - $MN2 + Data)
		('VCN',				uint32_t),		# 0x30 Version Control Number
		('PartitionVer',	uint32_t),  	# 0x34
		('DataFormatMinor',	uint16_t),		# 0x14 dword (0-15 Major, 16-31 Minor)
		('DataFormatMajor',	uint16_t),		# 0x16 dword (0-15 Major, 16-31 Minor)
		('InstanceID', 		uint32_t),  	# 0x3C
		('Flags', 			uint32_t),  	# 0x40 Used at CSE_Ext_16 as well, remember to change both!
		('Reserved', 		uint32_t*4),  	# 0x44
		('Unknown', 		uint32_t),  	# 0x54 Unknown (>= 11.6.0.1109, 1 CSSPS, 3 CSME)
		# 0x58
	]
	
	# Used at $FPT size calculation as well, remember to change in case of new Extension Revision!
	
	# PartitionSize & Hash are valid for RGN firmware only with stock $CPD & Data, no FIT/OEM configurations. The latter, usually oem.key and fitc.cfg,
	# are added at the end of the PartitionSize so FIT adjusts $CPD and appends customization files accordingly. Thus, PartitionSize and Hash fields
	# must not be verified at FIT/OEM-customized images because they're not applicable anymore.
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9 = self.get_flags()
		
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 3, Partition Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Partition Size', '0x%X' % self.PartitionSize])
		pt.add_row(['Partition Hash', '%s' % Hash])
		pt.add_row(['Version Control Number', '%d' % self.VCN])
		pt.add_row(['Partition Version', '0x%X' % self.PartitionVer])
		pt.add_row(['Data Format Version', '%d.%d' % (self.DataFormatMajor, self.DataFormatMinor)])
		pt.add_row(['Instance ID', '0x%0.8X' % self.InstanceID])
		pt.add_row(['Support Multiple Instances', fvalue[f1]])
		pt.add_row(['Support API Version Based Update', fvalue[f2]])
		pt.add_row(['Action On Update', '0x%X' % f3])
		pt.add_row(['Obey Full Update Rules', fvalue[f4]])
		pt.add_row(['IFR Enable Only', fvalue[f5]])
		pt.add_row(['Allow Cross Point Update', fvalue[f6]])
		pt.add_row(['Allow Cross Hotfix Update', fvalue[f7]])
		pt.add_row(['Partial Update Only', fvalue[f8]])
		pt.add_row(['Flags Reserved', '0x%X' % f9])
		pt.add_row(['Reserved', '0x%s' % Reserved])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Ext_03_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.SupportMultipleInstances, flags.b.SupportApiVersionBasedUpdate, flags.b.ActionOnUpdate, flags.b.ObeyFullUpdateRules,\
		       flags.b.IfrEnableOnly, flags.b.AllowCrossPointUpdate, flags.b.AllowCrossHotfixUpdate, flags.b.PartialUpdateOnly, flags.b.Reserved
			   
# noinspection PyTypeChecker
class CSE_Ext_03_R2(ctypes.LittleEndianStructure) : # R2 - Partition Information (MANIFEST_PARTITION_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('PartitionSize',	uint32_t),		# 0x0C Complete original/RGN size before any process have been removed by the OEM or firmware update process
		('Hash',			uint32_t*12),	# 0x10 SHA-384, Complete original/RGN partition covering everything except for the Manifest ($CPD - $MN2 + Data)
		('VCN',				uint32_t),		# 0x40 Version Control Number
		('PartitionVer',	uint32_t),  	# 0x44
		('DataFormatMinor',	uint16_t),		# 0x48 dword (0-15 Major, 16-31 Minor)
		('DataFormatMajor',	uint16_t),		# 0x4A dword (0-15 Major, 16-31 Minor)
		('InstanceID', 		uint32_t),  	# 0x4C
		('Flags', 			uint32_t),  	# 0x50 Used at CSE_Ext_16 as well, remember to change both!
		('Reserved', 		uint32_t*4),  	# 0x54
		('Unknown', 		uint32_t),  	# 0x64 Unknown (>= 11.6.0.1109, 1 CSSPS, 3 CSME)
		# 0x68
	]
	
	# Used at $FPT size calculation as well, remember to change in case of new Extension Revision!
	
	# PartitionSize & Hash are valid for RGN firmware only with stock $CPD & Data, no FIT/OEM configurations. The latter, usually oem.key and fitc.cfg,
	# are added at the end of the PartitionSize so FIT adjusts $CPD and appends customization files accordingly. Thus, PartitionSize and Hash fields
	# must not be verified at FIT/OEM-customized images because they're not applicable anymore.
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9 = self.get_flags()
		
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 3, Partition Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Partition Size', '0x%X' % self.PartitionSize])
		pt.add_row(['Partition Hash', '%s' % Hash])
		pt.add_row(['Version Control Number', '%d' % self.VCN])
		pt.add_row(['Partition Version', '0x%X' % self.PartitionVer])
		pt.add_row(['Data Format Version', '%d.%d' % (self.DataFormatMajor, self.DataFormatMinor)])
		pt.add_row(['Instance ID', '0x%0.8X' % self.InstanceID])
		pt.add_row(['Support Multiple Instances', fvalue[f1]])
		pt.add_row(['Support API Version Based Update', fvalue[f2]])
		pt.add_row(['Action On Update', '0x%X' % f3])
		pt.add_row(['Obey Full Update Rules', fvalue[f4]])
		pt.add_row(['IFR Enable Only', fvalue[f5]])
		pt.add_row(['Allow Cross Point Update', fvalue[f6]])
		pt.add_row(['Allow Cross Hotfix Update', fvalue[f7]])
		pt.add_row(['Partial Update Only', fvalue[f8]])
		pt.add_row(['Flags Reserved', '0x%X' % f9])
		pt.add_row(['Reserved', '0x%s' % Reserved])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Ext_03_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.SupportMultipleInstances, flags.b.SupportApiVersionBasedUpdate, flags.b.ActionOnUpdate, flags.b.ObeyFullUpdateRules,\
		       flags.b.IfrEnableOnly, flags.b.AllowCrossPointUpdate, flags.b.AllowCrossHotfixUpdate, flags.b.PartialUpdateOnly, flags.b.Reserved
	
class CSE_Ext_03_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('SupportMultipleInstances', uint32_t, 1), # For independently updated WCOD/LOCL partitions with multiple instances
		('SupportApiVersionBasedUpdate', uint32_t, 1),
		('ActionOnUpdate', uint32_t, 2),
		('ObeyFullUpdateRules', uint32_t, 1),
		('IfrEnableOnly', uint32_t, 1),
		('AllowCrossPointUpdate', uint32_t, 1),
		('AllowCrossHotfixUpdate', uint32_t, 1),
		('PartialUpdateOnly', uint32_t, 1),
		('Reserved', uint32_t, 23)
	]

class CSE_Ext_03_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_03_Flags),
		('asbytes', uint32_t)
	]

# noinspection PyTypeChecker
class CSE_Ext_03_Mod(ctypes.LittleEndianStructure) : # R1 - Module Information (MANIFEST_MODULE_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("Type",			uint8_t),		# 0x0C (MODULE_TYPES) (0 Process, 1 Shared Library, 2 Data, 3 OEM/IUP)
		("Compression",		uint8_t),		# 0x0D (0 Uncompressed --> always, 1 Huffman, 2 LZMA)
		("Reserved",		uint16_t),		# 0x0E FFFF
		("MetadataSize",	uint32_t),		# 0x10
		("MetadataHash",	uint32_t*8),	# 0x14
		# 0x34
	]
	
	def ext_print(self) :
		MetadataHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MetadataHash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 3, Module Information' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', ['Process','Shared Library','Data','OEM/IUP'][self.Type]])
		pt.add_row(['Compression', ['Uncompressed','Huffman','LZMA'][self.Compression]])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt

class CSE_Ext_04(ctypes.LittleEndianStructure) : # R1 - Shared Library Attributes (SHARED_LIB_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("ContextSize",		uint32_t),		# 0x08
		("TotAlocVirtSpc",	uint32_t),		# 0x0C
		("CodeBaseAddress",	uint32_t),		# 0x10
		("TLSSize",			uint32_t),		# 0x14
		("Reserved",		uint32_t),		# 0x18
		# 0x1C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 4, Shared Library Attributes' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Context Size', '0x%X' % self.ContextSize])
		pt.add_row(['Total Allocated Virtual Space', '0x%X' % self.TotAlocVirtSpc])
		pt.add_row(['Code Base Address', '0x%X' % self.CodeBaseAddress])
		pt.add_row(['TLS Size', '0x%X' % self.TLSSize])
		pt.add_row(['Reserved', '0x0' if self.Reserved == 0 else '0x%X' % self.Reserved])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_05(ctypes.LittleEndianStructure) : # R1 - Process Attributes (MAN_PROCESS_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Flags",			uint32_t),		# 0x08
		("MainThreadID",	uint32_t),		# 0x0C
		("CodeBaseAddress",	uint32_t),		# 0x10
		("CodeSizeUncomp",	uint32_t),		# 0x14
		("CM0HeapSize",		uint32_t),		# 0x18
		("BSSSize",			uint32_t),		# 0x1C
		("DefaultHeapSize",	uint32_t),		# 0x20
		("MainThreadEntry",	uint32_t),		# 0x24
		("AllowedSysCalls",	uint32_t*3),	# 0x28
		("UserID",			uint16_t),		# 0x34
		("Reserved0",		uint32_t),		# 0x36
		("Reserved1",		uint16_t),		# 0x3A
		("Reserved2",		uint64_t),		# 0x3C
		("GroupID",			uint16_t),	    # 0x44
		# 0x46
	]
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1value = ['Reset System','Terminate Process']
		f1,f2,f3,f4,f5,f6,f7,f8 = self.get_flags()
		AllowedSysCalls = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.AllowedSysCalls))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 5, Process Attributes' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Fault Tolerant', f1value[f1]])
		pt.add_row(['Permanent Process', fvalue[f2]])
		pt.add_row(['Single Instance', fvalue[f3]])
		pt.add_row(['Trusted SendReceive Sender', fvalue[f4]])
		pt.add_row(['Trusted Notify Sender', fvalue[f5]])
		pt.add_row(['Public SendReceive Receiver', fvalue[f6]])
		pt.add_row(['Public Notify Receiver', fvalue[f7]])
		pt.add_row(['Reserved', '0x%X' % f8])
		pt.add_row(['Main Thread ID', '0x%0.8X' % self.MainThreadID])
		pt.add_row(['Code Base Address', '0x%X' % self.CodeBaseAddress])
		pt.add_row(['Code Size Uncompressed', '0x%X' % self.CodeSizeUncomp])
		pt.add_row(['CM0 Heap Size', '0x%X' % self.CM0HeapSize])
		pt.add_row(['BSS Size', '0x%X' % self.BSSSize])
		pt.add_row(['Default Heap Size', '0x%X' % self.DefaultHeapSize])
		pt.add_row(['Main Thread Entry', '0x%X' % self.MainThreadEntry])
		pt.add_row(['Allowed System Calls', AllowedSysCalls])
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['Reserved 2', '0x%X' % self.Reserved2])
		pt.add_row(['Group ID', '0x%0.4X' % self.GroupID])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Ext_05_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.FaultTolerant, flags.b.PermanentProcess, flags.b.SingleInstance, flags.b.TrustedSendReceiveSender,\
		       flags.b.TrustedNotifySender, flags.b.PublicSendReceiveReceiver, flags.b.PublicNotifyReceiver, flags.b.Reserved

class CSE_Ext_05_Mod(ctypes.LittleEndianStructure) : # R1 - Group ID (PROCESS_GROUP_ID)
	_pack_ = 1
	_fields_ = [
		('GroupID',			uint16_t),		# 0x00
		# 0x02
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 5, Group ID' + col_e
		pt.add_row(['Data', '0x%0.4X' % self.GroupID])
		
		return pt			   

class CSE_Ext_05_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('FaultTolerant', uint32_t, 1), # (EXCEPTION_HANDLE_TYPES)
		('PermanentProcess', uint32_t, 1),
		('SingleInstance', uint32_t, 1),
		('TrustedSendReceiveSender', uint32_t, 1),
		('TrustedNotifySender', uint32_t, 1),
		('PublicSendReceiveReceiver', uint32_t, 1),
		('PublicNotifyReceiver', uint32_t, 1),
		('Reserved', uint32_t, 25)
	]

class CSE_Ext_05_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_05_Flags),
		('asbytes', uint32_t)
	]

class CSE_Ext_06(ctypes.LittleEndianStructure) : # R1 - Thread Attributes (Threads)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 6, Thread Attributes' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_06_Mod(ctypes.LittleEndianStructure) : # R1 - (Thread)
	_pack_ = 1
	_fields_ = [
		("StackSize",		uint32_t),		# 0x00
		("Flags",			uint32_t),		# 0x04
		("SchedulPolicy",	uint32_t),		# 0x08
		("Reserved",		uint32_t),		# 0x0C
		# 0x10
	]
	
	def ext_print(self) :
		f1value = ['Live','CM0 UMA Only']
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 6, Thread' + col_e
		pt.add_row(['Stack Size', '0x%X' % self.StackSize])
		pt.add_row(['Flags Type', f1value[f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Scheduling Policy Fixed Priority', fvalue[f3]])
		pt.add_row(['Scheduling Policy Reserved', '0x%X' % f4])
		pt.add_row(['Scheduling Attributes/Priority', '0x%X' % f5])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
	def get_flags(self) :
		f_flags = CSE_Ext_06_GetFlags()
		s_flags = CSE_Ext_06_GetSchedulPolicy()
		f_flags.asbytes = self.Flags
		s_flags.asbytes = self.SchedulPolicy
		
		return f_flags.b.FlagsType, f_flags.b.FlagsReserved, s_flags.b.PolicyFixedPriority, s_flags.b.PolicyReserved,\
		       s_flags.b.AttributesORPriority
	
class CSE_Ext_06_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('FlagsType', uint32_t, 1),
		('FlagsReserved', uint32_t, 31)
	]

class CSE_Ext_06_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_06_Flags),
		('asbytes', uint32_t)
	]
	
class CSE_Ext_06_SchedulPolicy(ctypes.LittleEndianStructure):
	_fields_ = [
		('PolicyFixedPriority', uint32_t, 1),
		('PolicyReserved', uint32_t, 6),
		('AttributesORPriority', uint32_t, 25)
	]
	
class CSE_Ext_06_GetSchedulPolicy(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_06_SchedulPolicy),
		('asbytes', uint32_t)
	]

class CSE_Ext_07(ctypes.LittleEndianStructure) : # R1 - Device Types (DeviceIds)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 7, Device Types' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_07_Mod(ctypes.LittleEndianStructure) : # R1 - (Device)
	_pack_ = 1
	_fields_ = [
		("DeviceID",		uint32_t),		# 0x00
		("Reserved",		uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 7, Device' + col_e
		pt.add_row(['Device ID', '0x%0.8X' % self.DeviceID])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt

class CSE_Ext_08(ctypes.LittleEndianStructure) : # R1 - MMIO Ranges (MmioRanges)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x8
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 8, MMIO Ranges' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_08_Mod(ctypes.LittleEndianStructure) : # R1 - (MmioRange)
	_pack_ = 1
	_fields_ = [
		("BaseAddress",		uint32_t),		# 0x00
		("SizeLimit",		uint32_t),		# 0x04
		("Flags",			uint32_t),		# 0x08 (MmioAccess)
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 8, MMIO Range' + col_e
		pt.add_row(['Base Address', '0x%X' % self.BaseAddress])
		pt.add_row(['Size Limit', '0x%X' % self.SizeLimit])
		pt.add_row(['Access', '%s' % ['N/A','Read Only','Write Only','Read & Write'][self.Flags]])
		
		return pt

class CSE_Ext_09(ctypes.LittleEndianStructure) : # R1 - Special File Producer (SPECIAL_FILE_PRODUCER_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("MajorNumber",		uint16_t),		# 0x08
		("Flags",			uint16_t),		# 0x0A (Unknown/Unused)
		# 0x0C
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 9, Special File Producer' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Major Number', '%d' % self.MajorNumber])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_09_Mod(ctypes.LittleEndianStructure) : # R1 - (SPECIAL_FILE_DEF)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("AccessMode",		uint16_t),		# 0x0C
		("UserID",			uint16_t),		# 0x0E
		("GroupID",			uint16_t),		# 0x10
		("MinorNumber",		uint8_t),		# 0x12
		("Reserved0",		uint8_t),		# 0x13
		("Reserved1",		uint32_t),		# 0x14
		# 0x18
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 9, Special File Definition' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Access Mode', '0x%X' % self.AccessMode])
		pt.add_row(['User ID', '0x%X' % self.UserID])
		pt.add_row(['Group ID', '0x%X' % self.GroupID])
		pt.add_row(['Minor Number', '%d' % self.MinorNumber])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_0A(ctypes.LittleEndianStructure) : # R1 - Module Attributes (MOD_ATTR_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Compression",		uint8_t),		# 0x08 0 Uncompressed, 1 Huffman, 2 LZMA
		("Encryption",		uint8_t),		# 0x09 0 No, 1 Yes, unknown if LE MSB or entire Byte
		("Reserved0",		uint8_t),		# 0x0A
		("Reserved1",		uint8_t),		# 0x0B
		("SizeUncomp",		uint32_t),		# 0x0C
		("SizeComp",		uint32_t),		# 0x10 LZMA & Huffman w/o EOM alignment
		("DEV_ID",			uint16_t),		# 0x14
		("VEN_ID",			uint16_t),		# 0x16 0x8086
		("Hash",			uint32_t*8),	# 0x18 SHA-256 (Compressed for LZMA, Uncompressed for Huffman)
		# 0x38
	]
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 10, Module Attributes' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Compression', ['Uncompressed','Huffman','LZMA'][self.Compression]])
		pt.add_row(['Encryption', ['No','Yes'][self.Encryption]])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['Device ID', '0x%0.4X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%0.4X' % self.VEN_ID])
		pt.add_row(['Hash', Hash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_0A_R2(ctypes.LittleEndianStructure) : # R2 - Module Attributes (MOD_ATTR_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Compression',		uint8_t),		# 0x08 0 Uncompressed, 1 Huffman, 2 LZMA
		('Encryption',		uint8_t),		# 0x09 0 No, 1 Yes, unknown if LE MSB or entire Byte
		('Reserved0',		uint8_t),		# 0x0A
		('Reserved1',		uint8_t),		# 0x0B
		('SizeUncomp',		uint32_t),		# 0x0C
		('SizeComp',		uint32_t),		# 0x10 LZMA & Huffman w/o EOM alignment
		('DEV_ID',			uint16_t),		# 0x14
		('VEN_ID',			uint16_t),		# 0x16 0x8086
		('Hash',			uint32_t*12),	# 0x18 SHA-384 (Compressed for LZMA, Uncompressed for Huffman)
		# 0x48
	]
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 10, Module Attributes' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Compression', ['Uncompressed','Huffman','LZMA'][self.Compression]])
		pt.add_row(['Encryption', ['No','Yes'][self.Encryption]])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Size Compressed', '0x%X' % self.SizeComp])
		pt.add_row(['Device ID', '0x%0.4X' % self.DEV_ID])
		pt.add_row(['Vendor ID', '0x%0.4X' % self.VEN_ID])
		pt.add_row(['Hash', Hash])
		
		return pt

class CSE_Ext_0B(ctypes.LittleEndianStructure) : # R1 - Locked Ranges (LockedRanges)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 11, Locked Ranges' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

class CSE_Ext_0B_Mod(ctypes.LittleEndianStructure) : # R1 - (LockedRange)
	_pack_ = 1
	_fields_ = [
		("RangeBase",		uint32_t),		# 0x00
		("RangeSize",		uint32_t),		# 0x04
		# 0x08
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 11, Locked Range' + col_e
		pt.add_row(['Range Base', '0x%X' % self.RangeBase])
		pt.add_row(['Range Size', '0x%X' % self.RangeSize])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_0C(ctypes.LittleEndianStructure) : # R1 - Client System Information (CLIENT_SYSTEM_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("FWSKUCaps",		uint32_t),		# 0x08 (System Tools User Guide > NVAR > OEMSkuRule)
		("FWSKUCapsReserv",	uint32_t*7),	# 0x0C
		("FWSKUAttrib",		uint64_t),		# 0x28
		# 0x30
	]
	
	def __init__(self, variant, major, minor, hotfix, build, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.variant = variant
		self.major = major
		self.minor = minor
		self.hotfix = hotfix
		self.build = build
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8 = self.get_flags()
		
		FWSKUCapsReserv = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.FWSKUCapsReserv))
		
		if [self.variant,self.major,self.minor,self.hotfix] == ['CSME',11,0,0] and (self.build < 1205 or self.build == 7101) :
			sku = ['N/A','N/A','Reserved','Reserved']
		else :
			sku = ['H','LP','N','Reserved']
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 12, Client System Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['SKU Capabilities', '0x%0.8X' % self.FWSKUCaps])
		pt.add_row(['SKU Capabilities Reserved', 'FF * 28' if FWSKUCapsReserv == 'FF' * 28 else FWSKUCapsReserv])
		pt.add_row(['CSE Size', '0x%X' % f1])
		pt.add_row(['SKU Type', ['Corporate','Consumer','Slim','Server'][f2]])
		pt.add_row(['Lewisburg', fvalue[f3]])
		pt.add_row(['M3', fvalue[f4]])
		pt.add_row(['M0', fvalue[f5]])
		pt.add_row(['SKU Platform', sku[f6]])
		pt.add_row(['Si Class', '%d' % f7])
		pt.add_row(['Reserved', '0x0' if f8 == 0 else '0x%X' % f8])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_0C_GetFWSKUAttrib()
		flags.asbytes = self.FWSKUAttrib
		
		return flags.b.CSESize, flags.b.SKUType, flags.b.Lewisburg, flags.b.M3, flags.b.M0,\
		       flags.b.SKUPlatform, flags.b.SiClass, flags.b.Reserved
	
class CSE_Ext_0C_FWSKUAttrib(ctypes.LittleEndianStructure):
	_fields_ = [
		('CSESize', uint64_t, 4), # CSESize * 0.5MB, always 0
		('SKUType', uint64_t, 3), # 0 COR, 1 CON, 2 SLM, 3 SVR (?)
		('Lewisburg', uint64_t, 1), # 0 11.x, 1 11.20
		('M3', uint64_t, 1), # 0 CON & SLM, 1 COR
		('M0', uint64_t, 1), # 1 CON & SLM & COR
		('SKUPlatform', uint64_t, 2), # 0 H/LP <= 11.0.0.1202, 0 H >= 11.0.0.1205, 1 LP >= 11.0.0.1205, 2 N
		('SiClass', uint64_t, 4), # 2 CON & SLM, 4 COR (not sure if bitmap or decimal)
		('Reserved', uint64_t, 50) # 0
	]

class CSE_Ext_0C_GetFWSKUAttrib(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_0C_FWSKUAttrib),
		('asbytes', uint64_t)
	]

class CSE_Ext_0D(ctypes.LittleEndianStructure) : # R1 - User Information (USER_INFO_EXTENSION)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		# 0x8
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 13, User Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_0D_Mod(ctypes.LittleEndianStructure) : # R1 - (USER_INFO_ENTRY)
	_pack_ = 1
	_fields_ = [
		("UserID",			uint16_t),		# 0x00
		("Reserved",		uint16_t),		# 0x02
		("NVStorageQuota",	uint32_t),		# 0x04
		("RAMStorageQuota",	uint32_t),		# 0x08
		("WOPQuota",		uint32_t),		# 0x0C (Wear-out Prevention)
		("WorkingDir",		char*36),		# 0x10
		# 0x34
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 13, Entry' + col_e
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['NV Storage Quota', '0x%X' % self.NVStorageQuota])
		pt.add_row(['RAM Storage Quota', '0x%X' % self.RAMStorageQuota])
		pt.add_row(['WOP Quota', '0x%X' % self.WOPQuota])
		pt.add_row(['Working Directory', self.WorkingDir.decode('utf-8')])
		
		return pt

class CSE_Ext_0D_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("UserID",			uint16_t),		# 0x00
		("Reserved",		uint16_t),		# 0x02
		("NVStorageQuota",	uint32_t),		# 0x04
		("RAMStorageQuota",	uint32_t),		# 0x08
		("WOPQuota",		uint32_t),		# 0x0C (Wear-out Prevention)
		# 0x10
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 13, Entry' + col_e
		pt.add_row(['User ID', '0x%0.4X' % self.UserID])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		pt.add_row(['NV Storage Quota', '0x%X' % self.NVStorageQuota])
		pt.add_row(['RAM Storage Quota', '0x%X' % self.RAMStorageQuota])
		pt.add_row(['WOP Quota', '0x%X' % self.WOPQuota])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_0E(ctypes.LittleEndianStructure) : # R1 - Key Manifest (KEY_MANIFEST_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("KeyType",			uint32_t),		# 0x08 1 RoT, 2 OEM (KeyManifestTypeValues)
		("KeySVN",			uint32_t),		# 0x0C
		("OEMID",			uint16_t),		# 0x10
		("KeyID",			uint8_t),		# 0x12 Matched against Field Programmable Fuse (FPF)
		("Reserved0",		uint8_t),		# 0x13
		("Reserved1",		uint32_t*4),	# 0x14
		# 0x24
	]
	
	def ext_print(self) :
		Reserved1 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved1))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 14, Key Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Key Type', ['Unknown','RoT','OEM'][self.KeyType]])
		pt.add_row(['Key SVN', '%d' % self.KeySVN])
		pt.add_row(['OEM ID', '0x%0.4X' % self.OEMID])
		pt.add_row(['Key ID', '0x%0.2X' % self.KeyID])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x0' if Reserved1 == '00000000' * 4 else Reserved1])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_0E_Mod(ctypes.LittleEndianStructure) : # R1 - (KEY_MANIFEST_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		("UsageBitmap",		uint8_t*16),	# 0x00 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		("Reserved0",		uint32_t*4),	# 0x10
		("Flags",			uint8_t),		# 0x20
		("HashAlgorithm",	uint8_t),		# 0x21
		("HashSize",		uint16_t),		# 0x22
		("Hash",			uint32_t*8),	# 0x24 SHA-256 (Big Endian, PKEY + EXP)
		# 0x44
	]
	
	def ext_print(self) :
		f1,f2 = self.get_flags()
		hash_usages = self.get_usages()
		
		Reserved0 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved0))
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 14, Entry' + col_e
		pt.add_row(['Hash Usages', ', '.join(map(str, hash_usages))])
		pt.add_row(['Reserved 0', '0x0' if Reserved0 == '00000000' * 4 else Reserved0])
		pt.add_row(['IPI Policy', ['OEM or Intel','Intel Only'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Hash Algorithm', ['Reserved','SHA-1','SHA-256'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Public Key & Exponent Hash', Hash])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_0E_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.IPIPolicy, flags.b.Reserved
	
	# Identical code at CSE_Ext_0F
	def get_usages(self) :
		hash_usages = []
		
		usage_bits = list(format(int.from_bytes(self.UsageBitmap, 'little'), '0128b'))
		usage_bits.reverse()
		
		for usage_bit in range(len(usage_bits)) :
			if usage_bits[usage_bit] == '1' :
				hash_usages.append(key_dict[usage_bit] if usage_bit in key_dict else 'Unknown')
				
		return hash_usages
		
# noinspection PyTypeChecker
class CSE_Ext_0E_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (KEY_MANIFEST_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		("UsageBitmap",		uint8_t*16),	# 0x00 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		("Reserved0",		uint32_t*4),	# 0x10
		("Flags",			uint8_t),		# 0x20
		("HashAlgorithm",	uint8_t),		# 0x21
		("HashSize",		uint16_t),		# 0x22
		("Hash",			uint32_t*12),	# 0x24 SHA-384 (Big Endian, PKEY + EXP)
		# 0x54
	]
	
	def ext_print(self) :
		f1,f2 = self.get_flags()
		hash_usages = self.get_usages()
		
		Reserved0 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved0))
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 14, Entry' + col_e
		pt.add_row(['Hash Usages', ', '.join(map(str, hash_usages))])
		pt.add_row(['Reserved 0', '0x0' if Reserved0 == '00000000' * 4 else Reserved0])
		pt.add_row(['IPI Policy', ['OEM or Intel','Intel Only'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Hash Algorithm', ['Reserved','SHA-1','SHA-256','SHA-384'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Public Key & Exponent Hash', Hash])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_0E_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.IPIPolicy, flags.b.Reserved
	
	# Identical code at CSE_Ext_0F
	def get_usages(self) :
		hash_usages = []
		
		usage_bits = list(format(int.from_bytes(self.UsageBitmap, 'little'), '0128b'))
		usage_bits.reverse()
		
		for usage_bit in range(len(usage_bits)) :
			if usage_bits[usage_bit] == '1' :
				hash_usages.append(key_dict[usage_bit] if usage_bit in key_dict else 'Unknown')
				
		return hash_usages
	
class CSE_Ext_0E_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('IPIPolicy', uint8_t, 1), # RoT (Root of Trust) Key Manifest
		('Reserved', uint8_t, 7)
	]

class CSE_Ext_0E_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_0E_Flags),
		('asbytes', uint8_t)
	]

# noinspection PyTypeChecker
class CSE_Ext_0F(ctypes.LittleEndianStructure) : # R1 - Signed Package Information (SIGNED_PACKAGE_INFO_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("PartitionName",	char*4),		# 0x08
		("VCN",				uint32_t),		# 0x0C Version Control Number
		("UsageBitmap",		uint8_t*16),	# 0x10 (KeyManifestHashUsages, OemKeyManifestHashUsages)
		("ARBSVN",			uint32_t),		# 0x20 FPF Anti-Rollback (ARB) Security Version Number
		("Reserved",		uint32_t*4),  	# 0x24
		# 0x34
	]
	
	def ext_print(self) :
		hash_usages = self.get_usages()
		
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Signed Package Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Version Control Number', '%d' % self.VCN])
		pt.add_row(['Hash Usages', ', '.join(map(str, hash_usages))])
		pt.add_row(['ARB Security Version Number', '%d' % self.ARBSVN])
		pt.add_row(['Reserved', Reserved])
		
		return pt
	
	# Identical code at CSE_Ext_0E_Mod & CSE_Ext_0E_Mod_R2
	def get_usages(self) :
		hash_usages = []
		
		usage_bits = list(format(int.from_bytes(self.UsageBitmap, 'little'), '0128b'))
		usage_bits.reverse()
		
		for usage_bit in range(len(usage_bits)) :
			if usage_bits[usage_bit] == '1' :
				hash_usages.append(key_dict[usage_bit] if usage_bit in key_dict else 'Unknown')
				
		return hash_usages

# noinspection PyTypeChecker
class CSE_Ext_0F_Mod(ctypes.LittleEndianStructure) : # R1 - (SIGNED_PACKAGE_INFO_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		("Name",			char*12),		# 0x00
		("Type",			uint8_t),		# 0x0C (MODULE_TYPES) (0 Process, 1 Shared Library, 2 Data, 3 OEM/IUP)
		("HashAlgorithm",	uint8_t),		# 0x0D (0 Reserved, 1 SHA-1, 2 SHA-256)
		("HashSize",		uint16_t),		# 0x0E
		("MetadataSize",	uint32_t),		# 0x10
		("MetadataHash",	uint32_t*8),	# 0x14 SHA-256
		# 0x34
	]
	
	def ext_print(self) :
		MetadataHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MetadataHash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', ['Process','Shared Library','Data','OEM/IUP'][self.Type]])
		pt.add_row(['Hash Algorithm', ['Reserved','SHA-1','SHA-256'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_0F_Mod_R2(ctypes.LittleEndianStructure) : # R2 - (SIGNED_PACKAGE_INFO_EXT_ENTRY, STRONG_SIGNED_PACKAGE_INFO_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		('Name',			char*12),		# 0x00
		('Type',			uint8_t),		# 0x0C (MODULE_TYPES) (0 Process, 1 Shared Library, 2 Data, 3 OEM/IUP)
		('HashAlgorithm',	uint8_t),		# 0x0D (0 Reserved, 1 SHA-1, 2 SHA-256, 3 SHA-384)
		('HashSize',		uint16_t),		# 0x0E
		('MetadataSize',	uint32_t),		# 0x10
		('MetadataHash',	uint32_t*12),	# 0x14 SHA-384
		# 0x44
	]
	
	def ext_print(self) :
		MetadataHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MetadataHash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', ['Process','Shared Library','Data','OEM/IUP'][self.Type]])
		pt.add_row(['Hash Algorithm', ['Reserved','SHA-1','SHA-256','SHA-384'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_0F_Mod_R3(ctypes.LittleEndianStructure) : # R3 - (SIGNED_PACKAGE_INFO_EXT_ENTRY, STRONG_SIGNED_PACKAGE_INFO_EXT_ENTRY)
	_pack_ = 1
	_fields_ = [
		('Name',			char*12),		# 0x00
		('Type',			uint8_t),		# 0x0C (MODULE_TYPES) (0 Process, 1 Shared Library, 2 Data, 3 OEM/IUP)
		('SVN',				uint8_t),		# 0x0D
		('HashSize',		uint16_t),		# 0x0E
		('MetadataSize',	uint32_t),		# 0x10
		('MetadataHash',	uint32_t*12),	# 0x14 SHA-384
		# 0x44
	]
	
	def ext_print(self) :
		MetadataHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MetadataHash))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 15, Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Type', ['Process','Shared Library','Data','OEM/IUP'][self.Type]])
		pt.add_row(['Security Version Number', self.SVN])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
		pt.add_row(['Metadata Hash', MetadataHash])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_10(ctypes.LittleEndianStructure) : # R1 - Anti-Cloning SKU ID (iUnit/IUNP, not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Revision',		uint32_t),		# 0x08
		('Reserved',		uint32_t*4),	# 0x0C
		# 0x1C
	]
	
	def ext_print(self) :
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 16, Anti-Cloning SKU ID' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Revision', '%d' % self.Revision])
		pt.add_row(['Reserved', '0x0' if Reserved == '00000000' * 4 else Reserved])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_10_Mod(ctypes.LittleEndianStructure) : # R1 - Anti-Cloning SKU ID Chunk (iUnit/IUNP, not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Chunk',			uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Day',				uint8_t),		# 0x08
		('Month',			uint8_t),		# 0x09
		('Year',			uint16_t),		# 0x0A
		('Hash',			uint32_t*8),	# 0x0C SHA-256 Big Endian
		('Unknown0',		uint32_t),		# 0x2C
		('Unknown1',		uint32_t),		# 0x30 Base Address ?
		('Reserved',		uint32_t*4),	# 0x34
		# 0x44
	]
	
	def ext_print(self) :
		Date = '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 16, Anti-Cloning SKU ID Chunk' + col_e
		pt.add_row(['Number', '%d' % self.Chunk])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Date', Date])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Reserved', '0x0' if Reserved == '00000000' * 4 else Reserved])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_10_Mod_R2(ctypes.LittleEndianStructure) : # R2 - Anti-Cloning SKU ID Chunk (iUnit/IUNP, not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Chunk',			uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Day',				uint8_t),		# 0x08
		('Month',			uint8_t),		# 0x09
		('Year',			uint16_t),		# 0x0A
		('Hash',			uint32_t*12),	# 0x0C SHA-384 Big Endian
		('Unknown0',		uint32_t),		# 0x3C
		('Unknown1',		uint32_t),		# 0x40 Base Address ?
		('Reserved',		uint32_t*4),	# 0x44
		# 0x54
	]
	
	def ext_print(self) :
		Date = '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 16, Anti-Cloning SKU ID Chunk' + col_e
		pt.add_row(['Number', '%d' % self.Chunk])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Date', Date])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Reserved', '0x0' if Reserved == '00000000' * 4 else Reserved])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_11(ctypes.LittleEndianStructure) : # R1 - cAVS (ADSP, not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Unknown",			uint32_t),		# 0x08 3
		("Reserved0",		uint32_t*7),	# 0x0C
		("Hash",			uint32_t*8),	# 0x28 SHA-256 Big Endian
		("SizeUnknown",		uint32_t),		# 0x48 Maybe cache size?
		("SizeUncomp",		uint32_t),		# 0x4C SizeUncomp - SizeUnknown = Actual ($CPD) Size
		("Reserved1",		uint32_t*4),	# 0x50
		# 0x60
	]
	
	def ext_print(self) :
		Reserved0 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved0))
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		Reserved1 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved1))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 17, Clear Audio Voice Speech (aDSP)' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		pt.add_row(['Reserved 0', '0x0' if Reserved0 == '00000000' * 7 else Reserved0])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Size Unknown', '0x%X' % self.SizeUnknown])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Reserved 1', '0x0' if Reserved1 == '00000000' * 4 else Reserved1])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_11_R2(ctypes.LittleEndianStructure) : # R2 - cAVS (ADSP, not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Unknown",			uint32_t),		# 0x08 3
		("Reserved0",		uint32_t*7),	# 0x0C
		("Hash",			uint32_t*12),	# 0x28 SHA-384 Big Endian
		("SizeUnknown",		uint32_t),		# 0x58 Maybe cache size?
		("SizeUncomp",		uint32_t),		# 0x5C SizeUncomp - SizeUnknown = Actual ($CPD) Size
		("Reserved1",		uint32_t*4),	# 0x60
		# 0x70
	]
	
	def ext_print(self) :
		Reserved0 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved0))
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		Reserved1 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved1))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 17, Clear Audio Voice Speech (aDSP)' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		pt.add_row(['Reserved 0', '0x0' if Reserved0 == '00000000' * 7 else Reserved0])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Size Unknown', '0x%X' % self.SizeUnknown])
		pt.add_row(['Size Uncompressed', '0x%X' % self.SizeUncomp])
		pt.add_row(['Reserved 1', '0x0' if Reserved1 == '00000000' * 4 else Reserved1])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_12(ctypes.LittleEndianStructure) : # R1 - Isolated Memory Region Information (FTPR, not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("ModuleCount",		uint32_t),		# 0x08 Region Count
		("Reserved",		uint32_t*4),	# 0x0C
		# 0x1C
	]
	
	def ext_print(self) :
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 18, Isolated Memory Region Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Module Count', '%d' % self.ModuleCount])
		pt.add_row(['Reserved', '0x0' if Reserved == '00000000' * 4 else Reserved])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_12_Mod(ctypes.LittleEndianStructure) : # R1 - (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("Unknown00_04",	uint32_t),		# 0x00
		("Unknown04_08",	uint32_t),		# 0x04
		("Unknown08_0C",	uint32_t),		# 0x08
		("Unknown0C_10",	uint32_t),		# 0x0C
		("Unknown10_18",	uint32_t*2),	# 0x10 FFFFFFFFFFFFFFFF
		("Unknown18_1C",	uint32_t),		# 0x18
		("Unknown1C_20",	uint32_t),		# 0x1C
		("Unknown20_28",	uint32_t*2),	# 0x20 FFFFFFFFFFFFFFFF
		("Unknown28_2C",	uint32_t),		# 0x28
		("Unknown2C_30",	uint32_t),		# 0x2C
		("Unknown30_38",	uint32_t*2),	# 0x30 FFFFFFFFFFFFFFFF
		# 0x38
	]
	
	def ext_print(self) :
		Unknown10_18 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown10_18))
		Unknown20_28 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown20_28))
		Unknown30_38 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown30_38))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 18, Isolated Memory Region' + col_e
		pt.add_row(['Unknown 00_04', '0x%X' % self.Unknown00_04])
		pt.add_row(['Unknown 04_08', '0x%X' % self.Unknown04_08])
		pt.add_row(['Unknown 08_0C', '0x%X' % self.Unknown08_0C])
		pt.add_row(['Unknown 0C_10', '0x%X' % self.Unknown0C_10])
		pt.add_row(['Unknown 10_18', '0xFF * 8' if Unknown10_18 == 'FFFFFFFF' * 2 else Unknown10_18])
		pt.add_row(['Unknown 18_1C', '0x%X' % self.Unknown18_1C])
		pt.add_row(['Unknown 1C_20', '0x%X' % self.Unknown1C_20])
		pt.add_row(['Unknown 20_28', '0xFF * 8' if Unknown20_28 == 'FFFFFFFF' * 2 else Unknown20_28])
		pt.add_row(['Unknown 28_2C', '0x%X' % self.Unknown28_2C])
		pt.add_row(['Unknown 2C_30', '0x%X' % self.Unknown2C_30])
		pt.add_row(['Unknown 30_38', '0xFF * 8' if Unknown30_38 == 'FFFFFFFF' * 2 else Unknown30_38])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_13(ctypes.LittleEndianStructure) : # R1 - Boot Policy (BOOT_POLICY_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("IBBNEMSize",		uint32_t),		# 0x08 in 4K pages (NEM: No Evict Mode or CAR: Cache as RAM)
		("IBBLHashAlg",		uint32_t),		# 0x0C 0 Reserved, 1 SHA-1, 2 SHA-256
		("IBBLHashSize",	uint32_t),		# 0x10
		("IBBLHash",		uint32_t*8),	# 0x14 Big Endian
		("IBBHashAlg",		uint32_t),		# 0x34 0 Reserved, 1 SHA-1, 2 SHA-256
		("IBBHashSize",		uint32_t),		# 0x38
		("IBBHash",			uint32_t*8),	# 0x3C Big Endian
		("OBBHashAlg",		uint32_t),		# 0x5C 0 Reserved, 1 SHA-1, 2 SHA-256
		("OBBHashSize",		uint32_t),		# 0x60
		("OBBHash",			uint32_t*8),	# 0x64 Big Endian
		("IBBFlags",		uint32_t),		# 0x84 Unknown/Unused
		("IBBMCHBar",		uint64_t),		# 0x88
		("IBBVTDBar",		uint64_t),		# 0x90
		("PMRLBase",		uint32_t),		# 0x98
		("PMRLLimit",		uint32_t),		# 0x9C
		("PMRHBase",		uint32_t),		# 0xA0
		("PMRHLimit",		uint32_t),		# 0xA4
		("IBBEntryPoint",	uint32_t),		# 0xA8
		("IBBSegmentCount",	uint32_t),		# 0xAC
		("VendorAttrSize",	uint32_t),		# 0xB0
		# 0xB4
	]
	
	def ext_print(self) :
		hash_alg = ['Reserved','SHA-1','SHA-256']
		
		IBBLHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.IBBLHash)
		IBBHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.IBBHash)
		OBBHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.OBBHash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 19, Boot Policy' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['No Evict Mode Size', '0x%X' % (self.IBBNEMSize * 4096)])
		pt.add_row(['IBBL Hash Algorithm', hash_alg[self.IBBLHashAlg]])
		pt.add_row(['IBBL Hash Size', '0x%X' % self.IBBLHashSize])
		pt.add_row(['IBBL Hash', IBBLHash])
		pt.add_row(['IBB Hash Algorithm', hash_alg[self.IBBHashAlg]])
		pt.add_row(['IBB Hash Size', '0x%X' % self.IBBHashSize])
		pt.add_row(['IBB Hash', IBBHash])
		pt.add_row(['OBB Hash Algorithm', hash_alg[self.OBBHashAlg]])
		pt.add_row(['OBB Hash Size', '0x%X' % self.OBBHashSize])
		pt.add_row(['OBB Hash', OBBHash])
		pt.add_row(['IBB Flags', '0x%X' % self.IBBFlags])
		pt.add_row(['IBB MCH Bar', '0x%X' % self.IBBMCHBar])
		pt.add_row(['IBB VTD Bar', '0x%X' % self.IBBVTDBar])
		pt.add_row(['PMRL Base', '0x%X' % self.PMRLBase])
		pt.add_row(['PMRL Limit', '0x%X' % self.PMRLLimit])
		pt.add_row(['PMRH Base', '0x%X' % self.PMRHBase])
		pt.add_row(['PMRH Limit', '0x%X' % self.PMRHLimit])
		pt.add_row(['IBB Entry Point', '0x%X' % self.IBBEntryPoint])
		pt.add_row(['IBB Segment Count', '%d' % self.IBBSegmentCount])
		pt.add_row(['Vendor Attributes Size', '0x%X' % self.VendorAttrSize])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_13_R2(ctypes.LittleEndianStructure) : # R2 - Boot Policy (BOOT_POLICY_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("IBBNEMSize",		uint32_t),		# 0x08 in 4K pages (NEM: No Evict Mode or CAR: Cache as RAM)
		("IBBLHashAlg",		uint32_t),		# 0x0C 0 Reserved, 1 SHA-1, 2 SHA-256, 3 SHA-384
		("IBBLHashSize",	uint32_t),		# 0x10
		("IBBLHash",		uint32_t*12),	# 0x14 Big Endian
		("IBBHashAlg",		uint32_t),		# 0x44 0 Reserved, 1 SHA-1, 2 SHA-256, 3 SHA-384
		("IBBHashSize",		uint32_t),		# 0x48
		("IBBHash",			uint32_t*12),	# 0x4C Big Endian
		("OBBHashAlg",		uint32_t),		# 0x7C 0 Reserved, 1 SHA-1, 2 SHA-256, 3 SHA-384
		("OBBHashSize",		uint32_t),		# 0x80
		("OBBHash",			uint32_t*12),	# 0x84 Big Endian
		("IBBFlags",		uint32_t),		# 0xB4 Unknown/Unused
		("IBBMCHBar",		uint64_t),		# 0xB8
		("IBBVTDBar",		uint64_t),		# 0xC0
		("PMRLBase",		uint32_t),		# 0xC8
		("PMRLLimit",		uint32_t),		# 0xCC
		("PMRHBase",		uint32_t),		# 0xD0
		("PMRHLimit",		uint32_t),		# 0xD4
		("IBBEntryPoint",	uint32_t),		# 0xD8
		("IBBSegmentCount",	uint32_t),		# 0xDC
		("VendorAttrSize",	uint32_t),		# 0xE0
		# 0xE4
	]
	
	def ext_print(self) :
		hash_alg = ['Reserved','SHA-1','SHA-256','SHA-384']
		
		IBBLHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.IBBLHash)
		IBBHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.IBBHash)
		OBBHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.OBBHash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 19, Boot Policy' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['No Evict Mode Size', '0x%X' % (self.IBBNEMSize * 4096)])
		pt.add_row(['IBBL Hash Algorithm', hash_alg[self.IBBLHashAlg]])
		pt.add_row(['IBBL Hash Size', '0x%X' % self.IBBLHashSize])
		pt.add_row(['IBBL Hash', IBBLHash])
		pt.add_row(['IBB Hash Algorithm', hash_alg[self.IBBHashAlg]])
		pt.add_row(['IBB Hash Size', '0x%X' % self.IBBHashSize])
		pt.add_row(['IBB Hash', IBBHash])
		pt.add_row(['OBB Hash Algorithm', hash_alg[self.OBBHashAlg]])
		pt.add_row(['OBB Hash Size', '0x%X' % self.OBBHashSize])
		pt.add_row(['OBB Hash', OBBHash])
		pt.add_row(['IBB Flags', '0x%X' % self.IBBFlags])
		pt.add_row(['IBB MCH Bar', '0x%X' % self.IBBMCHBar])
		pt.add_row(['IBB VTD Bar', '0x%X' % self.IBBVTDBar])
		pt.add_row(['PMRL Base', '0x%X' % self.PMRLBase])
		pt.add_row(['PMRL Limit', '0x%X' % self.PMRLLimit])
		pt.add_row(['PMRH Base', '0x%X' % self.PMRHBase])
		pt.add_row(['PMRH Limit', '0x%X' % self.PMRHLimit])
		pt.add_row(['IBB Entry Point', '0x%X' % self.IBBEntryPoint])
		pt.add_row(['IBB Segment Count', '%d' % self.IBBSegmentCount])
		pt.add_row(['Vendor Attributes Size', '0x%X' % self.VendorAttrSize])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_14(ctypes.LittleEndianStructure) : # R1 - DnX Manifest (DnxManifestExtension)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Minor",			uint8_t),		# 0x08
		("Major",			uint8_t),		# 0x09
		("Reserved0",		uint8_t),		# 0x0A
		("Reserved1",		uint8_t),		# 0x0B
		("OEMID",			uint16_t),		# 0x0C
		("PlatformID",		uint16_t),		# 0x0E
		("MachineID",		uint32_t*4),	# 0x10
		("SaltID",			uint32_t),		# 0x20
		("PublicKey",		uint32_t*64),	# 0x24
		("PublicExponent",	uint32_t),		# 0x88
		("IFWIRegionCount",	uint32_t),		# 0x8C Number of eMMC/UFS components (LBPs)
		("Flags",			uint32_t),		# 0x90 Unknown/Unused
		("Reserved2",		uint32_t),		# 0x94
		("Reserved3",		uint32_t),		# 0x98
		("Reserved4",		uint32_t),		# 0x9C
		("Reserved5",		uint32_t),		# 0xA0
		("ChunkSize",		uint32_t),		# 0xA4 0x10000 (64KB)
		("ChunkCount",		uint32_t),		# 0xA8
		# 0xAC
	]
	
	def ext_print(self) :
		MachineID = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MachineID))
		PublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.PublicKey))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 20 R1, DnX Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minor', '%d' % self.Minor])
		pt.add_row(['Major', '%d' % self.Major])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['OEM ID', '0x%0.4X' % self.OEMID])
		pt.add_row(['Platform ID', '0x%0.4X' % self.PlatformID])
		pt.add_row(['Machine ID', '0x0' if MachineID == '00000000' * 4 else MachineID])
		pt.add_row(['Salt ID', '0x%0.8X' % self.SaltID])
		pt.add_row(['Public Key', '%s [...]' % PublicKey[:7]])
		pt.add_row(['Public Exponent', '0x%X' % self.PublicExponent])
		pt.add_row(['IFWI Region Count', '%d' % self.IFWIRegionCount])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		pt.add_row(['Reserved 2', '0x%X' % self.Reserved2])
		pt.add_row(['Reserved 3', '0x%X' % self.Reserved3])
		pt.add_row(['Reserved 4', '0x%X' % self.Reserved4])
		pt.add_row(['Reserved 5', '0x%X' % self.Reserved5])
		pt.add_row(['IFWI Chunk Data Size', '0x%X' % self.ChunkSize])
		pt.add_row(['IFWI Chunk Count', '%d' % self.ChunkCount])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_14_R2(ctypes.LittleEndianStructure) : # R2 - DnX Manifest (DnxManifestExtension_ver2)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Minor",			uint8_t),		# 0x08
		("Major",			uint8_t),		# 0x09
		("Reserved0",		uint8_t),		# 0x0A
		("Reserved1",		uint8_t),		# 0x0B
		("OEMID",			uint16_t),		# 0x0C
		("PlatformID",		uint16_t),		# 0x0E
		("MachineID",		uint32_t*4),	# 0x10
		("SaltID",			uint32_t),		# 0x20
		("PublicKey",		uint32_t*64),	# 0x24
		("PublicExponent",	uint32_t),		# 0x124
		("IFWIRegionCount",	uint32_t),		# 0x128 Number of eMMC/UFS components (LBPs)
		("Flags",			uint32_t),		# 0x12C Unknown/Unused
		("Reserved2",		uint8_t),		# 0x12D
		("Reserved3",		uint8_t),		# 0x12E
		("Reserved4",		uint8_t),		# 0x12F
		("Reserved5",		uint8_t),		# 0x130
		("HashArrHdrMajor",	uint8_t),		# 0x131
		("HashArrHdrMinor",	uint8_t),		# 0x132
		("HashArrHdrCount",	uint16_t),		# 0x133
		("Reserved6",		uint8_t),		# 0x135
		("HashArrHashAlg",	uint8_t),		# 0x136 0 Reserved, 1 SHA-1, 2 SHA-256
		("HashArrHashSize",	uint16_t),		# 0x137
		("ChunkHashAlg",	uint8_t),		# 0x139 0 Reserved, 1 SHA-1, 2 SHA-256
		("Reserved7",		uint8_t),		# 0x13A
		("Reserved8",		uint8_t),		# 0x13B
		("Reserved9",		uint8_t),		# 0x13C
		("ChunkHashSize",	uint16_t),		# 0x13D
		("Reserved10",		uint8_t),		# 0x13F
		("Reserved11",		uint8_t),		# 0x140
		("ChunkSize",		uint32_t),		# 0x144 0x10000 (64KB)
		# 0x148
	]
	
	def ext_print(self) :
		hash_alg = ['Reserved','SHA-1','SHA-256']
		
		MachineID = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MachineID))
		PublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.PublicKey))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 20 R2, DnX Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minor', '%d' % self.Minor])
		pt.add_row(['Major', '%d' % self.Major])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['OEM ID', '0x%0.4X' % self.OEMID])
		pt.add_row(['Platform ID', '0x%0.4X' % self.PlatformID])
		pt.add_row(['Machine ID', '0x0' if MachineID == '00000000' * 4 else MachineID])
		pt.add_row(['Salt ID', '0x%0.8X' % self.SaltID])
		pt.add_row(['Public Key', '%s [...]' % PublicKey[:7]])
		pt.add_row(['Public Exponent', '0x%X' % self.PublicExponent])
		pt.add_row(['IFWI Region Count', '%d' % self.IFWIRegionCount])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		pt.add_row(['Reserved 2', '0x%X' % self.Reserved2])
		pt.add_row(['Reserved 3', '0x%X' % self.Reserved3])
		pt.add_row(['Reserved 4', '0x%X' % self.Reserved4])
		pt.add_row(['Reserved 5', '0x%X' % self.Reserved5])
		pt.add_row(['Hashes Array Header Major', '%d' % self.HashArrHdrMajor])
		pt.add_row(['Hashes Array Header Minor', '%d' % self.HashArrHdrMinor])
		pt.add_row(['Hashes Array Header Count', '%d' % self.HashArrHdrCount])
		pt.add_row(['Reserved 6', '0x%X' % self.Reserved6])
		pt.add_row(['Hashes Array Hash Algorithm', hash_alg[self.HashArrHashAlg]])
		pt.add_row(['Hashes Array Hash Size', '0x%X' % self.HashArrHashSize])
		pt.add_row(['IFWI Chunk Hash Algorithm', hash_alg[self.ChunkHashAlg]])
		pt.add_row(['Reserved 7', '0x%X' % self.Reserved7])
		pt.add_row(['Reserved 8', '0x%X' % self.Reserved8])
		pt.add_row(['Reserved 9', '0x%X' % self.Reserved9])
		pt.add_row(['IFWI Chunk Hash Size', '0x%X' % self.ChunkHashSize])
		pt.add_row(['Reserved 10', '0x%X' % self.Reserved10])
		pt.add_row(['Reserved 11', '0x%X' % self.Reserved11])
		pt.add_row(['IFWI Chunk Data Size', '0x%X' % self.ChunkSize])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_14_R3(ctypes.LittleEndianStructure) : # R3 - DnX Manifest (DnxManifestExtension_ver2)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Minor',			uint8_t),		# 0x08
		('Major',			uint8_t),		# 0x09
		('Reserved0',		uint8_t),		# 0x0A
		('Reserved1',		uint8_t),		# 0x0B
		('OEMID',			uint16_t),		# 0x0C
		('PlatformID',		uint16_t),		# 0x0E
		('MachineID',		uint32_t*4),	# 0x10
		('SaltID',			uint32_t),		# 0x20
		('PublicKey',		uint32_t*96),	# 0x24
		('PublicExponent',	uint32_t),		# 0x1A4
		('IFWIRegionCount',	uint32_t),		# 0x1A8 Number of eMMC/UFS components (LBPs)
		('Flags',			uint32_t),		# 0x1AC Unknown/Unused
		('Reserved2',		uint8_t),		# 0x1AD
		('Reserved3',		uint8_t),		# 0x1AE
		('Reserved4',		uint8_t),		# 0x1AF
		('Reserved5',		uint8_t),		# 0x1B0
		('HashArrHdrMajor',	uint8_t),		# 0x1B1
		('HashArrHdrMinor',	uint8_t),		# 0x1B2
		('HashArrHdrCount',	uint16_t),		# 0x1B3
		('Reserved6',		uint8_t),		# 0x1B5
		('HashArrHashAlg',	uint8_t),		# 0x1B6 0 Reserved, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashArrHashSize',	uint16_t),		# 0x1B7
		('ChunkHashAlg',	uint8_t),		# 0x1B9 0 Reserved, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('Reserved7',		uint8_t),		# 0x1BA
		('Reserved8',		uint8_t),		# 0x1BB
		('Reserved9',		uint8_t),		# 0x1BC
		('ChunkHashSize',	uint16_t),		# 0x1BD
		('Reserved10',		uint8_t),		# 0x1BF
		('Reserved11',		uint8_t),		# 0x1C0
		('ChunkSize',		uint32_t),		# 0x1C4 0x10000 (64KB)
		# 0x1C8
	]
	
	def ext_print(self) :
		hash_alg = ['Reserved','SHA-1','SHA-256','SHA-384']
		
		MachineID = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MachineID))
		PublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.PublicKey))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 20 R3, DnX Manifest' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Minor', '%d' % self.Minor])
		pt.add_row(['Major', '%d' % self.Major])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		pt.add_row(['OEM ID', '0x%0.4X' % self.OEMID])
		pt.add_row(['Platform ID', '0x%0.4X' % self.PlatformID])
		pt.add_row(['Machine ID', '0x0' if MachineID == '00000000' * 4 else MachineID])
		pt.add_row(['Salt ID', '0x%0.8X' % self.SaltID])
		pt.add_row(['Public Key', '%s [...]' % PublicKey[:7]])
		pt.add_row(['Public Exponent', '0x%X' % self.PublicExponent])
		pt.add_row(['IFWI Region Count', '%d' % self.IFWIRegionCount])
		pt.add_row(['Flags', '0x%X' % self.Flags])
		pt.add_row(['Reserved 2', '0x%X' % self.Reserved2])
		pt.add_row(['Reserved 3', '0x%X' % self.Reserved3])
		pt.add_row(['Reserved 4', '0x%X' % self.Reserved4])
		pt.add_row(['Reserved 5', '0x%X' % self.Reserved5])
		pt.add_row(['Hashes Array Header Major', '%d' % self.HashArrHdrMajor])
		pt.add_row(['Hashes Array Header Minor', '%d' % self.HashArrHdrMinor])
		pt.add_row(['Hashes Array Header Count', '%d' % self.HashArrHdrCount])
		pt.add_row(['Reserved 6', '0x%X' % self.Reserved6])
		pt.add_row(['Hashes Array Hash Algorithm', hash_alg[self.HashArrHashAlg]])
		pt.add_row(['Hashes Array Hash Size', '0x%X' % self.HashArrHashSize])
		pt.add_row(['IFWI Chunk Hash Algorithm', hash_alg[self.ChunkHashAlg]])
		pt.add_row(['Reserved 7', '0x%X' % self.Reserved7])
		pt.add_row(['Reserved 8', '0x%X' % self.Reserved8])
		pt.add_row(['Reserved 9', '0x%X' % self.Reserved9])
		pt.add_row(['IFWI Chunk Hash Size', '0x%X' % self.ChunkHashSize])
		pt.add_row(['Reserved 10', '0x%X' % self.Reserved10])
		pt.add_row(['Reserved 11', '0x%X' % self.Reserved11])
		pt.add_row(['IFWI Chunk Data Size', '0x%X' % self.ChunkSize])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_14_HashArray(ctypes.LittleEndianStructure) : # R1 - DnX R2 Hashes Array (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("HashArrSize",		uint32_t),		# 0x0 dwords
		("HashArrHash",		uint32_t*8),	# 0x4 SHA-256
		# 0x24
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		HashArrHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.HashArrHash))
		
		pt.title = col_y + 'Extension 20 R2, Hashes Array' + col_e
		pt.add_row(['Hashes Array Size', '0x%X' % (self.HashArrSize * 4)])
		pt.add_row(['Hashes Array Hash', HashArrHash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_14_HashArray_R2(ctypes.LittleEndianStructure) : # R2 - DnX R2 Hashes Array (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		("HashArrSize",		uint32_t),		# 0x0 dwords
		("HashArrHash",		uint32_t*12),	# 0x4 SHA-384
		# 0x34
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		HashArrHash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.HashArrHash))
		
		pt.title = col_y + 'Extension 20 R2, Hashes Array' + col_e
		pt.add_row(['Hashes Array Size', '0x%X' % (self.HashArrSize * 4)])
		pt.add_row(['Hashes Array Hash', HashArrHash])
		
		return pt
		
class CSE_Ext_14_RegionMap(ctypes.LittleEndianStructure) : # R1 - DnX R1/R2 Region Map (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Unknown',			uint32_t),		# 0x00 # 0 LBP 1, 1 LBP2, 4 SPI (?)
		('RegionOffset',	uint32_t),		# 0x04 # Start offset from rcipifwi file base
		('RegionSize',		uint32_t),		# 0x08 # Size of region after rcipifwi start offset
		# 0xC
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 20 R1/R2, IFWI Region Map' + col_e
		pt.add_row(['Unknown', '0x%X' % self.Unknown])
		pt.add_row(['IFWI Region Start', '0x%X' % self.RegionOffset])
		pt.add_row(['IFWI Region Size', '0x%X' % self.RegionSize])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_15(ctypes.LittleEndianStructure) : # R1 - Unlock/Secure Token UTOK/STKN (SECURE_TOKEN_EXT)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("ExtVersion",		uint32_t),		# 0x08
		("PayloadVersion",	uint32_t),		# 0x0C
		("PartIDCount",		uint32_t),		# 0x10
		("TokenType",		uint32_t),		# 0x14 (TokenIdValues, tokens_list_broxton)
		("Flags",			uint32_t),		# 0x18
		("ExpirationSec",	uint32_t),		# 0x1C From Time Base
		("ManufLot",		uint32_t),		# 0x20
		("Reserved",		uint32_t*4),	# 0x24
		# 0x34
	]
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		frvalue = ['Yes','No']
		token_ids = {
					1: 'Intel Unlock',
					2: 'IDLM Unlock',
					3: 'OEM Unlock',
					4: 'PAVP Unlock',
					5: 'Visa Override',
					8: 'Change Device Lifecycle'
					}
		f1,f2,f3,f4,f5,f6,f7 = self.get_flags()
		
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Unlock/Secure Token' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Extension Version', '%d' % self.ExtVersion])
		pt.add_row(['Payload Version', '%d' % self.PayloadVersion])
		pt.add_row(['Part ID Count', '%d' % self.PartIDCount])
		pt.add_row(['Token Type', token_ids[self.TokenType] if self.TokenType in token_ids else 'Unknown'])
		pt.add_row(['Single Boot', fvalue[f1]])
		pt.add_row(['Part Restricted', frvalue[f2]])
		pt.add_row(['Anti-Replay', frvalue[f3]])
		pt.add_row(['Time Limited', frvalue[f4]])
		pt.add_row(['Manufacturing Lot Restrict', fvalue[f5]])
		pt.add_row(['Manufacturing Part ID', fvalue[f6]])
		pt.add_row(['Flags Reserved', '0x%X' % f7])
		pt.add_row(['Expiration Seconds', '%d' % self.ExpirationSec])
		pt.add_row(['Manufacturing Lot', '0x%X' % self.ManufLot])
		pt.add_row(['Reserved', '0x0' if Reserved == '00000000' * 4 else Reserved])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_15_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.SingleBoot, flags.b.PartRestricted, flags.b.AntiReplay, flags.b.TimeLimited,\
		       flags.b.ManufacturingLotRestrict, flags.b.ManufacturingPartID, flags.b.Reserved
	
class CSE_Ext_15_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('SingleBoot', uint32_t, 1),
		('PartRestricted', uint32_t, 1),
		('AntiReplay', uint32_t, 1),
		('TimeLimited', uint32_t, 1),
		('ManufacturingLotRestrict', uint32_t, 1),
		('ManufacturingPartID', uint32_t, 1),
		('Reserved', uint32_t, 26)
	]

class CSE_Ext_15_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_15_Flags),
		('asbytes', uint32_t)
	]

# noinspection PyTypeChecker
class CSE_Ext_15_PartID(ctypes.LittleEndianStructure) : # After CSE_Ext_15 (SECURE_TOKEN_PARTID)
	_pack_ = 1
	_fields_ = [
		("PartID",			uint32_t*3),	# 0x00
		("Nonce",			uint32_t),		# 0x0C
		("TimeBase",		uint32_t),		# 0x10
		# 0x14
	]
	
	def ext_print(self) :
		PartID = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.PartID))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Part ID' + col_e
		pt.add_row(['Part ID', 'N/A' if PartID == '00000000' * 3 else PartID])
		pt.add_row(['Nonce', '0x%X' % self.Nonce])
		pt.add_row(['Time Base', '0x%X' % self.TimeBase])
		
		return pt

class CSE_Ext_15_Payload(ctypes.LittleEndianStructure) : # After CSE_Ext_15_PartID (SECURE_TOKEN_PAYLOAD)
	_pack_ = 1
	_fields_ = [
		("KnobCount",		uint32_t),		# 0x00
		# 0x04
	]
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Payload' + col_e
		pt.add_row(['Knob Count', '%d' % self.KnobCount])
		
		return pt

class CSE_Ext_15_Payload_Knob(ctypes.LittleEndianStructure) : # After CSE_Ext_15_Payload (SECURE_TOKEN_PAYLOAD_KNOB)
	_pack_ = 1
	_fields_ = [
		("ID",			uint32_t),			# 0x00 (KnobIdValues)
		("Data",		uint32_t),			# 0x04
		# 0x08
	]
	
	def __init__(self, variant, major, minor, hotfix, build, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.variant = variant
		self.major = major
		self.minor = minor
		self.hotfix = hotfix
		self.build = build
	
	def ext_print(self) :
		knob_ids = {
			0x80860001 : ['Intel Unlock', ['Disabled', 'Enabled']],
			0x80860002 : ['OEM Unlock', ['Disabled', 'Enabled']],
			0x80860003 : ['PAVP Unlock', ['Disabled', 'Enabled']],
			0x80860010 : ['Allow Visa Override', ['Disabled', 'Enabled']],
			0x80860011 : ['Enable DCI', ['No', 'Yes']],
			0x80860020 : ['ISH GDB Support', ['Disabled', 'Enabled']],
			0x80860030 : ['Boot Guard', ['Nothing', 'Disabled', 'No Enforcement', 'No Timeouts', 'No Enforcement & Timeouts']] \
			if self.variant == 'CSME' and self.major >= 12 else ['BIOS Secure Boot', ['Enforced', 'Allow RnD Keys & Policies', 'Disabled']],
			0x80860031 : ['Audio FW Authentication', ['Enforced', 'Allow RnD Keys', 'Disabled']],
			0x80860032 : ['ISH FW Authentication', ['Enforced', 'Allow RnD Keys', 'Disabled']],
			0x80860033 : ['IUNIT FW Authentication', ['Enforced', 'Allow RnD Keys', 'Disabled']],
			0x80860040 : ['Anti-Rollback', ['Enabled', 'Disabled']], # (BtGuardArbOemKeyManifest)
			0x80860050 : ['PSF and System Agent Debug', ['PSF & System Agent Disabled', 'System Agent Enabled', 'PSF Enabled', 'PSF & System Agent Enabled']], # (KnobIdValues)
			0x80860051 : ['OEM BIOS Payload', ['Enabled', 'Disabled']], # (KnobIdValues)
			0x80860101 : ['Change Device Lifecycle', ['No', 'Customer Care', 'RnD', 'Refurbish']],
			0x80860201 : ['Co-Signing', ['Enabled', 'Disabled']]
			}
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 21, Payload Knob' + col_e
		pt.add_row(['ID', knob_ids[self.ID][0] if self.ID in knob_ids else 'Unknown: 0x%X' % self.ID])
		pt.add_row(['Data', knob_ids[self.ID][1][self.Data] if self.ID in knob_ids else 'Unknown: 0x%X' % self.Data])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_16(ctypes.LittleEndianStructure) : # R1 - IFWI Partition Information (IFWI_PARTITION_MANIFEST_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('PartitionSize',	uint32_t),		# 0x0C Complete original/RGN size before any process have been removed by the OEM or firmware update process
		('PartitionVer',	uint32_t),		# 0x10
		('DataFormatMinor',	uint16_t),		# 0x14 dword (0-15 Major, 16-31 Minor)
		('DataFormatMajor',	uint16_t),		# 0x16 dword (0-15 Major, 16-31 Minor)
		('InstanceID',		uint32_t),		# 0x18
		('Flags',			uint32_t),		# 0x1C Used at CSE_Ext_03 as well, remember to change both!
		('HashAlgorithm',	uint8_t),		# 0x20 0 Reserved, 1 SHA-1, 2 SHA-256
		('HashSize',		uint8_t*3),		# 0x21
		('Hash',			uint32_t*8),	# 0x24 Complete original/RGN partition covering everything except for the Manifest ($CPD - $MN2 + Data)
		('Reserved',		uint32_t*5),	# 0x44
		# 0x58
	]
	
	# PartitionSize & Hash are valid for RGN firmware only with stock $CPD & Data, no FIT/OEM configurations. The latter, usually oem.key and fitc.cfg,
	# are added at the end of the PartitionSize so FIT adjusts $CPD and appends customization files accordingly. Thus, PartitionSize and Hash fields
	# must not be verified at FIT/OEM-customized images because they're not applicable anymore.
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9 = self.get_flags()
		
		HashSize = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.HashSize))
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 22, IFWI Partition Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Partition Size', '0x%X' % self.PartitionSize])
		pt.add_row(['Partition Version', '0x%X' % self.PartitionVer])
		pt.add_row(['Data Format Version', '%d.%d' % (self.DataFormatMajor, self.DataFormatMinor)])
		pt.add_row(['Instance ID', '0x%0.8X' % self.InstanceID])
		pt.add_row(['Support Multiple Instances', fvalue[f1]])
		pt.add_row(['Support API Version Based Update', fvalue[f2]])
		pt.add_row(['Action On Update', '0x%X' % f3])
		pt.add_row(['Obey Full Update Rules', fvalue[f4]])
		pt.add_row(['IFR Enable Only', fvalue[f5]])
		pt.add_row(['Allow Cross Point Update', fvalue[f6]])
		pt.add_row(['Allow Cross Hotfix Update', fvalue[f7]])
		pt.add_row(['Partial Update Only', fvalue[f8]])
		pt.add_row(['Flags Reserved', '0x%X' % f9])
		pt.add_row(['Hash Type', ['Reserved','SHA-1','SHA-256'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % int(HashSize, 16)])
		pt.add_row(['Partition Hash', Hash])
		pt.add_row(['Reserved', '0x%X' % int(Reserved, 16)])
		
		return pt
	
	def get_flags(self) :
		flags = CSE_Ext_16_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.SupportMultipleInstances, flags.b.SupportApiVersionBasedUpdate, flags.b.ActionOnUpdate, flags.b.ObeyFullUpdateRules,\
		       flags.b.IfrEnableOnly, flags.b.AllowCrossPointUpdate, flags.b.AllowCrossHotfixUpdate, flags.b.PartialUpdateOnly, flags.b.Reserved

# noinspection PyTypeChecker
class CSE_Ext_16_R2(ctypes.LittleEndianStructure) : # R2 - IFWI Partition Information (IFWI_PARTITION_MANIFEST_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('PartitionName',	char*4),		# 0x08
		('PartitionSize',	uint32_t),		# 0x0C Complete original/RGN size before any process have been removed by the OEM or firmware update process
		('PartitionVer',	uint32_t),		# 0x10
		('DataFormatMinor',	uint16_t),		# 0x14 dword (0-15 Major, 16-31 Minor)
		('DataFormatMajor',	uint16_t),		# 0x16 dword (0-15 Major, 16-31 Minor)
		('InstanceID',		uint32_t),		# 0x18
		('Flags',			uint32_t),		# 0x1C
		('HashAlgorithm',	uint8_t),		# 0x20 0 Reserved, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashSize',		uint8_t*3),		# 0x21
		('Hash',			uint32_t*12),	# 0x24 Complete original/RGN partition covering everything except for the Manifest ($CPD - $MN2 + Data)
		('Reserved',		uint32_t*5),	# 0x54
		# 0x68
	]
	
	# PartitionSize & Hash are valid for RGN firmware only with stock $CPD & Data, no FIT/OEM configurations. The latter, usually oem.key and fitc.cfg,
	# are added at the end of the PartitionSize so FIT adjusts $CPD and appends customization files accordingly. Thus, PartitionSize and Hash fields
	# must not be verified at FIT/OEM-customized images because they're not applicable anymore.
	
	def ext_print(self) :
		fvalue = ['No','Yes']
		f1,f2,f3,f4,f5,f6,f7,f8,f9 = self.get_flags()
		
		HashSize = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.HashSize))
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Hash))
		Reserved = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 22, IFWI Partition Information' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Partition Name', self.PartitionName.decode('utf-8')])
		pt.add_row(['Partition Size', '0x%X' % self.PartitionSize])
		pt.add_row(['Partition Version', '0x%X' % self.PartitionVer])
		pt.add_row(['Data Format Version', '%d.%d' % (self.DataFormatMajor, self.DataFormatMinor)])
		pt.add_row(['Instance ID', '0x%0.8X' % self.InstanceID])
		pt.add_row(['Support Multiple Instances', fvalue[f1]])
		pt.add_row(['Support API Version Based Update', fvalue[f2]])
		pt.add_row(['Action On Update', '0x%X' % f3])
		pt.add_row(['Obey Full Update Rules', fvalue[f4]])
		pt.add_row(['IFR Enable Only', fvalue[f5]])
		pt.add_row(['Allow Cross Point Update', fvalue[f6]])
		pt.add_row(['Allow Cross Hotfix Update', fvalue[f7]])
		pt.add_row(['Partial Update Only', fvalue[f8]])
		pt.add_row(['Flags Reserved', '0x%X' % f9])
		pt.add_row(['Hash Type', ['Reserved','SHA-1','SHA-256','SHA-384'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % int(HashSize, 16)])
		pt.add_row(['Hash', Hash])
		pt.add_row(['Reserved', '0x%X' % int(Reserved, 16)])
		
		return pt
		
	def get_flags(self) :
		flags = CSE_Ext_16_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.SupportMultipleInstances, flags.b.SupportApiVersionBasedUpdate, flags.b.ActionOnUpdate, flags.b.ObeyFullUpdateRules,\
		       flags.b.IfrEnableOnly, flags.b.AllowCrossPointUpdate, flags.b.AllowCrossHotfixUpdate, flags.b.PartialUpdateOnly, flags.b.Reserved
	
class CSE_Ext_16_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('SupportMultipleInstances', uint32_t, 1), # For independently updated WCOD/LOCL partitions with multiple instances
		('SupportApiVersionBasedUpdate', uint32_t, 1),
		('ActionOnUpdate', uint32_t, 2),
		('ObeyFullUpdateRules', uint32_t, 1),
		('IfrEnableOnly', uint32_t, 1),
		('AllowCrossPointUpdate', uint32_t, 1),
		('AllowCrossHotfixUpdate', uint32_t, 1),
		('PartialUpdateOnly', uint32_t, 1),
		('Reserved', uint32_t, 23)
	]

class CSE_Ext_16_GetFlags(ctypes.Union):
	_fields_ = [
		('b', CSE_Ext_16_Flags),
		('asbytes', uint32_t)
	]
		
# noinspection PyTypeChecker
class CSE_Ext_17(ctypes.LittleEndianStructure) : # R1 - Flash Descriptor Hash (not in XML, Reverse Engineered)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		# 0x08 (?)
	]
	
	# No sample, placeholder!
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 23, Flash Descriptor Hash (TBD)' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_18(ctypes.LittleEndianStructure) : # R1 - USB Type C IO Manageability (TCSS_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Reserved',		uint32_t),		# 0x08
		# 0x0C
	]
	
	# TCCS = USB Type C Sub-System
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 24, USB Type C IO Manageability' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_18_Mod(ctypes.LittleEndianStructure) : # R1 - USB Type C IO Manageability Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 SHA-1, 1 SHA-256, 2 MD5
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*8),	# 0x0C SHA-256 Big Endian
		# 0x2C
	]
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 24, USB Type C IO Manageability Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', ['SHA-1','SHA-256','MD5'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_18_Mod_R2(ctypes.LittleEndianStructure) : # R2 - USB Type C IO Manageability Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 Reserved, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*12),	# 0x0C SHA-384 Big Endian
		# 0x3C
	]
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 24, USB Type C IO Manageability Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', ['Reserved','SHA-1','SHA-256','SHA-384'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt

# noinspection PyTypeChecker
class CSE_Ext_19(ctypes.LittleEndianStructure) : # R1 - USB Type C MG (TCSS_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Reserved',		uint32_t),		# 0x08
		# 0x0C
	]
	
	# TCCS = USB Type C Sub-System
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 25, USB Type C MG' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_19_Mod(ctypes.LittleEndianStructure) : # R1 - USB Type C MG Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 SHA-1, 1 SHA-256, 2 MD5
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*8),	# 0x0C SHA-256 Big Endian
		# 0x2C
	]
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 25, USB Type C MG Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', ['SHA-1','SHA-256','MD5'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_19_Mod_R2(ctypes.LittleEndianStructure) : # R2 - USB Type C MG Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 Reserved, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*12),	# 0x0C SHA-384 Big Endian
		# 0x3C
	]
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 25, USB Type C MG Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', ['Reserved','SHA-1','SHA-256','SHA-384'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_1A(ctypes.LittleEndianStructure) : # R1 - USB Type C Thunderbolt (TCSS_METADATA_EXT)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		('Reserved',		uint32_t),		# 0x08
		# 0x0C
	]
	
	# TCCS = USB Type C Sub-System
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 26, USB Type C Thunderbolt' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Reserved', '0x%X' % self.Reserved])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_1A_Mod(ctypes.LittleEndianStructure) : # R1 - USB Type C Thunderbolt Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 SHA-1, 1 SHA-256, 2 MD5
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*8),	# 0x0C SHA-256 Big Endian
		# 0x2C
	]
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 26, USB Type C Thunderbolt Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', ['SHA-1','SHA-256','MD5'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_1A_Mod_R2(ctypes.LittleEndianStructure) : # R2 - USB Type C Thunderbolt Hash (TCSS_HASH_METADATA)
	_pack_ = 1
	_fields_ = [
		('HashType',		uint32_t),		# 0x00
		('HashAlgorithm',	uint32_t),		# 0x04 0 Reserved, 1 SHA-1, 2 SHA-256, 3 SHA-384
		('HashSize',		uint32_t),		# 0x08
		('Hash',			uint32_t*12),	# 0x0C SHA-384 Big Endian
		# 0x3C
	]
	
	def ext_print(self) :
		Hash = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'big') for val in self.Hash)
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 26, USB Type C Thunderbolt Hash' + col_e
		pt.add_row(['Hash Type', '0x%X' % self.HashType])
		pt.add_row(['Hash Algorithm', ['Reserved','SHA-1','SHA-256','SHA-384'][self.HashAlgorithm]])
		pt.add_row(['Hash Size', '0x%X' % self.HashSize])
		pt.add_row(['Hash', Hash])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_30(ctypes.LittleEndianStructure) : # R1 - Golden Measurements File Certificate (CERTIFICATE_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		# 0x08 (?)
	]
	
	# No sample, placeholder!
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 48, Golden Measurements File Certificate (TBD)' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_31(ctypes.LittleEndianStructure) : # R1 - Golden Measurements File Body Header (GMF_BODY_HEADER_EXTENSION)
	_pack_ = 1
	_fields_ = [
		('Tag',				uint32_t),		# 0x00
		('Size',			uint32_t),		# 0x04
		# 0x08 (?)
	]
	
	# No sample, placeholder!
	
	def ext_print(self) :
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 49, Golden Measurements File Body Header (TBD)' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		
		return pt
		
# noinspection PyTypeChecker
class CSE_Ext_32(ctypes.LittleEndianStructure) : # R1 - SPS Platform ID (MFT_EXT_MANIFEST_PLATFORM_ID)
	_pack_ = 1
	_fields_ = [
		("Tag",				uint32_t),		# 0x00
		("Size",			uint32_t),		# 0x04
		("Type",			char*2),		# 0x08 RC Recovery, OP Operational
		("Platform",		char*2),		# 0x08 GE Greenlow, PU Purley, HA Harrisonville, PE Purley EPO, BA Bakerville
		("Reserved",		uint32_t),		# 0x0C
		# 0x10
	]
	
	def ext_print(self) :
		type_str = self.Type.decode('utf-8')
		platform_str = self.Platform.decode('utf-8')
		
		pt = ext_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Extension 50, CSSPS Platform ID' + col_e
		pt.add_row(['Tag', '0x%0.2X' % self.Tag])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Type', 'Unknown' if type_str not in cssps_type_fw else cssps_type_fw[type_str]])
		pt.add_row(['Platform', 'Unknown (%s)' % platform_str if platform_str not in cssps_platform else cssps_platform[platform_str]])
		pt.add_row(['Reserved', '0x0' if self.Reserved == 0 else '0x%X' % self.Reserved])
		
		return pt

# CSE Extensions without Modules
ext_tag_mod_none = [0x4, 0xA, 0xC, 0x11, 0x13, 0x16, 0x30, 0x31, 0x32]

# CSE Extensions with Module Count
ext_tag_mod_count = [0x1, 0x2, 0x12, 0x14, 0x15]

# CSE SPS SKU Type ID
cssps_type_fw = {'RC':'Recovery', 'OP':'Operational'}

# CSE SPS SKU Platform ID
cssps_platform = {'GE':'Greenlow', 'PU':'Purley', 'HA':'Harrisonville', 'PE':'Purley EPO', 'BA':'Bakerville', 'ME':'Mehlow'}

# CSE File System ID
mfs_type = {0:'root', 1:'home', 2:'bin', 3:'susram', 4:'fpf', 5:'dev', 6:'umafs'}

# CSE File System Home Directory Record Structures
home_rec_struct = {0x18:MFS_Home_Record_0x18, 0x1C:MFS_Home_Record_0x1C}

# CSE File System Configuration Record Structures
config_rec_struct = {0x1C:MFS_Config_Record_0x1C, 0xC:MFS_Config_Record_0xC}

# CSE File System Home Directory Integrity Structures
sec_hdr_struct = {0x28:MFS_Integrity_Table_0x28, 0x34:MFS_Integrity_Table_0x34}

# CSE Extension Structures
ext_dict = {
			'CSE_Ext_00' : CSE_Ext_00,
			'CSE_Ext_00_R2' : CSE_Ext_00_R2,
			'CSE_Ext_01' : CSE_Ext_01,
			'CSE_Ext_02' : CSE_Ext_02,
			'CSE_Ext_03' : CSE_Ext_03,
			'CSE_Ext_03_R2' : CSE_Ext_03_R2,
			'CSE_Ext_04' : CSE_Ext_04,
			'CSE_Ext_05' : CSE_Ext_05,
			'CSE_Ext_06' : CSE_Ext_06,
			'CSE_Ext_07' : CSE_Ext_07,
			'CSE_Ext_08' : CSE_Ext_08,
			'CSE_Ext_09' : CSE_Ext_09,
			'CSE_Ext_0A' : CSE_Ext_0A,
			'CSE_Ext_0A_R2' : CSE_Ext_0A_R2,
			'CSE_Ext_0B' : CSE_Ext_0B,
			'CSE_Ext_0C' : CSE_Ext_0C,
			'CSE_Ext_0D' : CSE_Ext_0D,
			'CSE_Ext_0E' : CSE_Ext_0E,
			'CSE_Ext_0F' : CSE_Ext_0F,
			'CSE_Ext_10' : CSE_Ext_10,
			'CSE_Ext_11' : CSE_Ext_11,
			'CSE_Ext_11_R2' : CSE_Ext_11_R2,
			'CSE_Ext_12' : CSE_Ext_12,
			'CSE_Ext_13' : CSE_Ext_13,
			'CSE_Ext_13_R2' : CSE_Ext_13_R2,
			'CSE_Ext_14' : CSE_Ext_14,
			'CSE_Ext_14_R2' : CSE_Ext_14_R2,
			'CSE_Ext_14_R3' : CSE_Ext_14_R3,
			'CSE_Ext_15' : CSE_Ext_15,
			'CSE_Ext_16' : CSE_Ext_16,
			'CSE_Ext_16_R2' : CSE_Ext_16_R2,
			'CSE_Ext_17' : CSE_Ext_17,
			'CSE_Ext_18' : CSE_Ext_18,
			'CSE_Ext_19' : CSE_Ext_19,
			'CSE_Ext_1A' : CSE_Ext_1A,
			'CSE_Ext_32' : CSE_Ext_32,
			'CSE_Ext_00_Mod' : CSE_Ext_00_Mod,
			'CSE_Ext_00_Mod_R2' : CSE_Ext_00_Mod_R2,
			'CSE_Ext_01_Mod' : CSE_Ext_01_Mod,
			'CSE_Ext_01_Mod_R2' : CSE_Ext_01_Mod_R2,
			'CSE_Ext_02_Mod' : CSE_Ext_02_Mod,
			'CSE_Ext_03_Mod' : CSE_Ext_03_Mod,
			'CSE_Ext_05_Mod' : CSE_Ext_05_Mod,
			'CSE_Ext_06_Mod' : CSE_Ext_06_Mod,
			'CSE_Ext_07_Mod' : CSE_Ext_07_Mod,
			'CSE_Ext_08_Mod' : CSE_Ext_08_Mod,
			'CSE_Ext_09_Mod' : CSE_Ext_09_Mod,
			'CSE_Ext_0B_Mod' : CSE_Ext_0B_Mod,
			'CSE_Ext_0D_Mod' : CSE_Ext_0D_Mod,
			'CSE_Ext_0D_Mod_R2' : CSE_Ext_0D_Mod_R2,
			'CSE_Ext_0E_Mod' : CSE_Ext_0E_Mod,
			'CSE_Ext_0E_Mod_R2' : CSE_Ext_0E_Mod_R2,
			'CSE_Ext_0F_Mod' : CSE_Ext_0F_Mod,
			'CSE_Ext_0F_Mod_R2' : CSE_Ext_0F_Mod_R2,
			'CSE_Ext_0F_Mod_R3' : CSE_Ext_0F_Mod_R3,
			'CSE_Ext_10_Mod' : CSE_Ext_10_Mod,
			'CSE_Ext_10_Mod_R2' : CSE_Ext_10_Mod_R2,
			'CSE_Ext_12_Mod' : CSE_Ext_12_Mod,
			'CSE_Ext_14_HashArray' : CSE_Ext_14_HashArray,
			'CSE_Ext_14_HashArray_R2' : CSE_Ext_14_HashArray_R2,
			'CSE_Ext_14_RegionMap' : CSE_Ext_14_RegionMap,
			'CSE_Ext_15_PartID' : CSE_Ext_15_PartID,
			'CSE_Ext_15_Payload' : CSE_Ext_15_Payload,
			'CSE_Ext_15_Payload_Knob' : CSE_Ext_15_Payload_Knob,
			'CSE_Ext_18_Mod' : CSE_Ext_18_Mod,
			'CSE_Ext_18_Mod_R2' : CSE_Ext_18_Mod_R2,
			'CSE_Ext_19_Mod' : CSE_Ext_19_Mod,
			'CSE_Ext_19_Mod_R2' : CSE_Ext_19_Mod_R2,
			'CSE_Ext_1A_Mod' : CSE_Ext_1A_Mod,
			'CSE_Ext_1A_Mod_R2' : CSE_Ext_1A_Mod_R2,
			}
			
# CSE Key Manifest Hash Usages
key_dict = {
			# Intel (0-31)
			0 : 'CSE BUP', # Fault Tolerant Partition (FTPR)
			1 : 'CSE Main', # Non-Fault Tolerant Partition (NFTP)
			2 : 'PMC', # Power Management Controller
			6 : 'USB Type C IOM', # USB Type C I/O Manageability
			7 : 'USB Type C MG', # # USB Type C Manageability (?)
			8 : 'USB Type C TBT', # USB Type C Thunderbolt
			9 : 'WCOD', # Wireless Microcode
			10 : 'LOCL', # AMT Localization
			11 : 'Intel Unlock Token',
			13 : 'USB Type C D-PHY',
			14 : 'PCH Configuration',
			16 : 'Intel ISI',
			# OEM (32-127)
			32 : 'Boot Policy',
			33 : 'iUnit Boot Loader', # Imaging Unit (Camera)
			34 : 'iUnit Main Firmware',
			35 : 'cAVS Image 0', # Clear Audio Voice Speech
			36 : 'cAVS Image 1',
			37 : 'IFWI', # Integrated Firmware Image
			38 : 'OS Boot Loader',
			39 : 'OS Kernel',
			40 : 'OEM SMIP', # Signed Master Image Profile
			41 : 'ISH Main', # Integrated Sensor Hub
			42 : 'ISH BUP',
			43 : 'OEM Unlock Token',
			44 : 'OEM Life Cycle',
			45 : 'OEM Key',
			46 : 'SilentLake VMM',
			47 : 'OEM Key Attestation',
			48 : 'OEM DAL', # Dynamic Application Loader
			49 : 'OEM DNX IFWI R1', # XML v1.0 (Download and Execute v1)
			53 : 'OEM DNX IFWI R2', # XML v2.4 (Download and Execute v2)
			57 : 'OEM Descriptor',
			58 : 'OEM ISI',
			}
	
# IFWI BPDT Entry Types
# Names from $MN2 Manifest
bpdt_dict = {
			0 : 'SMIP', # OEM-SMIP Partition
			1 : 'RBEP', # ROM Boot Extensions Partition (CSE-RBE)
			2 : 'FTPR', # Fault Tolerant Partition (CSE-BUP)
			3 : 'UCOD', # Microcode Partition
			4 : 'IBBP', # IBB Partition
			5 : 'S-BPDT', # Secondary BPDT
			6 : 'OBBP', # OBB Partition
			7 : 'NFTP', # Non-Fault Tolerant Partition (CSE-MAIN)
			8 : 'ISHC', # ISH Partition
			9 : 'DLMP', # IDLM Partition
			10 : 'UEPB', # IFP Override/Bypass Partition
			11 : 'UTOK', # Debug Tokens Partition
			12 : 'UFS PHY', # UFS PHY Partition
			13 : 'UFS GPP LUN', # UFS GPP LUN Partition
			14 : 'PMCP', # PMC Partition
			15 : 'IUNP', # IUnit Partition
			16 : 'NVMC', # NVM Configuration
			17 : 'UEP', # Unified Emulation Partition
			18 : 'WCOD', # CSE-WCOD Partition
			19 : 'LOCL', # CSE-LOCL Partition
			20 : 'OEMP', # OEM KM Partition
			21 : 'FITC', # Defaults/FITC.cfg
			22 : 'PAVP', # Protected Audio Video Path
			23 : 'IOMP', # USB Type C IO Manageability Partition (UIOM)
			24 : 'NPHY', # USB Type C MG Partition (NPHY = MGPP)
			25 : 'TBTP', # USB Type C Thunderbolt Partition (TBT)
			26 : 'PLTS', # Platform Settings
			31 : 'DPHY', # USB Type C Dekel PHY
			32 : 'PCHC', # PCH Configuration
			33 : 'ISIF', # ISI Firmware
			34 : 'ISIC', # ISI Configuration
			}
	
# CSE PCH Platforms
pch_dict = {
			0x0 : 'LBG-H', # Lewisburg H
			0x3 : 'ICP-LP', # Ice Point LP
			0x4 : 'ICP-N', # Ice Point N (JSL)
			0x5 : 'ICP-H', # Ice Point H
			0x6 : 'TGP-LP', # Tiger Point LP
			0x7 : 'TGP-H', # Tiger Point H
			0x8 : 'SPT/KBP-LP', # Sunrise/Union Point LP
			0x9 : 'SPT-H', # Sunrise Point H
			0xB : 'KBP/BSF-H', # Union Point/Basin Falls H
			0xC : 'CNP-LP', # Cannon Point LP
			0xD : 'CNP-H', # Cannon Point H
			0xE : 'LKF-?', # Lakefield ?
			}
	
# CSE Known Bad Partition/Module Hashes
cse_known_bad_hashes = [
('B42458010144CB5708148C31590637372021FCBF21CE079679772FBD2990CF5F','CFB464D442FB477C1642B3C8F60809F764C727509A2112AB921430E2625ECB9B'), # CSME 11.8.50.3399_COR_H_DA_PRD > WCOD 24FD > mu_init
('89BFFD3CFAA25C0CA3AE4ABBDBFAA06F21566CEE653EF65401A80EAB36EB6F08','3A294E6196783ED22310AA3031706E7F6B774FCAFE479D5AFA1C6433E192652E'), # CSME 11.8.50.3399_COR_H_DA_PRD > WCOD 24FD > mu_d0d3
('B63D75602385A6CFE56EC8B79481E46074B1E39217F191B3C9AB961CE4A03139','3B3866517F1C3B1F07BA9692A8B1599F5DDAA24BFFB3F704C711F30D1E067288'), # CSME 11.8.50.3399_COR_H_DA_PRD > WCOD 24FD > umac_d0
('470A0E018AF18F6477029AFE0207307BCD77991272CF23DA741712DAB109C8F8','B570786DAAA91A9A0119BD6F4143160044B054663FB06317650AE77DD6842401'), # CSME 11.8.50.3399_COR_H_DA_PRD > WCOD 24F3 > mu_init
('35C7D3383E6B380C3B07CB41444448EC63E3F219C77E7D99DA19C5BFB856713B','785F395BC28544253332ACB1C5C65CDA7C24662D55DC8AB8F0E56543B865A4C3'), # CSME 11.8.50.3399_COR_H_DA_PRD > WCOD 24F3 > mu_d0d3
('4DCF921DC0A48D2967063969ED1314CB17AA03E86635A366E2750BE43A219D95','058C09ABE1D1AB2B28D1D06153908EDAE8B420967D54EC4F1F99AC0D0101454C'), # CSME 11.8.50.3399_COR_H_DA_PRD > WCOD 24F3 > umac_d0
('IGNORE','IGNORE') # Ignore CSE firmware groups which are always hashed wrongly (CSME 11.8 SLM Extension 0x3, CSSPS 5 Extension 0x16)
]

# CSE Extensions 0x00-0x16, 0x18-0x1A, 0x30-0x32
ext_tag_all = list(range(23)) + list(range(24,27)) + list(range(48,51))

# CSME 12-14 Revised Extensions
ext_tag_rev_hdr_csme12 = {0x14:'_R2'}

# CSME 12-14 Revised Extension Modules
ext_tag_rev_mod_csme12 = {0x1:'_R2', 0xD:'_R2'}

# CSME 15 Revised Extensions
ext_tag_rev_hdr_csme15 = {0x0:'_R2', 0x3:'_R2', 0xA:'_R2', 0x11:'_R2', 0x13:'_R2', 0x14:'_R3', 0x16:'_R2'}

# CSME 15 Revised Extension Modules
ext_tag_rev_mod_csme15 = {0xE:'_R2', 0xF:'_R2', 0x10:'_R2', 0x18:'_R2', 0x19:'_R2', 0x1A:'_R2'}

# CSSPS 5 Revised Extensions
ext_tag_rev_hdr_cssps5 = {}

# CSSPS 5 Revised Extension Modules
ext_tag_rev_mod_cssps5 = {0x1:'_R2', 0x0:'_R2'}

# CSSPS 5.0.0-3 Revised Extensions
ext_tag_rev_hdr_cssps503 = {}

# CSSPS 5.0.0-3 Revised Extension Modules
ext_tag_rev_mod_cssps503 = {0x0:'_R2'}
