package ghidraps4loader;

import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.app.util.bin.format.elf.ElfDynamic;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.util.Msg;

public class PS4ElfParser {
	// ELF Types
	public static final long ET_SCE_EXEC = 0xFE00;
	public static final long ET_SCE_REPLAY_EXEC = 0xFE01;
	public static final long ET_SCE_RELEXEC = 0XFE04;
	public static final long ET_SCE_STUBLIB = 0xFE0C;
	public static final long ET_SCE_DYNEXEC = 0xFE10;
	public static final long ET_SCE_DYNAMIC = 0xFE18;

	// Program Segment Type
	public static final long PT_SCE_RELA = 0x60000000;
	public static final long PT_SCE_DYNLIBDATA = 0x61000000;
	public static final long PT_SCE_PROCPARAM = 0x61000001;
	public static final long PT_SCE_MODULEPARAM = 0x61000002;
	public static final long PT_SCE_RELRO = 0x61000010;
	public static final long PT_SCE_COMMENT = 0X6FFFFF00;
	public static final long PT_SCE_LIBVERSION = 0X6FFFFF01;

	// Dynamic Section Types
	public static final long DT_SCE_IDTABENTSZ = 0x61000005;
	public static final long DT_SCE_FINGERPRINT = 0x61000007;
	public static final long DT_SCE_ORIGINAL_FILENAME = 0x61000009;
	public static final long DT_SCE_MODULE_INFO = 0x6100000D;
	public static final long DT_SCE_NEEDED_MODULE = 0x6100000F;
	public static final long DT_SCE_MODULE_ATTR = 0x61000011;
	public static final long DT_SCE_EXPORT_LIB = 0x61000013;
	public static final long DT_SCE_IMPORT_LIB = 0x61000015;
	public static final long DT_SCE_EXPORT_LIB_ATTR = 0x61000017;
	public static final long DT_SCE_IMPORT_LIB_ATTR = 0x61000019;
	public static final long DT_SCE_STUB_MODULE_NAME = 0x6100001D;
	public static final long DT_SCE_STUB_MODULE_VERSION = 0x6100001F;
	public static final long DT_SCE_STUB_LIBRARY_NAME = 0x61000021;
	public static final long DT_SCE_STUB_LIBRARY_VERSION = 0x61000023;
	public static final long DT_SCE_HASH = 0x61000025;
	public static final long DT_SCE_PLTGOT = 0x61000027;
	public static final long DT_SCE_JMPREL = 0x61000029;
	public static final long DT_SCE_PLTREL = 0x6100002B;
	public static final long DT_SCE_PLTRELSZ = 0x6100002D;
	public static final long DT_SCE_RELA = 0x6100002F;
	public static final long DT_SCE_RELASZ = 0x61000031;
	public static final long DT_SCE_RELAENT = 0x61000033;
	public static final long DT_SCE_STRTAB = 0x61000035;
	public static final long DT_SCE_STRSZ = 0x61000037;
	public static final long DT_SCE_SYMTAB = 0x61000039;
	public static final long DT_SCE_SYMENT = 0x6100003B;
	public static final long DT_SCE_HASHSZ = 0x6100003D;
	public static final long DT_SCE_SYMTABSZ = 0x6100003F;
	public static final long DT_SCE_HIOS = 0X6FFFF000;

	public static class Elf64_Rela {
		public long r_offset;    /* Location at which to apply the action */
		public long r_info;      /* index and type of relocation */
		public long r_addend;    /* Constant addend used to compute value */
		public static final int SIZE = 24;

		public Elf64_Rela(BinaryReader br) throws IOException {
			r_offset = br.readNextLong();
			r_info = br.readNextLong();
			r_addend = br.readNextLong();
		}
	}

	public static class Elf64_Sym {
		public int st_name;        /* Symbol name, index in string tbl */
		public byte st_info;       /* Type and binding attributes */
		public byte st_other;      /* No defined meaning, 0 */
		public short st_shndx;     /* Associated section index */
		public long st_value;      /* Value of the symbol */
		public long st_size;       /* Associated symbol size */
		public static final int SIZE = 24;

		public Elf64_Sym(BinaryReader br) throws IOException {
			st_name = br.readNextInt();
			st_info = br.readNextByte();
			st_other = br.readNextByte();
			st_shndx = br.readNextShort();
			st_value = br.readNextLong();
			st_size = br.readNextLong();
		}
	}

	public static ElfHeader getElfHeader(ByteProvider provider) throws ElfException, IOException {
		ElfHeader elfHeader = new ElfHeader(provider, msg -> Msg.error(PS4ElfParser.class, msg));
		elfHeader.parse();
		return elfHeader;
	}

	public static Map<Long, String> getSonyElfImports(ByteProvider provider, ElfHeader elfHeader) throws IOException {
		// Parse the specific Sony ELF region and build the map
		BinaryReader br = new BinaryReader(provider, true);
		Map<Long, String> results = new TreeMap<Long, String>();
		long dynlibdataAddr = 0;

		ElfDynamicTable dynTable = elfHeader.getDynamicTable();
		for(ElfProgramHeader prog : elfHeader.getProgramHeaders((int)PT_SCE_DYNLIBDATA)) {
			dynlibdataAddr = prog.getOffset();
		}

		long symAddr = dynlibdataAddr;
		long relocAddr = dynlibdataAddr;
		long strtableAddr = dynlibdataAddr;
		long strtableSize = 0;
		long number = 0;
		if (null != dynTable)
			for(ElfDynamic dyn : dynTable.getDynamics()) {
				long tag = dyn.getTag();
				if(tag == DT_SCE_JMPREL) {
					relocAddr += dyn.getValue();
				} else if(tag == DT_SCE_SYMTAB) {
					symAddr += dyn.getValue();
				} else if(tag == DT_SCE_STRTAB) {
					strtableAddr += dyn.getValue();
				} else if(tag == DT_SCE_STRSZ) {
					strtableSize += dyn.getValue();
				} else if(tag == DT_SCE_PLTRELSZ) {
					number = dyn.getValue() / 24;
				}
			}

		// Parse through the relocation addresses and associate the symbol with each relocation
		for(int i = 0; i < number; i++) {
			br.setPointerIndex(relocAddr);
			Elf64_Rela rela = new Elf64_Rela(br);

			// find symbol for relocation
			br.setPointerIndex(symAddr + (Elf64_Sym.SIZE * (rela.r_info >> 32)));
			Elf64_Sym sym = new Elf64_Sym(br);

			br.setPointerIndex(strtableAddr + sym.st_name);
			String nid = br.readNextAsciiString().split("#")[0];
			//System.out.println(nid);

			results.put(rela.r_offset, nid);

			relocAddr += Elf64_Rela.SIZE;
		}

		return results;
	}
}