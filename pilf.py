import struct

class elf_file_header:
    def __init__(self, e_ident, e_type, e_machine, e_version, e_entry, e_phoff,
                 e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize,
                 e_shnum, e_shstrndx):
       self.e_ident = e_ident
       self.e_type = e_type
       self.e_machine = e_machine
       self.e_version = e_version
       self.e_entry = e_entry
       self.e_phoff = e_phoff
       self.e_shoff = e_shoff
       self.e_flags = e_flags
       self.e_ehsize = e_ehsize
       self.e_phentsize = e_phentsize
       self.e_phnum = e_phnum
       self.e_shentsize = e_shentsize
       self.e_shnum = e_shnum
       self.e_shstrndx = e_shstrndx
    
    @classmethod
    def unpack(self, buffer):
        if(len(buffer) >= 52):
            buf = buffer[:52]
            unpacked_data = struct.unpack_from('<16sHHIIIIIHHHHHH', buf, 0)
            return unpacked_data
        return None
    
    def verify_header(self) -> bool:
        ret = False
        if(self.e_ident[1:4] == bytearray(b'ELF') and self.e_ident[0] == 0x7f):
            print("header verified")
            ret=True
        return ret

class elf32_prog_header:
    def __init__(self, p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align):
        self.p_type = p_type
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_flags = p_flags
        self.p_align = p_align

    @classmethod
    def unpack(cls, buffer):
        if(len(buffer) >= 84):
            buf = buffer[52 : 84 ]
            unpacked_data = struct.unpack('<IIIIIIII', buf)
            return unpacked_data
        return None


class elf32_section_hdr:
    def __init__(self, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize):
        self.sh_name = sh_name
        self.sh_type = sh_type
        self.sh_flags = sh_flags
        self.sh_addr = sh_addr
        self.sh_offset = sh_offset
        self.sh_size = sh_size
        self.sh_link = sh_link
        self.sh_info = sh_info
        self.sh_addralign = sh_addralign
        self.sh_entsize = sh_entsize

    @classmethod
    def unpack(cls, buffer):
        if(len(buffer) >= 40):
            buf = buffer[ : 40 ]
            unpacked_data = struct.unpack('<IIIIIIIIII', buf)
            return unpacked_data    
        return None    


def parse_elf_file(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

data = bytearray([
    0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xdd, 0x21, 0x00, 0x08, 0x34, 0x00, 0x00, 0x00,
    0x44, 0xd1, 0x13, 0x00, 0x00, 0x04, 0x00, 0x05,
    0x34, 0x00, 0x20, 0x00, 0x03, 0x00, 0x28, 0x00,
    0x1b, 0x00, 0x1a, 0x00
])

fata = bytearray([
    0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xdd, 0x21, 0x00, 0x08, 0x34, 0x00, 0x00, 0x00,
    0x44, 0xd1, 0x13, 0x00, 0x00, 0x04, 0x00, 0x05,
    0x34, 0x00, 0x20, 0x00, 0x03, 0x00, 0x28, 0x00,
    0x1b, 0x00, 0x1a
])

#TODO: error handling
elf_buf = parse_elf_file('EIS_Firmware_test_1.elf')
#TODO: error handling
elf_hdr = elf_file_header.unpack(elf_buf)
#TODO: error handling
hdr = elf_file_header(elf_hdr[0],elf_hdr[1],elf_hdr[2],elf_hdr[3],elf_hdr[4],elf_hdr[5],
                      elf_hdr[6],elf_hdr[7],elf_hdr[8],elf_hdr[9],elf_hdr[10],elf_hdr[11],
                      elf_hdr[12],elf_hdr[13])
hdr.verify_header()
elf_hdr = elf32_prog_header.unpack(elf_buf)
prg_hdr = elf32_prog_header(elf_hdr[0],elf_hdr[1],elf_hdr[2],elf_hdr[3],elf_hdr[4],elf_hdr[5],
                      elf_hdr[6],elf_hdr[7])

section_hdr_list = list()
for i in range(hdr.e_shnum-1):
    section_data = elf_buf[hdr.e_shoff + (hdr.e_shentsize*i):hdr.e_shoff + (hdr.e_shentsize*(i+1))]
    elf_hdr = elf32_section_hdr.unpack(section_data) 
    section_hdr_list.append(elf32_section_hdr(elf_hdr[0],elf_hdr[1],elf_hdr[2],elf_hdr[3],elf_hdr[4],elf_hdr[5],
                      elf_hdr[6],elf_hdr[7],elf_hdr[8],elf_hdr[9]))

print("hi")

