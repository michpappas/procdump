/*
 *  Reconstruct ELF executable from a running process
 *  Copyright (C) 2017 Michalis Pappas
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <byteswap.h>
#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define MAPS_READ_LEN	45

struct segment {
	uint64_t base;
	size_t offset;
	size_t len;
	uint8_t *buf;
};

struct section {
	Elf64_Shdr shdr;
	uint8_t *buf;
};

void hexdump(uint8_t *buf, size_t len, size_t print_base)
{
	if (!print_base)
		print_base = (size_t)buf;

	for (size_t i = 0; i < len; i += 16) {
		printf("%08x  ", print_base + i);
		for (int j = 0; j < 8; j++) {
			if (i + j < len)
				printf("%02x ", buf[i + j]);
		}
		printf(" ");
		for (int j = 8; j < 16; j++) {
			if (i + j < len)
				printf("%02x ", buf[i + j]);
		}
		/* Print ASCII */
		printf(" |");
		for (int j = 0; j < 16; j++) {
			if (i + j < len)
				printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
		}
		printf("|\n");
	}
}

int pt_peek(int pid, uint8_t *dst, const uint8_t *src, size_t len)
{
	errno = 0;
	for (int i = 0; i < len; i+= sizeof(uint64_t)) {
		*(uint64_t *)dst = ptrace(PTRACE_PEEKTEXT, pid, (long *)src, NULL);
		if (errno) {
			perror("ptrace");
			return errno;
		}
		src += sizeof(uint64_t);
		dst += sizeof(uint64_t);
	}
	return 0;
}

int get_baseaddr(int pid, unsigned long *base, unsigned long *len)
{
	int fd;
	char maps_fname[32];
	char maps[MAPS_READ_LEN];

	char *p1, *p2;
	unsigned long start, end;

	snprintf(maps_fname, sizeof(maps_fname), "/proc/%u/maps", pid);

	fd = open(maps_fname, O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	read(fd, maps, sizeof(maps));

	/* parse segment start */
	p1 = strchr(maps, '-');
	*p1 = '\0';
	start = strtol(maps, NULL, 16);

	/* parse segment end */
	p1++;
	p2 = strchr(p1, ' ');
	*p2 = '\0';
	end = strtol(p1, NULL, 16);

	*base = start;
	if (len)
		*len = end - start;

	return 0;
}

int main(int argc, char **argv)
{
	unsigned int pid;

	struct segment text_seg;
	struct segment data_seg;
	struct segment dynamic_seg;

	struct section interp = {0};
	struct section pltrel = {0};
	struct section plt = {0};
	struct section gotplt = {0};
	struct section dynstr = {0};
	struct section dynsym = {0};
	struct section reladyn = {0};
	struct section init_array = {0};
	struct section fini_array = {0};

	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;

	Elf64_Dyn *dynamic;

	if (argc != 2 || !(pid = atoi(argv[1]))) {
		fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
		return -1;
	}

	/* get base address from /proc/<pid>/maps */
	if (get_baseaddr(pid, &text_seg.base, &text_seg.len)) {
		fprintf(stderr, "No such process\n");
		return -1;
	}

	/* attach */
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		perror("PTRACE_ATTACH");
		return -1;
	}

	waitpid(pid, NULL, 0);

	/* read text segment */
	text_seg.buf = calloc(text_seg.len, 1);
	if (pt_peek(pid, (void *)text_seg.buf, (void *)text_seg.base, text_seg.len)) {
		fprintf(stderr, "Could not read text segment\n");
		return -1;
	}

	//hexdump(text_seg.buf, text_seg.len, text_seg.base);

	/* parse elf header to locate program header table */
	if (text_seg.buf[0] != 0x7f || strncmp(&text_seg.buf[1], "ELF", 3)) {
		fprintf(stderr, "Bad ELF header\n");
	}
	ehdr = (Elf64_Ehdr *)text_seg.buf;
	phdr = (Elf64_Phdr *)&text_seg.buf[ehdr->e_phoff];

	printf("[+] Program header at 0x%x\n", phdr);

	/* Locate data segment */
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_INTERP) {
			interp.shdr.sh_addr = phdr[i].p_vaddr;
			interp.shdr.sh_offset = phdr[i].p_offset;
			interp.shdr.sh_size = phdr[i].p_filesz;
		}
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R | PF_W)) {
			printf("[+] Data segment at 0x%x\n", phdr[i].p_vaddr);
			data_seg.buf = calloc(phdr[i].p_memsz, 1);
			if (pt_peek(pid, (void *)data_seg.buf, (void *)phdr[i].p_vaddr, phdr[i].p_memsz)) {
				fprintf(stderr, "Could not read data segment\n");
				return -1;
			}
			data_seg.base = phdr[i].p_vaddr;
			data_seg.offset = phdr[i].p_offset;
			data_seg.len = phdr[i].p_memsz;
			//hexdump(data_buf, phdr[i].p_memsz, phdr[i].p_vaddr);
		}

		/* Locate dyamic segment */
		if (phdr[i].p_type == PT_DYNAMIC) {
			dynamic_seg.buf = calloc(phdr[i].p_memsz, 1);
			printf("[+] Dynamic segment at 0x%x\n", phdr[i].p_vaddr);
			if (pt_peek(pid, (void *)dynamic_seg.buf, (void *)phdr[i].p_vaddr, phdr[i].p_memsz)) {
				fprintf(stderr, "Could not read dynamic segment\n");
				return -1;
			}
			dynamic_seg.base = phdr[i].p_vaddr;
			dynamic_seg.offset = phdr[i].p_offset;
			dynamic_seg.len = phdr[i].p_memsz;
			//hexdump(dynamic_seg.buf, phdr[i].p_memsz, phdr[i].p_vaddr);
		}
	}

	dynamic = (Elf64_Dyn *)dynamic_seg.buf;
	for (int i = 0; dynamic[i].d_tag != DT_NULL; i++) {
		switch (dynamic[i].d_tag) {
		/*
		 * == Mandatory Tags ==
		 */
		case DT_HASH:
			/* TODO */
			break;
		case DT_STRTAB:
			dynstr.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			dynstr.shdr.sh_offset = dynstr.shdr.sh_addr - text_seg.base;
			dynstr.buf = &text_seg.buf[dynstr.shdr.sh_offset];
			printf("Found dynstr at 0x%x\n", dynstr.shdr.sh_addr);
			break;
		case DT_SYMTAB:
			dynsym.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			dynsym.shdr.sh_offset = dynsym.shdr.sh_addr - text_seg.base;
			printf("Found dynsym at 0x%x\n", dynsym.shdr.sh_addr);
			break;
		case DT_RELA: /* .rela.dyn */
			reladyn.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			reladyn.shdr.sh_offset = reladyn.shdr.sh_addr - text_seg.base;
			printf("Found RELA at 0x%x\n", reladyn.shdr.sh_addr);
			break;
		case DT_RELASZ:
			reladyn.shdr.sh_size = dynamic[i].d_un.d_val;
		case DT_RELAENT:
			reladyn.shdr.sh_entsize = dynamic[i].d_un.d_val;
			break;
		case DT_STRSZ:
			dynstr.shdr.sh_size = dynamic[i].d_un.d_ptr;
			break;
		case DT_SYMENT:
			dynsym.shdr.sh_entsize = dynamic[i].d_un.d_val;
			printf("Found syment: 0x%x\n", dynsym.shdr.sh_entsize);
			break;
		case DT_REL:
		case DT_RELSZ:
		case DT_RELENT:
			/* TODO */
			break;
		/*
		 * == Optional Tags ==
		 */
		case DT_PLTGOT:
			printf("[+] Found GOT at 0x%x\n", dynamic[i].d_un.d_ptr);
			gotplt.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			gotplt.shdr.sh_offset = dynamic[i].d_un.d_ptr - data_seg.base;
			/* TODO check if GOT lives in the data segment */
			gotplt.buf = &data_seg.buf[gotplt.shdr.sh_addr - data_seg.base];
			break;
		case DT_PLTRELSZ:
			pltrel.shdr.sh_size = dynamic[i].d_un.d_ptr;
			break;
		case DT_JMPREL:
			pltrel.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			pltrel.shdr.sh_offset = pltrel.shdr.sh_addr - text_seg.base;
			printf("[+] Found JMPREL at: 0x%x\n", dynamic[i].d_un.d_ptr);
			break;
		case DT_PLTREL:
			if (dynamic[i].d_un.d_val == DT_REL) {
				pltrel.shdr.sh_entsize = sizeof(Elf64_Rel);
				printf("PLTREL type: DT_REL\n");
			} else {
				pltrel.shdr.sh_entsize = sizeof(Elf64_Rela);
				printf("PLTREL type: DT_RELA\n");
			}
			break;
		case DT_INIT_ARRAY:
			init_array.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			init_array.shdr.sh_offset = dynamic[i].d_un.d_ptr - data_seg.base;
			break;
		case DT_INIT_ARRAYSZ:
			init_array.shdr.sh_size = dynamic[i].d_un.d_val;
			break;
		case DT_FINI_ARRAY:
			fini_array.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			fini_array.shdr.sh_offset = fini_array.shdr.sh_addr - data_seg.base;
			break;
		case DT_FINI_ARRAYSZ:
			fini_array.shdr.sh_size = dynamic[i].d_un.d_val;
			break;
		}
	}

	/* get indices to GOT from plt relocation entries */
	pltrel.buf = &text_seg.buf[pltrel.shdr.sh_offset];
	printf("PLTREL offset = %d\n", pltrel.shdr.sh_offset);
	for (int i = 0; i < pltrel.shdr.sh_size / sizeof(Elf64_Rela); i++) {
		Elf64_Rela *r = (Elf64_Rela *)(pltrel.buf + i * sizeof(Elf64_Rela));
		printf("%x %lx %s %x\n", r->r_offset, ELF64_R_SYM(r->r_info), ELF64_R_TYPE(r->r_info) == R_X86_64_JUMP_SLOT ? "R_X86_64_JUMP_SLOT" : "Other", r->r_addend);
	}

	/* Scan text segment for PLT-0 */
	printf("[+] Looking for PLT-0\n");
	uint8_t *ptr = text_seg.buf;
	while (ptr <= text_seg.buf + text_seg.len) {
		/* x86_64 PLT-0 signature:
		 *	ff 35 ?? ?? ?? ??	pushq 0x????????(%rip) # GOT[1]
		 *	ff 25 ?? ?? ?? ??	jmpq  *0x????????(rip) # GOT[2]
		 *	0f 1f 40 00		nopl  0x0(%rax)
		 */
		uint64_t vaddr = text_seg.base + ptr - text_seg.buf;

		uint64_t got1_offs = (gotplt.shdr.sh_addr + 8)- (vaddr + 6);
		uint64_t got2_offs = (gotplt.shdr.sh_addr + 16)- (vaddr + 12);

		uint64_t sig1 = 0x25ff0000000035ff | (got1_offs << 16);
		uint64_t sig2 = 0x00401f0f00000000 | got2_offs;

		if (*(uint64_t *)ptr == sig1 && *(uint64_t *)(ptr + 8) == sig2) {
			printf("[+] Found PLT at 0x%08x\n", vaddr);
			plt.buf = ptr;
			plt.shdr.sh_addr = vaddr;
			plt.shdr.sh_offset = vaddr - text_seg.base;
		}
		ptr++;
	}

	if (!plt.buf) {
		fprintf(stderr, "Could not find PLT-0\n");
		exit(EXIT_FAILURE);
	}

	/* Restore GOT entries */
	printf("[+] Restoring GOT\n");
	*((uint64_t *)gotplt.buf + 1) = 0;	/* GOT[1] set to zero */
	*((uint64_t *)gotplt.buf + 2) = 0;	/* GOT[2] set to zero */
	for (int i = 0; i < pltrel.shdr.sh_size / sizeof(Elf64_Rela); i++) {
		/* the relocation entry's offset value contains the GOT address to patch */
		Elf64_Rela *r = (Elf64_Rela *)(pltrel.buf + i * sizeof(Elf64_Rela));
		/* find which PLT entry contains the jmp to this address */
		printf("PLT entries:\n");
		for (int i = 0; i < pltrel.shdr.sh_size / sizeof(Elf64_Rela); i++) {
			/* this contains the offset from the next instruction */
			uint64_t got_offs_from_plt_instr = *(uint64_t *)(plt.buf + 0x10 + 0x10 * i) >> 16 & 0xffffffff;
			/* the address of the next instruction is */
			uint64_t addr_of_next_plt_instr = plt.shdr.sh_addr + 0x10 + 0x10 * i + 6;
			/* the GOT address in this relocation entry is: */
			uint64_t got_addr = addr_of_next_plt_instr + got_offs_from_plt_instr;

			if (got_addr == r->r_offset) {
				/* Patch this GOT entry with addr_of_next_plt_instr*/
				printf("Found matching entry, 0x%x bytes away from GOT[0]\n", got_addr - gotplt.shdr.sh_addr);
				printf("Patching with 0x%lx\n", addr_of_next_plt_instr);
				*((uint64_t *)gotplt.buf + ((got_addr - gotplt.shdr.sh_addr) / 8)) = addr_of_next_plt_instr;
			}
		}
	}

	/* Reconstruct file */
	FILE *f;
	char fname[20];

	snprintf(fname, sizeof(fname), "%d.dump", pid);

	f = fopen(fname, "w");

	/* TODO: Reconstruct  section header table */
	uint8_t shstrtab[] = "\0.interp\0.dynsym\0.dynstr\0.rela.dyn\0.rela.plt\0.plt\0.init_array\0.fini_array\0.dynamic\0.got.plt\0.shstrtab\0";

	Elf64_Shdr shdr[12];

	/* NULL */
	shdr[0].sh_name = 0;
	shdr[0].sh_type = SHT_NULL;
	shdr[0].sh_flags = 0;
	shdr[0].sh_addr = 0;
	shdr[0].sh_offset = 0;
	shdr[0].sh_size = 0;
	shdr[0].sh_link = 0;
	shdr[0].sh_info = 0;
	shdr[0].sh_addralign = 0;
	shdr[0].sh_entsize = 0;

	/* .interp */
	shdr[1].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".interp\0", 8) - shstrtab;
	shdr[1].sh_type = SHT_PROGBITS;
	shdr[1].sh_flags = SHF_ALLOC;
	shdr[1].sh_addr = interp.shdr.sh_addr;
	shdr[1].sh_offset = interp.shdr.sh_offset;
	shdr[1].sh_size = interp.shdr.sh_size;
	shdr[1].sh_link = 0;
	shdr[1].sh_info = 0;
	shdr[1].sh_addralign = 1;
	shdr[1].sh_entsize = 0;

	/* .shstrtab */
	shdr[2].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".shstrtab\0", 10) - shstrtab;;
	shdr[2].sh_type = SHT_STRTAB;
	shdr[2].sh_flags = 0;
	shdr[2].sh_addr = 0;
	shdr[2].sh_offset = data_seg.offset + data_seg.len;
	shdr[2].sh_size = sizeof(shstrtab);
	shdr[2].sh_link = 0;
	shdr[2].sh_info = 0;
	shdr[2].sh_addralign = 1;
	shdr[2].sh_entsize = 0;

	/* .dynstr */
	shdr[3].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".dynstr\0", 8) - shstrtab;
	shdr[3].sh_type = SHT_STRTAB;
	shdr[3].sh_flags = SHF_ALLOC;
	shdr[3].sh_addr = dynstr.shdr.sh_addr;
	shdr[3].sh_offset = dynstr.shdr.sh_offset;
	shdr[3].sh_size = dynstr.shdr.sh_size;
	shdr[3].sh_link = 0;
	shdr[3].sh_info = 0;
	shdr[3].sh_addralign = 1;
	shdr[3].sh_entsize = 0;

	/* .dynamic */
	shdr[4].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".dynamic\0", 9) - shstrtab;
	shdr[4].sh_type = SHT_DYNAMIC;
	shdr[4].sh_flags = SHF_ALLOC | SHF_WRITE; /* x86 specific */
	shdr[4].sh_addr = dynamic_seg.base;
	shdr[4].sh_offset = dynamic_seg.offset;
	shdr[4].sh_size = dynamic_seg.len;
	shdr[4].sh_link = 3; /* link to .dynstr */
	shdr[4].sh_info = 0;
	shdr[4].sh_addralign = 8;
	shdr[4].sh_entsize = sizeof(Elf64_Dyn);

	/* .init_array */
	shdr[5].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".init_array\0", 9) - shstrtab;
	shdr[5].sh_type = SHT_INIT_ARRAY;
	shdr[5].sh_flags = SHF_ALLOC | SHF_WRITE;
	shdr[5].sh_addr = init_array.shdr.sh_addr;
	shdr[5].sh_offset = init_array.shdr.sh_offset;
	shdr[5].sh_size = init_array.shdr.sh_size;
	shdr[5].sh_link = 0;
	shdr[5].sh_info = 0;
	shdr[5].sh_addralign = 8;
	shdr[5].sh_entsize = 8;

	/* .fini_array */
	shdr[6].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".fini_array\0", 9) - shstrtab;
	shdr[6].sh_type = SHT_FINI_ARRAY;
	shdr[6].sh_flags = SHF_ALLOC | SHF_WRITE;
	shdr[6].sh_addr = fini_array.shdr.sh_addr;
	shdr[6].sh_offset = fini_array.shdr.sh_offset;
	shdr[6].sh_size = fini_array.shdr.sh_size;
	shdr[6].sh_link = 0;
	shdr[6].sh_info = 0;
	shdr[6].sh_addralign = 8;
	shdr[6].sh_entsize = 8;

	/* .rela.plt */
	shdr[7].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".rela.plt\0", 10) - shstrtab;
	shdr[7].sh_type = SHT_RELA;
	shdr[7].sh_flags = SHF_ALLOC | SHF_INFO_LINK;
	shdr[7].sh_addr = pltrel.shdr.sh_addr;
	shdr[7].sh_offset = pltrel.shdr.sh_offset;
	shdr[7].sh_size = pltrel.shdr.sh_size;
	shdr[7].sh_link = 9; /* link to .dynsym */
	shdr[7].sh_info = 0;
	shdr[7].sh_addralign = 8;
	shdr[7].sh_entsize = pltrel.shdr.sh_entsize;

	/* .rela.dyn */
	shdr[8].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".rela.dyn\0", 10) - shstrtab;
	shdr[8].sh_type = SHT_RELA;
	shdr[8].sh_flags = SHF_ALLOC;
	shdr[8].sh_addr = reladyn.shdr.sh_addr;
	shdr[8].sh_offset = reladyn.shdr.sh_offset;
	shdr[8].sh_size = reladyn.shdr.sh_size;
	shdr[8].sh_link = 9; /* link to .dynsym */
	shdr[8].sh_info = 0;
	shdr[8].sh_addralign = 8;
	shdr[8].sh_entsize = reladyn.shdr.sh_entsize;

	/* .dynsym */
	shdr[9].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".dynsym\0", 8) - shstrtab;
	shdr[9].sh_type = SHT_DYNSYM;
	shdr[9].sh_flags = SHF_ALLOC;
	shdr[9].sh_addr = dynsym.shdr.sh_addr;
	shdr[9].sh_offset = dynsym.shdr.sh_offset;
	shdr[9].sh_size = 0; /* FIXME */
	shdr[9].sh_link = 3; /* link to .dynstr */
	shdr[9].sh_info = 0;
	shdr[9].sh_addralign = 8;
	shdr[9].sh_entsize = dynsym.shdr.sh_entsize;

	/* .got.plt */
	shdr[10].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".got.plt\0", 9) - shstrtab;
	shdr[10].sh_type = SHT_PROGBITS;
	shdr[10].sh_flags = SHF_ALLOC | SHF_WRITE;
	shdr[10].sh_addr = gotplt.shdr.sh_addr;
	shdr[10].sh_offset = gotplt.shdr.sh_offset; /* FIXME incorrect value */
	shdr[10].sh_size = sizeof(uint64_t) * 3 + (pltrel.shdr.sh_size / sizeof(Elf64_Rela)) * sizeof(uint64_t); /* x86-64 specific */
	shdr[10].sh_link = 0;
	shdr[10].sh_info = 0;
	shdr[10].sh_addralign = 8;
	shdr[10].sh_entsize = 8;

	/* .plt */
	shdr[11].sh_name = (uint8_t *)memmem(shstrtab, sizeof(shstrtab), ".plt\0", 5) - shstrtab;
	shdr[11].sh_type = SHT_PROGBITS;
	shdr[11].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	shdr[11].sh_addr = plt.shdr.sh_addr;
	shdr[11].sh_offset = plt.shdr.sh_offset;
	shdr[11].sh_size = 0x10 + (pltrel.shdr.sh_size / sizeof(Elf64_Rela)) * 0x10;
	shdr[11].sh_link = 0;
	shdr[11].sh_info = 0;
	shdr[11].sh_addralign = 16;
	shdr[11].sh_entsize = 0x10;

	/* TODO .text, .data */

	ehdr->e_shnum = sizeof(shdr) / sizeof(Elf64_Shdr);
	ehdr->e_shstrndx = 2;

	/* text segment */
	printf("[+] Writing text segment at 0x%x\n", 0);
	fwrite(text_seg.buf, 1, text_seg.len, f);

	/* data segment */
	printf("[+] Writing data segment at 0x%x\n", data_seg.offset);
	fseek(f, data_seg.offset, SEEK_SET);
	fwrite(data_seg.buf, 1, data_seg.len, f);

	/* shstrtab */
	printf("[+] Writing shstrtab at 0x%x\n", data_seg.offset + data_seg.len);
	fwrite(shstrtab, 1, sizeof(shstrtab), f);

	/* section header table */
	printf("[+] Writing section header table at 0x%x\n", ehdr->e_shoff);
	fseek(f, ehdr->e_shoff, SEEK_SET);
	fwrite(shdr, 1, sizeof(shdr), f);

	fclose(f);
}

