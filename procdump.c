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

	struct section pltrel = {0};
	struct section plt = {0};
	struct section gotplt = {0};
	struct section dynstr = {0};
	struct section dynsym = {0};

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
		case DT_PLTGOT:
			printf("[+] Found GOT at 0x%x\n", dynamic[i].d_un.d_ptr);
			gotplt.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			gotplt.shdr.sh_offset = dynamic[i].d_un.d_ptr;
			/* TODO check if GOT lives in the data segment */
			gotplt.buf = &data_seg.buf[gotplt.shdr.sh_addr - data_seg.base];
			break;
		case DT_SYMTAB:
			dynsym.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			dynsym.shdr.sh_offset = dynsym.shdr.sh_addr - text_seg.base;
			printf("Found dynsym at 0x%x\n", dynsym.shdr.sh_addr);
			break;
		case DT_SYMENT:
			dynsym.shdr.sh_size = dynamic[i].d_un.d_val;
			printf("Found syment: 0x%x\n", dynsym.shdr.sh_size);
			break;
		case DT_STRTAB:
			dynstr.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			dynstr.shdr.sh_offset = dynstr.shdr.sh_addr - text_seg.base;
			dynstr.buf = &text_seg.buf[dynstr.shdr.sh_offset];
			printf("Found dynstr at 0x%x\n", dynstr.shdr.sh_addr);
			break;
		case DT_JMPREL:
			pltrel.shdr.sh_addr = dynamic[i].d_un.d_ptr;
			pltrel.shdr.sh_offset = pltrel.shdr.sh_addr - text_seg.base;
			printf("JMPREL at: 0x%x\n", dynamic[i].d_un.d_ptr);
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
		case DT_PLTRELSZ:
			pltrel.shdr.sh_size = dynamic[i].d_un.d_ptr;
			printf("PLTRELSZ = %d\n", dynamic[i].d_un.d_val);
			break;
		case DT_STRSZ:
			dynstr.shdr.sh_size = dynamic[i].d_un.d_ptr;
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
		}
		ptr++;
	}

	if (!plt.buf) {
		fprintf(stderr, "Could not find PLT-0\n");
		exit(EXIT_FAILURE);
	}

	/* Restore GOT entries */
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

	/* text segment */
	printf("[+] Writing text segment at 0x%x\n", 0);
	fwrite(text_seg.buf, 1, text_seg.len, f);

	/* data segment */
	printf("[+] Writing data segment at 0x%x\n", data_seg.offset);
	fseek(f, data_seg.offset, SEEK_SET);
	fwrite(data_seg.buf, 1, data_seg.len, f);

	/* dynamic segment */
	printf("[+] Writing dynamic segment at 0x%x\n", dynamic_seg.offset);
	fseek(f, dynamic_seg.offset, SEEK_SET);
	fwrite(dynamic_seg.buf, 1, dynamic_seg.len, f);

	fclose(f);
}

