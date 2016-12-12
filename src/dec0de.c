/*****************************************************************************
 *
 * $DEC0DE v1.0 by Orion from The Replicants & Fuzion, Dec 2016.
 *
 * Remove encryption systems used to protect GEMDOS programs.
 *
 * This source file can be compiled on any Operating System supporting gcc.
 * For non-Linux systems, the following gcc ports are available:
 * - gcc for Mac OS X   https://github.com/kennethreitz/osx-gcc-installer
 * - gcc for Windows    http://www.mingw.org
 * - gcc for Atari      http://vincent.riviere.free.fr/soft/m68k-atari-mint
 *
 * Depending on the target Operating System, run gcc as follows:
 * - For Linux:
 *   # gcc -O -Wall -Wextra -m32 -static dec0de.c -o dec0de
 * - For Mac OS X:
 *   # gcc -O -Wall -Wextra -mmacosx-version-min=10.5 dec0de.c -o dec0de
 * - For Windows:
 *   # gcc -O -Wall -Wextra -std=c99 dec0de.c -o dec0de.exe
 * - For Atari ST:
 *   # m68k-atari-mint-gcc -O -Wall -Wextra dec0de.c -o dec0de.prg
 *   or
 *   # m68k-atari-mint-gcc -O -Wall -Wextra dec0de.c -o dec0de.ttp
 *
 * On Linux, Mac or Windows, run the resulting program from the command prompt.
 * To obtain usage information, run the program as follows:
 * # dec0de -h
 *
 * On Atari ST, launch dec0de.prg or dec0de.ttp from the GEM desktop.
 * dec0de.prg provides an interactive mode, while dec0de.ttp expects
 * parameters to be provided through the command line.
 *
 * Version history:
 * - v1.0, Dec 2016, Initial version.
 *   Supports:
 *   NTM/Cameo Toxic Packer v1.0,
 *   R.AL Little protection v01 & Megaprot v0.02,
 *   Orion Sly packer v2.0,
 *   Cameo Cooper v0.5 & v0.6,
 *   Illegal Anti-bitos v1.0, v1.4 (a & b), v1.6 & v1.61,
 *   Zippy Little protection v2.05 & v2.06,
 *   Yoda Lock-o-matic v1.3.
 *
 *****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>

/*****************************************************************************
 * Declarations & macros
 *****************************************************************************/

#define DEC0DE_NAME		"DEC0DE"

#define DEC0DE_VERSION		"1.0"

#define DEC0DE_DATE		"Dec 2016"

#define DEC0DE_BANNER						\
    "$" DEC0DE_NAME " v" DEC0DE_VERSION				\
    " by Orion from The Replicants & Fuzion, "			\
    DEC0DE_DATE ".\n"

#if defined(__atarist__)
#define TARGET_ST
#else
#undef  TARGET_ST
#endif

/* For compatibility with Windows open() */
#ifndef O_BINARY
#define O_BINARY		0
#endif

#define LOG_INFO(_f, _a...)					\
    do {							\
	fprintf(stdout, _f, ##_a);				\
	fflush(stdout);						\
    } while (0)

#define LOG_ERROR(_f, _a...)					\
    do {							\
	fprintf(stderr, _f, ##_a);				\
	fflush(stderr);						\
    } while (0)

#define LOG_WARN(_f, _a...)					\
    do {							\
	fprintf(stderr, _f, ##_a);				\
	fflush(stderr);						\
    } while (0)

#define ASSERT(_a)						\
    do {							\
	if (!(_a)) {						\
	    LOG_ERROR("Assertion failed at %s:%d\n",		\
		      __FUNCTION__, __LINE__);			\
	    abort();						\
	}							\
    } while (0)

#define MARKER_MAGIC		0xdec0de10

/*
 * Protection identification pattern.
 */
typedef struct pattern_t {
    size_t         offset;
    size_t         count;
    unsigned char  buf[];
} pattern_t;

/*
 * Protection description.
 */
typedef struct prot_t {
    const char*    name;
    size_t         offset;
    pattern_t**    patterns;
    int          (*dec0de) (unsigned char* buf, size_t size);
} prot_t;

/*
 * Program description.
 */
typedef struct prog_t {
    char*          name;
    size_t         size;
    size_t         size_orig;
    prot_t*        prot;
    unsigned char* marker;
    unsigned char  buf[];
} prog_t;

/*
 * GEMDOS program header.
 *
 * See http://toshyp.atari.org/en/005005.html
 */
typedef struct prog_hdr_t {
    uint8_t ph_branch[2];	/* WORD: branch to start of the program  */
				/*       (must be 0x601a!)               */
    uint8_t ph_tlen[4];		/* LONG: length of the TEXT segment      */
    uint8_t ph_dlen[4];		/* LONG: length of the DATA segment      */
    uint8_t ph_blen[4];		/* LONG: length of the BSS segment       */
    uint8_t ph_slen[4];		/* LONG: length of the symbol table      */
    uint8_t ph_res1[4];		/* LONG: reserved, should be 0           */
				/*       (required by PureC)             */
    uint8_t ph_prgflags[4];	/* LONG: program flags                   */
    uint8_t ph_absflag[2];	/* WORD: 0 = relocation info present     */
} prog_hdr_t;

/*****************************************************************************
 * Platform-specific behavior
 *****************************************************************************/

#if defined(TARGET_ST)

static int  prog_atstart (void);
static void prog_atexit  (void);

static int  ia_mode_avail (void);
static int  ia_mode_enter (void);

static int  key_wait (void);

/*
 * VT-52 Terminal Control Sequences.
 *
 * See http://toshyp.atari.org/en/VT_52_terminal.html#VT-52_20terminal
 */

#define CLEAR_HOME		"\33E"
#define REV_ON			"\33p"
#define REV_OFF			"\33q"
#define CUR_OFF			"\33f"
#define WRAP_ON			"\33v"

#define PP_LINEBRK		"\n"

#define IA_MODE_AVAIL()		ia_mode_avail()
#define IA_MODE_ENTER()		ia_mode_enter()

#define PROG_ATSTART()		prog_atstart()
#define PROG_ATEXIT()		prog_atexit()

#define PROG_NAME(_a)						\
    ({								\
	static const char* _pname = DEC0DE_NAME;		\
	(void) (_a);						\
	_pname;							\
    })

#define LOG_INFO_MORE(_t)					\
    do {							\
	LOG_INFO(_t);						\
	LOG_INFO(REV_ON "Press any key to continue" REV_OFF);	\
	key_wait();						\
	LOG_INFO(CLEAR_HOME);					\
    } while (0)

#else /* !TARGET_ST */

#define PP_LINEBRK		""

#define IA_MODE_AVAIL()		({ 0; })
#define IA_MODE_ENTER()		({ 1; })

#define PROG_ATSTART()		({ 0; })
#define PROG_ATEXIT()		do { } while (0)

#define PROG_NAME(_a)		((_a)[0])

#define LOG_INFO_MORE(_t)	LOG_INFO(_t)

#endif /* !TARGET_ST */

/*****************************************************************************
 * Dec0ding helper routines
 *****************************************************************************/

#define SIZE_32		sizeof(uint32_t)

static inline uint32_t read32 (unsigned char* buf)
{
    uint32_t w32;

#if defined(TARGET_ST)
    w32  = *(uint32_t*) buf;
#else
    w32  = 0;
    w32 |= (((uint32_t) buf[0]) << 24);
    w32 |= (((uint32_t) buf[1]) << 16);
    w32 |= (((uint32_t) buf[2]) <<  8);
    w32 |= (((uint32_t) buf[3]) <<  0);
#endif

    return w32;
}

static inline void write32 (uint32_t w32, unsigned char* buf)
{
#if defined(TARGET_ST)
    *(uint32_t*) buf = w32;
#else
    buf[0] = (unsigned char) ((w32 >> 24) & 0xff);
    buf[1] = (unsigned char) ((w32 >> 16) & 0xff);
    buf[2] = (unsigned char) ((w32 >>  8) & 0xff);
    buf[3] = (unsigned char) ((w32 >>  0) & 0xff);
#endif
}

#define SIZE_16		sizeof(uint16_t)

static inline uint16_t read16 (unsigned char* buf)
{
    uint16_t w16;

#if defined(TARGET_ST)
    w16  = *(uint16_t*) buf;
#else
    w16  = 0;
    w16 |= (((uint16_t) buf[0]) << 8);
    w16 |= (((uint32_t) buf[1]) << 0);
#endif

    return w16;
}

static inline void write16 (uint16_t w16, unsigned char* buf)
{
#if defined(TARGET_ST)
    *(uint16_t*) buf = w16;
#else
    buf[0] = (unsigned char) ((w16 >> 8) & 0xff);
    buf[1] = (unsigned char) ((w16 >> 0) & 0xff);
#endif
}

#define SIZE_8		sizeof(uint8_t)

static inline uint8_t read8 (unsigned char* buf)
{
    return (uint8_t) buf[0];
}

static inline void write8 (uint8_t w8, unsigned char* buf)
{
    buf[0] = (unsigned char) w8;
}

#define BIT(_b)		(1 << (_b))

#define ROR32(_w32,_b)							      \
    ((((_w32) & ((uint32_t)  (BIT(_b) - 1))) << (32 - (_b))) |		      \
     (((_w32) & ((uint32_t) ~(BIT(_b) - 1))) >> (_b)))

#define ROL32(_w32,_b)							      \
    ((((_w32) & ((uint32_t)  ((BIT(_b) - 1) << (32 - (_b))))) >> (32 - (_b)))|\
     (((_w32) & ((uint32_t) ~((BIT(_b) - 1) << (32 - (_b))))) << (_b)))

#define ROR16(_w16,_b)							      \
    ((((_w16) & ((uint16_t)  (BIT(_b) - 1))) << (16 - (_b))) |		      \
     (((_w16) & ((uint16_t) ~(BIT(_b) - 1))) >> (_b)))

#define ROL16(_w16,_b)							      \
    ((((_w16) & ((uint16_t)  ((BIT(_b) - 1) << (16 - (_b))))) >> (16 - (_b)))|\
     (((_w16) & ((uint16_t) ~((BIT(_b) - 1) << (16 - (_b))))) << (_b)))

#define ROR8(_w8,_b)							      \
    ((((_w8) & ((uint8_t)  (BIT(_b) - 1))) << (8 - (_b))) |		      \
     (((_w8) & ((uint8_t) ~(BIT(_b) - 1))) >> (_b)))

#define ROL8(_w8,_b)							      \
    ((((_w8) & ((uint8_t)  ((BIT(_b) - 1) << (8 - (_b))))) >> (8 - (_b))) |   \
     (((_w8) & ((uint8_t) ~((BIT(_b) - 1) << (8 - (_b))))) << (_b)))

#define SWAP32(_w32)							      \
    ((((_w32) & (uint32_t) 0xffff0000) >> 16) |				      \
     (((_w32) & (uint32_t) 0x0000ffff) << 16))

#define NEG8(_w8)	(((uint8_t) 0) - (_w8))

#define NEG16(_w16)	(((uint16_t) 0) - (_w16))

#define NEG32(_w32)	(((uint32_t) 0) - (_w32))

#define DBF_SIZE8(_s)	((((uint32_t)(_s)) & (uint32_t) 0x0000ffff) + 1)

#define DBF_SIZE16(_s)	((((uint32_t)(_s)) & (uint32_t) 0x0001ffff) + 1)

#define DBF_SIZE32(_s)	((((uint32_t)(_s)) & (uint32_t) 0x0003ffff) + 1)

/*****************************************************************************
 * Program loading, fixup & saving
 *****************************************************************************/

static void release_prog (prog_t* prog)
{
    if (prog->name) {
	free(prog->name);
    }
    free(prog);
}

static prog_t* load_prog (const char* name)
{
    int            fd;
    off_t          off;
    ssize_t        sz;
    size_t         sz_buf;
    size_t         count;
    prog_t*        prog = NULL;
    unsigned char* buf;

    fd = open(name, O_BINARY | O_RDONLY);
    if (fd == -1) {
	LOG_ERROR("Cannot open file '%s': %s\n", name, strerror(errno));
	return NULL;
    }

    off = lseek(fd, 0, SEEK_END);
    if (off == (off_t) -1) {
	LOG_ERROR("Cannot seek to end of file '%s': %s\n",
		  name, strerror(errno));
	goto err;
    }

    /*
     * Allocate an extra 32-bits word for safely allowing buffer overflow:
     * - when creating a fixup (relocation table) offset.
     * - when decrypting the last word (overflow may happen if file size and
     *   decrypted word size are not compatible).
     *
     * Allocate another extra 32-bits word as a marker used to detect
     * unexpected buffer overflow.
     */
    sz_buf  = (((size_t) off) + (SIZE_32 - 1)) & ~(SIZE_32 - 1);
    sz_buf += 2 * SIZE_32;
    prog    = malloc(sz_buf + sizeof(prog_t));
    if (!prog) {
	LOG_ERROR("Cannot allocate a program buffer of %zu bytes\n",
		  sz_buf + sizeof(prog_t));
	goto err;
    }
    memset(prog, 0, sizeof(prog_t));

    prog->name = malloc(strlen(name) + 1);
    if (!prog->name) {
	LOG_ERROR("Cannot allocate a name string of %zu bytes\n",
		  strlen(name) + 1);
	goto err;
    }
    strcpy(prog->name, name);

    prog->size   = (size_t) off;
    prog->marker = prog->buf + sz_buf - SIZE_32;

    off = lseek(fd, 0, SEEK_SET);
    if (off == (off_t) -1) {
	LOG_ERROR("Cannot seek to start of file '%s': %s\n",
		  name, strerror(errno));
	goto err;
    }

    count = prog->size;
    buf   = prog->buf;

    do {
	sz = read(fd, buf, count);
	if (sz == (ssize_t) -1) {
	    if (errno == EINTR) {
		continue;
	    }
	    LOG_ERROR("Failed to read %zu bytes from file '%s': %s\n",
		      count, name, strerror(errno));
	    goto err;
	}
	count -= (size_t) sz;
	buf   += sz;
    } while (count && sz);

    if (count) {
	LOG_ERROR("Unexpected EOF while reading from file '%s', file size=%zu"
		  " bytes, unread bytes=%zu, last read result=%zd\n",
		  name, prog->size, count, (size_t) sz);
	goto err;
    }

    while (buf != prog->marker) {
	*buf = '\0';
	buf++;
    }
    write32(MARKER_MAGIC, prog->marker);

    if (read16(prog->buf) != (uint16_t) 0x601a) {
	LOG_ERROR("File '%s' is not a valid GEMDOS program\n", name);
	goto err;
    }

ret:
    (void) close(fd);

    return prog;

err:
    if (prog) {
	release_prog(prog);
	prog = NULL;
    }

    goto ret;
}

static int save_prog (prog_t* prog, const char* name)
{
    unsigned char* buf;
    size_t         count;
    ssize_t        sz;
    int            fd;

    ASSERT(prog->prot && prog->size_orig);

    fd = open(name, O_BINARY | O_RDWR | O_CREAT | O_EXCL, 0666);
    if (fd == -1) {
	LOG_ERROR("Cannot create file '%s': %s\n", name, strerror(errno));
	return 1;
    }

    buf   = prog->buf + prog->prot->offset;
    count = prog->size_orig;

    while (count) {
	sz = write(fd, buf, count);
	if (sz == (ssize_t) -1) {
	    if (errno == EINTR) {
		continue;
	    }
	    LOG_ERROR("Failed to write %zu bytes to file '%s': %s\n",
		      count, name, strerror(errno));
	    goto err;
	}
	count -= (size_t) sz;
	buf   += sz;
    }

    (void) close(fd);

    return 0;

err:
    (void) close(fd);
    (void) unlink(name);

    return 1;
}

static void dump_hdr (prog_t* prog, size_t offset)
{
    unsigned char* buf = prog->buf + offset;
    unsigned int   i;

    LOG_ERROR("File size: %zu bytes\n", prog->size);
    LOG_ERROR("Original program offset: %zu bytes\n", prog->prot->offset);
    LOG_ERROR("Original program size: %zu bytes\n",
	      prog->size - prog->prot->offset);
    LOG_ERROR("Dec0ded header: ");
    for (i = 0; i < (unsigned int) sizeof(prog_hdr_t); i++) {
	LOG_ERROR("%02x", (unsigned int) buf[i]);
    }
    LOG_ERROR("\n");
}

static int fixup_prog (prog_t* prog)
{
    unsigned char* buf;
    prog_hdr_t*    hdr;
    size_t         offset;
    size_t         sz_file;
    size_t         sz_text;
    size_t         sz_data;
    size_t         sz_bss;
    size_t         sz_symb;
    size_t         sz;
    size_t         i;
    uint32_t       res1;

    ASSERT(sizeof(prog_hdr_t) == 28);
    ASSERT(prog->prot);

    offset  = prog->prot->offset;
    buf     = prog->buf + offset;
    hdr     = (prog_hdr_t*) buf;
    sz_file = prog->size - offset;

    /*
     * The program size must be greater than the GEMDOS header size.
     */
    if ((ssize_t) sz_file < (ssize_t) sizeof(prog_hdr_t)) {
	LOG_ERROR("Invalid original program size=%zu bytes\n", sz_file);
	return 1;
    }

    /*
     * Check for unexpected buffer overflow during decrypting.
     */
    if (read32(prog->marker) != (uint32_t) MARKER_MAGIC) {
	LOG_ERROR("Buffer overflow detected after dec0ding program\n");
	return 1;
    }

    sz_text = (size_t) read32((unsigned char*)&hdr->ph_tlen);
    sz_data = (size_t) read32((unsigned char*)&hdr->ph_dlen);
    sz_bss  = (size_t) read32((unsigned char*)&hdr->ph_blen);
    sz_symb = (size_t) read32((unsigned char*)&hdr->ph_slen);

    /*
     * Check text size.
     */
    if (sz_text > sz_file - sizeof(prog_hdr_t)) {
	LOG_ERROR("Invalid text size=%zu bytes\n", sz_text);
	goto dump;
    }

    /*
     * Check data size.
     */
    if (sz_data > sz_file - sizeof(prog_hdr_t)) {
	LOG_ERROR("Invalid data size=%zu bytes\n", sz_data);
	goto dump;
    }

    /*
     * Check symbols size.
     */
    if (sz_symb > sz_file - sizeof(prog_hdr_t)) {
	LOG_ERROR("Invalid symbols size=%zu bytes\n", sz_symb);
	goto dump;
    }

    /*
     * Check bss size.
     */
    if (sz_bss > (8 * 1024 * 1024)) {
	LOG_ERROR("Invalid bss size=%zu bytes\n", sz_bss);
	goto dump;
    }

    /*
     * Check reserved field.
     */
    res1 = read32((unsigned char*)&hdr->ph_res1);
    if (res1 != 0) {
	LOG_WARN("Warning: unexpected non-null reserved field=0x%08x\n", res1);
    }

    /*
     * Check aggregated size (header + text + data + symbols).
     */
    sz = sizeof(prog_hdr_t) + sz_text + sz_data + sz_symb;

    if (sz > sz_file) {
	LOG_ERROR("Invalid aggregated size=%zu bytes\n", sz);
	goto dump;
    }

    /*
     * Check relocation table (fixups).
     */
    if (read16((unsigned char*)&hdr->ph_absflag) == 0) {
	uint32_t rel_off;
	uint8_t  off8;
	/*
	 * ph_absflag is null, a relocation table may be present.
	 */
	if (sz + SIZE_32 > sz_file) {
	    LOG_ERROR("Truncated starting fixup offset\n");
	    goto dump;
	}
	/*
	 * A non-zero fixup offset indicates that a relocation table is
	 * actually present.
	 */
	rel_off = read32(buf + sz);
	sz     += SIZE_32;
	if (rel_off != (uint32_t) 0) {
	    /*
	     * Check relocation table entries.
	     */
	    if ((rel_off & 0x1) ||
		(rel_off + (uint32_t) SIZE_32 >
		 (uint32_t) (sz_text + sz_data))) {
		LOG_ERROR("Invalid starting fixup offset=0x%x\n",
			  (unsigned int) rel_off);
		goto dump;
	    }
	    do {
		if (sz + SIZE_8 > sz_file) {
		    LOG_ERROR("Truncated relocation table\n");
		    goto dump;
		}
		off8 = read8(buf + sz);
		sz  += SIZE_8;
		if (off8 == 1) {
		    rel_off += (uint32_t) 254;
		} else if (off8 & 0x1) {
		    LOG_ERROR("Invalid (odd) 8-bits fixup offset\n");
		    goto dump;
		} else {
		    rel_off += (uint32_t) off8;
		}
		if (rel_off + (uint32_t) SIZE_32 >
		    (uint32_t) (sz_text + sz_data)) {
		    LOG_ERROR("Invalid fixup offset=0x%x\n",
			      (unsigned int) rel_off);
		    goto dump;
		}
	    } while (off8 != (uint8_t) 0);
	}
    } else {
	/*
	 * ph_absflag is not null, there is no relocation table.
	 *
	 * Some TOS handle files with ph_absflag being non-zero incorrectly.
	 * Therefore it is better to represent a program having no fixups
	 * with a null ph_absflag and a null 32-bits word as the fixup offset.
	 */
	write16(0, (unsigned char*)&hdr->ph_absflag);
	write32(0, buf + sz);
	/*
	 * Buffer overflow is safely handled here since an extra 32-bits word
	 * has been provisioned at buffer allocation time.
	 */
	sz += SIZE_32;
    }

    for (i = 0; (ssize_t)i < (ssize_t)(sz_file - sz); i++) {
	write8('\0', buf + sz + i);
    }

    /*
     * Some crypters may corrupt the branch value, reset it explicitly.
     */
    write16(0x601a, (unsigned char*)&hdr->ph_branch);

    /*
     * Save the actual size of the GEMDOS program.
     */
    prog->size_orig = sz;

    return 0;

dump:
    LOG_ERROR("Program dec0ding failed!\n");
    dump_hdr(prog, offset);
    return 1;
}

/*****************************************************************************
 * Toxic Packer v1.0 by NTM/Cameo from The Replicants
 *****************************************************************************/

#define TP1_OFF 0x20e

static int dec0de_tp1 (unsigned char* buf, size_t size)
{
    uint32_t key32 = 0xbabebabe;
    uint16_t key16;
    uint16_t w16;
    size_t   i;

    for (i = 0; i < size; i += SIZE_16) {
	w16    = read16(buf + i);

	w16   ^= (uint16_t) (key32 & (uint32_t) 0x0000ffff);

	key16  = (uint16_t) (key32 & (uint32_t) 0x0000ffff);
	key16  = ROR16(key16, 3);
	key16 += 0x9876;

	key32  = (key32 & (uint32_t) 0xffff0000) | (uint32_t) key16;
	key32  = ROR32(key32, 2);

	write16(w16, buf + i);
    }

    return 0;
}

static pattern_t pattern1_tp1 = {
    0xb0,
    80,
    {
	0x42, 0xb9, 0x00, 0xff, 0xfa, 0x06, 0x2b, 0x47,
	0x00, 0x24, 0x2b, 0x47, 0x00, 0x10, 0xe4, 0x98,
	0xd0, 0xad, 0x00, 0x24, 0x90, 0xad, 0x00, 0x10,
	0x46, 0x79, 0x00, 0xff, 0x82, 0x40, 0x4e, 0x73,
	0x20, 0x3c, 0x12, 0x34, 0x56, 0x78, 0x41, 0xfa,
	0x01, 0x36, 0x43, 0xfa, 0x2d, 0xf2, 0x20, 0x2a,
	0x00, 0x24, 0xb1, 0x58, 0xe6, 0x58, 0x06, 0x40,
	0x98, 0x76, 0x4e, 0x42, 0xb3, 0xc8, 0x6c, 0x00,
	0xff, 0xf2, 0x21, 0xf8, 0x02, 0x00, 0x00, 0x68,
	0x23, 0xf8, 0x02, 0x04, 0x00, 0xff, 0xfa, 0x06,
    },
};

static pattern_t* patterns_tp1[] = {
    &pattern1_tp1,
    NULL,
};

static prot_t prot_tp1 = {
    .name     = "Toxic Packer v1.0 by NTM/Cameo from The Replicants",
    .offset   = TP1_OFF,
    .patterns = patterns_tp1,
    .dec0de   = dec0de_tp1,
};

/*****************************************************************************
 * Little protection v01 by R.AL from The Replicants
 * Supposedly installed by the Toxic Packer v2.0 by NTM/Cameo
 * from The Replicants
 *****************************************************************************/

#define RAL_LP_OFF 0x372

static int dec0de_ral_lp (unsigned char* buf, size_t size)
{
    uint32_t key32 = 0x6085c752;
    uint16_t w16;
    size_t   i;

    for (i = 0; i < size; i += SIZE_16) {
	key32  = (key32 & (uint32_t) 0x0000ffff) * (uint32_t) 0x00003141;
	key32 += 1;

	w16    = read16(buf + i);

	w16   ^= (uint16_t) (key32 & (uint32_t) 0x0000ffff);

	write16(w16, buf + i);
    }

    return 0;
}

static pattern_t pattern1_ral_lp = {
    0x58,
    56,
    {
	0x11, 0xd8, 0x00, 0x7f, 0xd0, 0xb8, 0x00, 0x7c,
	0xb1, 0xfc, 0x00, 0x00, 0x35, 0x3a, 0x6d, 0x04,
	0x41, 0xf8, 0x32, 0x00, 0xd0, 0xb8, 0x00, 0x24,
	0xd0, 0xaf, 0x00, 0x02, 0x00, 0x57, 0xa7, 0x10,
	0x4e, 0x73, 0x42, 0x80, 0x42, 0xb8, 0x00, 0x7c,
	0x41, 0xf8, 0x32, 0x00, 0x21, 0xfc, 0x00, 0x00,
	0x32, 0x22, 0x00, 0x24, 0x46, 0xfc, 0xa7, 0x00,
    },
};

static pattern_t* patterns_ral_lp[] = {
    &pattern1_ral_lp,
    NULL,
};

static prot_t prot_ral_lp = {
    .name     = "Little protection v01 by R.AL from The Replicants",
    .offset   = RAL_LP_OFF,
    .patterns = patterns_ral_lp,
    .dec0de   = dec0de_ral_lp,
};

/*****************************************************************************
 * Megaprot v0.02 by R.AL from The Replicants
 * Installed by the Toxic Packer v3.0 by NTM/Cameo from The Replicants
 *****************************************************************************/

#define RAL_MP_OFF 0x83e

static int dec0de_ral_mp (unsigned char* buf, size_t size)
{
    uint32_t key32 = 0xe45d2af8;
    uint32_t w32;
    uint32_t bit1;
    uint32_t bit21;
    size_t   i;

    for (i = 0; i < size; i += SIZE_32) {
	key32 <<= 1;

	bit1   = (key32 & (uint32_t) BIT(1)) >>  1;
	bit21  = (key32 & (uint32_t) BIT(21)) >> 21;

	if (bit1 != bit21) {
	    key32 += 1;
	}

	w32    = read32(buf + i);

	w32   += key32;

	key32 += w32;

	write32(w32, buf + i);
    }

    return 0;
}

static pattern_t pattern1_ral_mp = {
    0x52,
    50,
    {
	0x20, 0x78, 0x04, 0x26, 0x20, 0xb8, 0x04, 0x2a,
	0x20, 0x6f, 0x00, 0x02, 0x21, 0xc8, 0x04, 0x26,
	0x21, 0xd0, 0x04, 0x2a, 0x20, 0x28, 0xff, 0xfc,
	0x46, 0x80, 0x48, 0x40, 0xb1, 0x90, 0x4e, 0x73,
	0x41, 0xfa, 0xff, 0xde, 0x21, 0xc8, 0x00, 0x24,
	0x41, 0xfa, 0xff, 0xc8, 0x21, 0xc8, 0x00, 0x10,
	0x4a, 0xfc,
    },
};

static pattern_t pattern2_ral_mp = {
    0x836,
    8,
    {
	0x63, 0x73, 0x97, 0xeb, 0xd8, 0x13, 0xd2, 0xfa,
    },
};

static pattern_t* patterns_ral_mp[] = {
    &pattern1_ral_mp,
    &pattern2_ral_mp,
    NULL,
};

static prot_t prot_ral_mp = {
    .name     = "Megaprot v0.02 by R.AL from The Replicants",
    .offset   = RAL_MP_OFF,
    .patterns = patterns_ral_mp,
    .dec0de   = dec0de_ral_mp,
};

/*****************************************************************************
 * Sly packer v2.0 by Orion from The Replicants
 *****************************************************************************/

#define SLY_OFF 0x73c

static int calc_rand_sly (unsigned char* buf, uint16_t* rand)
{
    uint32_t w32;
    uint16_t rand16;

    w32    = read32(buf - SLY_OFF + 0x698);
    w32    = w32 ^ (uint32_t) 0xbbb7dc8a;

    rand16 = (uint16_t) (w32 & (uint32_t) 0x0000ffff);

    *rand  = rand16;

    return 0;
}

static int dec0de_sly (unsigned char* buf, size_t size)
{
    uint32_t key32;
    uint16_t rand16;
    uint16_t w16;
    size_t   i;

    if (calc_rand_sly(buf, &rand16)) {
	LOG_ERROR("Cannot determine random number\n");
	return 1;
    }

    key32 = 0x9cf142b3;

    key32 = key32 ^ (uint32_t) rand16;

    for (i = 0; i < size; i += SIZE_16) {

	w16    = read16(buf + i);

	rand16 = ~rand16;

	key32  = key32 + (uint32_t) rand16;

	w16    = (~w16) ^ (uint16_t) (key32 & (uint32_t) 0x0000ffff);

	key32  = SWAP32(key32);

	write16(w16, buf + i);
    }

    return 0;
}

static pattern_t pattern1_sly = {
    0xc8,
    28,
    {
	0x41, 0xf8, 0x82, 0x09, 0x10, 0x10, 0x12, 0x10,
	0xb2, 0x00, 0x67, 0xfa, 0x02, 0x01, 0x00, 0x1f,
	0x94, 0x01, 0xe5, 0x29, 0x4f, 0xf8, 0x00, 0x14,
	0x46, 0xfc, 0xff, 0xff,
    },
};

static pattern_t pattern2_sly = {
    0x6fe,
    22,
    {
	0xd0, 0xb8, 0x00, 0x24, 0xb3, 0x80, 0x48, 0x40,
	0x51, 0xca, 0xff, 0xf4, 0xb1, 0x91, 0x4c, 0xf8,
	0x07, 0x07, 0x00, 0x40, 0x4e, 0x73,
    },
};

static pattern_t* patterns_sly[] = {
    &pattern1_sly,
    &pattern2_sly,
    NULL,
};

static prot_t prot_sly = {
    .name     = "Sly packer v2.0 by Orion from The Replicants",
    .offset   = SLY_OFF,
    .patterns = patterns_sly,
    .dec0de   = dec0de_sly,
};

/*****************************************************************************
 * Cooper v0.5 by Cameo from The Replicants
 *****************************************************************************/

#define COOPER5_OFF 0x6ec

static int calc_rand_cooper5 (unsigned char* buf, uint16_t* rand)
{
    uint32_t w32;
    uint16_t rand16;

    w32    = read32(buf - COOPER5_OFF + 0x3c2);

    w32   ^= (uint32_t) 0x0b364000;

    rand16 = (uint16_t) 0x1c86 + (uint16_t) (w32 & (uint32_t) 0x0000ffff);

    *rand  = rand16;

    return 0;
}

static int dec0de_cooper5 (unsigned char* buf, size_t size)
{
    uint32_t key32;
    uint16_t rand16;
    uint8_t  w8;
    size_t   i;

    if (calc_rand_cooper5(buf, &rand16)) {
	LOG_ERROR("Cannot determine random number\n");
	return 1;
    }

    key32 = 0x616a6178;

    for (i = 0; i < size; i += SIZE_8) {

	w8    = read8(buf + i);

	w8    = w8 ^ (uint8_t) (key32 & (uint32_t) 0x000000ff);

	key32 = key32 + (uint32_t) rand16;

	key32 = SWAP32(key32);

	write8(w8, buf + i);
    }

    return 0;
}

static pattern_t pattern1_cooper5 = {
    0x63c,
    38,
    {
	0x20, 0x78, 0x00, 0x24, 0xd0, 0xe8, 0x00, 0x02,
	0x7c, 0x45, 0x42, 0xb8, 0x00, 0x10, 0x42, 0xb8,
	0xfa, 0x06, 0x49, 0xd0, 0xbb, 0x58, 0x51, 0xce,
	0xff, 0xfc, 0x60, 0x08, 0x7c, 0x45, 0xbb, 0x5c,
	0x51, 0xce, 0xff, 0xfc, 0x4e, 0x73,
    },
};

static pattern_t pattern2_cooper5 = {
    0x152,
    18,
    {
	0xdb, 0x97, 0x22, 0x97, 0x23, 0x57, 0x00, 0x0c,
	0x3e, 0x93, 0x06, 0x57, 0x0b, 0xe7, 0x46, 0xfc,
	0xff, 0xff,
    },
};

static pattern_t* patterns_cooper5[] = {
    &pattern1_cooper5,
    &pattern2_cooper5,
    NULL,
};

static prot_t prot_cooper5 = {
    .name     = "Cooper v0.5 by Cameo from The Replicants",
    .offset   = COOPER5_OFF,
    .patterns = patterns_cooper5,
    .dec0de   = dec0de_cooper5,
};

/*****************************************************************************
 * Cooper v0.6 by Cameo from The Replicants
 *****************************************************************************/

#define COOPER6_OFF 0x79e

static int calc_rand_cooper6 (unsigned char* buf, uint16_t* rand)
{
    uint32_t w32;
    uint16_t rand16;

    w32    = read32(buf - COOPER6_OFF + 0x47c);

    w32   ^= (uint32_t) 0x48028910;

    rand16 = (uint16_t) 0x1c86 + (uint16_t) (w32 & (uint32_t) 0x0000ffff);

    *rand  = rand16;

    return 0;
}

static int dec0de_cooper6 (unsigned char* buf, size_t size)
{
    uint32_t key32;
    uint32_t rand32;
    uint16_t rand16;
    uint8_t  w8;
    size_t   i;

    if (calc_rand_cooper6(buf, &rand16)) {
	LOG_ERROR("Cannot determine random number\n");
	return 1;
    }

    rand32 = (uint32_t) rand16;

    key32  = 0x616a6178;

    for (i = 0; i < size; i += SIZE_8) {

	w8     = read8(buf + i);

	w8     = w8 ^ (uint8_t) (key32 & (uint32_t) 0x000000ff);

	key32  = key32 + rand32;

	key32  = SWAP32(key32);

	key32  = key32 ^ (uint32_t) 0x43616d2b;

	rand32 = rand32 + (uint32_t) 0x12345678;

	rand32 = ROL32(rand32, 8);

	write8(w8, buf + i);
    }

    return 0;
}

static pattern_t pattern1_cooper6 = {
    0x6ee,
    38,
    {
	0x20, 0x78, 0x00, 0x24, 0xd0, 0xe8, 0x00, 0x02,
	0x7c, 0x45, 0x42, 0xb8, 0x00, 0x10, 0x42, 0xb8,
	0xfa, 0x06, 0x49, 0xd0, 0xbb, 0x58, 0x51, 0xce,
	0xff, 0xfc, 0x60, 0x08, 0x7c, 0x45, 0xbb, 0x5c,
	0x51, 0xce, 0xff, 0xfc, 0x4e, 0x73,
    },
};

static pattern_t pattern2_cooper6 = {
    0x110,
    18,
    {
	0xdb, 0x97, 0x22, 0x97, 0x23, 0x57, 0x00, 0x0c,
	0x3e, 0x93, 0x06, 0x57, 0x0b, 0xe7, 0x46, 0xfc,
	0xff, 0xff,
    },
};

static pattern_t* patterns_cooper6[] = {
    &pattern1_cooper6,
    &pattern2_cooper6,
    NULL,
};

static prot_t prot_cooper6 = {
    .name     = "Cooper v0.6 by Cameo from The Replicants",
    .offset   = COOPER6_OFF,
    .patterns = patterns_cooper6,
    .dec0de   = dec0de_cooper6,
};

/*****************************************************************************
 * Generic Anti-bitos decrypting routines
 *****************************************************************************/

static int calc_rand_abx (unsigned char* buf, uint16_t sub_count,
			  uint16_t* rand)
{
    uint16_t w16;
    uint16_t rand16;

    rand16  = read16(buf);

    w16     = ((((uint16_t) 0x004f) - sub_count) << 1) ^ (uint16_t) 0x1234;
    w16     = (uint16_t) ROL8((uint8_t)(w16 & (uint16_t) 0x00ff), 1);
    w16    |= (uint16_t) 0x4f00;

    rand16 ^= (((uint16_t) 0x601a) ^ w16);

    *rand   = rand16;

    return 0;
}

static int dec0de_abx (unsigned char* buf, uint16_t sub_count,
		       size_t size, size_t size_orig, uint16_t reloc)
{
    uint16_t key16;
    uint8_t  key8;
    uint16_t rand16;
    uint16_t w16;
    uint8_t  w8;
    uint32_t i;

    if ((size > size_orig) || (size_orig - size > 8)) {
	LOG_ERROR("Invalid file size=0x%x (should be close to 0x%x)\n",
		  (unsigned int) size, (unsigned int) size_orig);
	return 1;
    }

    if (!reloc) {
	LOG_ERROR("Original program is not a GEMDOS program\n");
	return 1;
    }

    if (calc_rand_abx(buf, sub_count, &rand16)) {
	LOG_ERROR("Cannot determine random number\n");
	return 1;
    }

    key16 = 0x004f;

    for (i = 0; i < DBF_SIZE8(size); i += (uint32_t) SIZE_8) {

	w8     = read8(buf + i);

	w8    ^= (uint8_t) (key16 & (uint16_t) 0x00ff);

	key16 -= sub_count;

	key16  = key16 << 1;

	key16 ^= (uint16_t) 0x1234;

	key8   = (uint8_t) (key16 & (uint16_t) 0x00ff);
	key8   = ROL8(key8, 1);
	key16  = (key16 & (uint16_t) 0xff00) | (uint16_t) key8;

	write8(w8, buf + i);
    }

    for (i = 0; i < DBF_SIZE16(size); i += (uint32_t) SIZE_16) {

	w16     = read16(buf + i);

	w16    ^= rand16;

	rand16 += 1;

	write16(w16, buf + i);
    }

    return 0;
}

/*****************************************************************************
 * Anti-bitos v1.0 by Illegal from The Replicants
 *****************************************************************************/

#define AB100_OFF 0x44e

static int dec0de_ab100 (unsigned char* buf, size_t size)
{
    return dec0de_abx(buf,
		      2,
		      (size_t) (read16(buf - AB100_OFF + 0x30) << 1),
		      size,
		      read16(buf - AB100_OFF + 0x32));
}

static pattern_t pattern1_ab100 = {
    0xa0,
    20,
    {
	0x41, 0xfa, 0xff, 0x92, 0x30, 0xb8, 0x82, 0x40,
	0x11, 0xf8, 0xfa, 0x07, 0x00, 0xf4, 0x11, 0xf8,
	0xfa, 0x09, 0x00, 0xf8,
    },
};

static pattern_t pattern2_ab100 = {
    0xb8,
    36,
    {
	0x41, 0xfa, 0x00, 0xa6, 0x43, 0xfa, 0x00, 0xce,
	0x45, 0xfa, 0x00, 0x90, 0x21, 0xc8, 0x00, 0x10,
	0x21, 0xc9, 0x00, 0x80, 0x21, 0xca, 0x00, 0x24,
	0x21, 0xfc, 0x00, 0x0f, 0x80, 0x00, 0x00, 0x30,
	0x46, 0xfc, 0xa3, 0x00,
    },
};

static pattern_t pattern3_ab100 = {
    0x152,
    38,
    {
	0x48, 0x50, 0x20, 0x6f, 0x00, 0x06, 0x4e, 0x40,
	0x4a, 0xfc, 0x20, 0x5f, 0x4e, 0x73, 0x48, 0xe7,
	0xc0, 0xc0, 0x22, 0x48, 0x20, 0x28, 0xff, 0xf4,
	0x22, 0x28, 0xff, 0xf0, 0xb1, 0x81, 0x46, 0x81,
	0x0a, 0x81, 0x12, 0x34, 0x56, 0x78,
    },
};

static pattern_t pattern4_ab100 = {
    0x1c,
    2,
    {
	0x60, 0x30,
    },
};

static pattern_t* patterns_ab100[] = {
    &pattern1_ab100,
    &pattern2_ab100,
    &pattern3_ab100,
    &pattern4_ab100,
    NULL,
};

static prot_t prot_ab100 = {
    .name     = "Anti-bitos v1.0 by Illegal from The Replicants",
    .offset   = AB100_OFF,
    .patterns = patterns_ab100,
    .dec0de   = dec0de_ab100,
};

/*****************************************************************************
 * Anti-bitos v1.4 (a & b) by Illegal from The Replicants
 *****************************************************************************/

#define AB140A_OFF 0x692
#define AB140B_OFF 0x68c

static int dec0de_ab140a (unsigned char* buf, size_t size)
{
    return dec0de_abx(buf,
		      2,
		      (size_t) (read16(buf - AB140A_OFF + 0x36) << 1),
		      size,
		      read16(buf - AB140A_OFF + 0x38));
}

static pattern_t pattern1_ab140a = {
    0xa6,
    20,
    {
	0x11, 0xfc, 0x00, 0x12, 0xfc, 0x02, 0x41, 0xfa,
	0xff, 0x8c, 0x30, 0xb8, 0x82, 0x40, 0x11, 0xf8,
	0xfa, 0x07, 0x00, 0xf4,
    },
};

static pattern_t pattern2_ab140a = {
    0xc4,
    36,
    {
	0x41, 0xfa, 0x00, 0xa6, 0x43, 0xfa, 0x00, 0xce,
	0x45, 0xfa, 0x00, 0x90, 0x21, 0xc8, 0x00, 0x10,
	0x21, 0xc9, 0x00, 0x80, 0x21, 0xca, 0x00, 0x24,
	0x21, 0xfc, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x30,
	0x46, 0xfc, 0xa3, 0x00,
    },
};

static pattern_t pattern3_ab140a = {
    0x15e,
    38,
    {
	0x48, 0x50, 0x20, 0x6f, 0x00, 0x06, 0x4e, 0x40,
	0x4a, 0xfc, 0x20, 0x5f, 0x4e, 0x73, 0x48, 0xe7,
	0xc0, 0xc0, 0x22, 0x48, 0x20, 0x28, 0xff, 0xf4,
	0x22, 0x28, 0xff, 0xf0, 0xb1, 0x81, 0x46, 0x81,
	0x0a, 0x81, 0x12, 0x34, 0x56, 0x78,
    },
};

static pattern_t pattern4_ab140a = {
    0x1c,
    2,
    {
	0x60, 0x36,
    },
};

static pattern_t* patterns_ab140a[] = {
    &pattern1_ab140a,
    &pattern2_ab140a,
    &pattern3_ab140a,
    &pattern4_ab140a,
    NULL,
};

static prot_t prot_ab140a = {
    .name     = "Anti-bitos v1.4 (a) by Illegal from The Replicants",
    .offset   = AB140A_OFF,
    .patterns = patterns_ab140a,
    .dec0de   = dec0de_ab140a,
};

static int dec0de_ab140b (unsigned char* buf, size_t size)
{
    return dec0de_abx(buf,
		      2,
		      (size_t) (read16(buf - AB140B_OFF + 0x36) << 1),
		      size,
		      read16(buf - AB140B_OFF + 0x38));
}

static pattern_t pattern1_ab140b = {
    0xa6,
    20,
    {
	0x41, 0xfa, 0xff, 0x92, 0x30, 0xb8, 0x82, 0x40,
	0x11, 0xf8, 0xfa, 0x07, 0x00, 0xf4, 0x11, 0xf8,
	0xfa, 0x09, 0x00, 0xf8,
    },
};

static pattern_t pattern2_ab140b = {
    0xbe,
    36,
    {
	0x41, 0xfa, 0x00, 0xa6, 0x43, 0xfa, 0x00, 0xce,
	0x45, 0xfa, 0x00, 0x90, 0x21, 0xc8, 0x00, 0x10,
	0x21, 0xc9, 0x00, 0x80, 0x21, 0xca, 0x00, 0x24,
	0x21, 0xfc, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x30,
	0x46, 0xfc, 0xa3, 0x00,
    },
};

static pattern_t pattern3_ab140b = {
    0x158,
    38,
    {
	0x48, 0x50, 0x20, 0x6f, 0x00, 0x06, 0x4e, 0x40,
	0x4a, 0xfc, 0x20, 0x5f, 0x4e, 0x73, 0x48, 0xe7,
	0xc0, 0xc0, 0x22, 0x48, 0x20, 0x28, 0xff, 0xf4,
	0x22, 0x28, 0xff, 0xf0, 0xb1, 0x81, 0x46, 0x81,
	0x0a, 0x81, 0x12, 0x34, 0x56, 0x78,
    },
};

static pattern_t pattern4_ab140b = {
    0x1c,
    2,
    {
	0x60, 0x36,
    },
};

static pattern_t* patterns_ab140b[] = {
    &pattern1_ab140b,
    &pattern2_ab140b,
    &pattern3_ab140b,
    &pattern4_ab140b,
    NULL,
};

static prot_t prot_ab140b = {
    .name     = "Anti-bitos v1.4 (b) by Illegal from The Replicants",
    .offset   = AB140B_OFF,
    .patterns = patterns_ab140b,
    .dec0de   = dec0de_ab140b,
};

/*****************************************************************************
 * Anti-bitos v1.6 by Illegal from The Replicants
 *****************************************************************************/

#define AB160_OFF 0x618

static int dec0de_ab160 (unsigned char* buf, size_t size)
{
    return dec0de_abx(buf,
		      3,
		      (size_t) (read32(buf - AB160_OFF + 0x4a) << 1),
		      size,
		      read16(buf - AB160_OFF + 0x4e));
}

static pattern_t pattern1_ab160 = {
    0x9a,
    36,
    {
	0x41, 0xfa, 0x00, 0xa6, 0x43, 0xfa, 0x00, 0xce,
	0x45, 0xfa, 0x00, 0x90, 0x21, 0xc8, 0x00, 0x10,
	0x21, 0xc9, 0x00, 0x80, 0x21, 0xca, 0x00, 0x24,
	0x21, 0xfc, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x30,
	0x46, 0xfc, 0xa3, 0x00,
    },
};

static pattern_t pattern2_ab160 = {
    0x134,
    38,
    {
	0x48, 0x50, 0x20, 0x6f, 0x00, 0x06, 0x4e, 0x40,
	0x4a, 0xfc, 0x20, 0x5f, 0x4e, 0x73, 0x48, 0xe7,
	0xc0, 0xc0, 0x22, 0x48, 0x20, 0x28, 0xff, 0xf4,
	0x22, 0x28, 0xff, 0xf0, 0xb1, 0x81, 0x46, 0x81,
	0x0a, 0x81, 0x52, 0x45, 0x50, 0x53,
    },
};

static pattern_t pattern3_ab160 = {
    0x1c,
    2,
    {
	0x60, 0x38,
    },
};

static pattern_t* patterns_ab160[] = {
    &pattern1_ab160,
    &pattern2_ab160,
    &pattern3_ab160,
    NULL,
};

static prot_t prot_ab160 = {
    .name     = "Anti-bitos v1.6 by Illegal from The Replicants",
    .offset   = AB160_OFF,
    .patterns = patterns_ab160,
    .dec0de   = dec0de_ab160,
};

/*****************************************************************************
 * Anti-bitos v1.6 by Illegal from The Replicants
 *****************************************************************************/

#define AB161_OFF 0x662

static int dec0de_ab161 (unsigned char* buf, size_t size)
{
    return dec0de_abx(buf,
		      3,
		      (size_t) (read32(buf - AB161_OFF + 0x4e) << 1),
		      size,
		      read16(buf - AB161_OFF + 0x52));
}

static pattern_t pattern1_ab161 = {
    0x9e,
    36,
    {
	0x41, 0xfa, 0x00, 0xa6, 0x43, 0xfa, 0x00, 0xce,
	0x45, 0xfa, 0x00, 0x90, 0x21, 0xc8, 0x00, 0x10,
	0x21, 0xc9, 0x00, 0x80, 0x21, 0xca, 0x00, 0x24,
	0x21, 0xfc, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x30,
	0x46, 0xfc, 0xa3, 0x00,
    },
};

static pattern_t pattern2_ab161 = {
    0x138,
    38,
    {
	0x48, 0x50, 0x20, 0x6f, 0x00, 0x06, 0x4e, 0x40,
	0x4a, 0xfc, 0x20, 0x5f, 0x4e, 0x73, 0x48, 0xe7,
	0xc0, 0xc0, 0x22, 0x48, 0x20, 0x28, 0xff, 0xf4,
	0x22, 0x28, 0xff, 0xf0, 0xb1, 0x81, 0x46, 0x81,
	0x0a, 0x81, 0x52, 0x45, 0x50, 0x53,
    },
};

static pattern_t pattern3_ab161 = {
    0x1c,
    2,
    {
	0x60, 0x3c,
    },
};

static pattern_t* patterns_ab161[] = {
    &pattern1_ab161,
    &pattern2_ab161,
    &pattern3_ab161,
    NULL,
};

static prot_t prot_ab161 = {
    .name     = "Anti-bitos v1.61 by Illegal from The Replicants",
    .offset   = AB161_OFF,
    .patterns = patterns_ab161,
    .dec0de   = dec0de_ab161,
};

/*****************************************************************************
 * Generic Zippy's Little protection decrypting routines
 *****************************************************************************/

static int calc_rand_zippy20x (unsigned char* buf, uint32_t* rand)
{
    uint32_t rand32;

    rand32  = read32(buf - 4);

    rand32  = ~rand32;

    rand32 ^= (uint32_t) 0x34e1fa87;

    *rand   = rand32;

    return 0;
}

static int dec0de_zippy20x (unsigned char* buf, size_t size)
{
    uint32_t key32;
    uint32_t rand32;
    uint8_t  w8;
    size_t   i;

    if (calc_rand_zippy20x(buf, &rand32)) {
	LOG_ERROR("Cannot determine random number\n");
	return 1;
    }

    if (rand32 & (uint32_t) BIT(0)) {
	LOG_WARN("Warning: original program runs only in supervisor mode\n");
    }

    key32 = 0x4c414e47;

    for (i = 0; i < size; i += SIZE_8) {

	w8     = read8(buf + i);

	key32  = key32 ^ rand32;

	rand32 = ROL32(rand32, 1);

	rand32 = ~rand32;

	key32  = ROR32(key32, 3);

	key32  = NEG32(key32);

	w8     = w8 ^ (uint8_t) (key32 & (uint32_t) 0x000000ff);

	write8(w8, buf + i);
    }

    return 0;
}

/*****************************************************************************
 * Little protection v2.05 by Zippy from The Medway Boys
 *****************************************************************************/

#define ZIPPY205_OFF 0x66e

static pattern_t pattern1_zippy205 = {
    0x100,
    30,
    {
	0x90, 0x10, 0x02, 0x40, 0x00, 0xff, 0x51, 0xc8,
	0xff, 0xfe, 0xbf, 0x95, 0xee, 0x9f, 0x2c, 0x6f,
	0x00, 0x02, 0xde, 0x10, 0x40, 0xc0, 0xb1, 0x07,
	0xbf, 0x96, 0x2a, 0x4e, 0x4e, 0x73,
    },
};

static pattern_t pattern2_zippy205 = {
    0x128,
    50,
    {
	0x21, 0xfc, 0x00, 0x07, 0x70, 0x00, 0x00, 0x24,
	0x21, 0xfc, 0x12, 0x34, 0x56, 0x78, 0x00, 0x10,
	0x4c, 0xfa, 0x7f, 0xff, 0x00, 0x20, 0x4e, 0x72,
	0x23, 0x00, 0x4e, 0x72, 0x23, 0x00, 0x46, 0xfc,
	0x27, 0x00, 0x12, 0x10, 0x67, 0xfc, 0x90, 0x01,
	0xe1, 0x28, 0x4b, 0xfa, 0xff, 0xca, 0x46, 0xfc,
	0xa7, 0x00,
    },
};

static pattern_t pattern3_zippy205 = {
    0x48,
    20,
    {
	0x4d, 0xfa, 0xfe, 0xd2, 0x23, 0xcf, 0x00, 0x00,
	0x01, 0x04, 0x40, 0xc0, 0x08, 0x00, 0x00, 0x0d,
	0x66, 0x00, 0x00, 0xc4,
    },
};

static pattern_t* patterns_zippy205[] = {
    &pattern1_zippy205,
    &pattern2_zippy205,
    &pattern3_zippy205,
    NULL,
};

static prot_t prot_zippy205 = {
    .name     = "Little protection v2.05 by Zippy from The Medway Boys",
    .offset   = ZIPPY205_OFF,
    .patterns = patterns_zippy205,
    .dec0de   = dec0de_zippy20x,
};

/*****************************************************************************
 * Little protection v2.06 by Zippy from The Medway Boys
 *****************************************************************************/

#define ZIPPY206_OFF 0x66a

static pattern_t pattern1_zippy206 = {
    0xfc,
    30,
    {
	0x90, 0x10, 0x02, 0x40, 0x00, 0xff, 0x51, 0xc8,
	0xff, 0xfe, 0xbf, 0x95, 0xee, 0x9f, 0x2c, 0x6f,
	0x00, 0x02, 0xde, 0x10, 0x40, 0xc0, 0xb1, 0x07,
	0xbf, 0x96, 0x2a, 0x4e, 0x4e, 0x73,
    },
};

static pattern_t pattern2_zippy206 = {
    0x124,
    50,
    {
	0x21, 0xfc, 0x00, 0x07, 0x70, 0x00, 0x00, 0x24,
	0x21, 0xfc, 0x12, 0x34, 0x56, 0x78, 0x00, 0x10,
	0x4c, 0xfa, 0x7f, 0xff, 0x00, 0x20, 0x4e, 0x72,
	0x23, 0x00, 0x4e, 0x72, 0x23, 0x00, 0x46, 0xfc,
	0x27, 0x00, 0x12, 0x10, 0x67, 0xfc, 0x90, 0x01,
	0xe1, 0x28, 0x4b, 0xfa, 0xff, 0xca, 0x46, 0xfc,
	0xa7, 0x00,
    },
};

static pattern_t pattern3_zippy206 = {
    0x48,
    20,
    {
	0x4d, 0xfa, 0xfe, 0xd2, 0x4b, 0xfa, 0x00, 0xce,
	0x2a, 0x8f, 0x40, 0xc0, 0x08, 0x00, 0x00, 0x0d,
	0x66, 0x00, 0x00, 0xc0,
    },
};

static pattern_t* patterns_zippy206[] = {
    &pattern1_zippy206,
    &pattern2_zippy206,
    &pattern3_zippy206,
    NULL,
};

static prot_t prot_zippy206 = {
    .name     = "Little protection v2.06 by Zippy from The Medway Boys",
    .offset   = ZIPPY206_OFF,
    .patterns = patterns_zippy206,
    .dec0de   = dec0de_zippy20x,
};

/*****************************************************************************
 * Lock-o-matic v1.3 by Yoda from The Marvellous V8
 *****************************************************************************/

#define LOCKOMATIC_OFF 0x418

static void trace_lockomatic (unsigned char* tr_start, uint32_t pc_ret,
			      uint32_t* d0, uint32_t* d7, uint32_t* a4)
{
    uint32_t     tmp_d0 = *d0;
    uint32_t     tmp_d7 = *d7;
    uint32_t     tmp_a4 = *a4;
    unsigned int i;

    for (i = 0; i < 76; i += (unsigned int) SIZE_32) {

	tmp_d7  = read32(tr_start + i);
	tmp_d0 ^= tmp_d7;
	tmp_d0 += 3;
    }

    tmp_a4 += 2;
    tmp_d7  = tmp_a4;
    tmp_d0 ^= tmp_d7;
    tmp_d7  = pc_ret;
    tmp_d0 ^= tmp_d7;

    *d0 = tmp_d0;
    *d7 = tmp_d7;
    *a4 = tmp_a4;
}

static int calc_rand_lockomatic (unsigned char* buf, uint32_t* rand)
{
    unsigned char* tr_start = buf - LOCKOMATIC_OFF + 0x116;
    uint32_t       d0;
    uint32_t       d2;
    uint32_t       d7;
    uint32_t       a4;
    unsigned int   i;

    write16(0x0851, tr_start +  4);
    write16(0x4e73, tr_start + 56);

    d0 = 0x49fafffe;
    d7 = 0x0;
    a4 = 0x8;

    for (i = 0; i <= 0x23; i++) {
	trace_lockomatic(tr_start, 0x0e, &d0, &d7, &a4);

	d2 = 0x226f0002;
	trace_lockomatic(tr_start, 0x14, &d0, &d7, &a4);

	d2 = (d2 & (uint32_t) 0xffff0000) | (d7 & (uint32_t) 0x0000ffff);
	trace_lockomatic(tr_start, 0x16, &d0, &d7, &a4);

	d0 = SWAP32(d0);
	trace_lockomatic(tr_start, 0x18, &d0, &d7, &a4);

	d0 = d0 ^ (d2 & (uint32_t) 0x000000ff);
	trace_lockomatic(tr_start, 0x1a, &d0, &d7, &a4);
    }
    trace_lockomatic(tr_start, 0x1e, &d0, &d7, &a4);

    d0 ^= d7;
    d0 ^= (uint32_t) 0x4ed61234;
    d0 ^= (uint32_t) 0xfff2777f;
    d0 ^= (uint32_t) 0xb50051cb;
    d0 ^= (uint32_t) 0x0000007f;
    d0 ^= d2;
    d0 ^= (uint32_t) 0x77232439;

    *rand = d0;

    return 0;
}

static uint32_t dec0de_routs_lockomatic (unsigned char* buf, unsigned int size,
					 uint32_t rand32)
{
    uint32_t     w32;
    unsigned int i;

    for (i = 0; i < size; i += (unsigned int) SIZE_32) {
	w32 = read32(buf + i);

	w32    ^= rand32;
	rand32 += 3;

	write32(w32, buf + i);
    }

    return rand32;
}

static int dec0de_lockomatic (unsigned char* buf, size_t size)
{
    prog_hdr_t*  hdr = (prog_hdr_t*) buf;
    uint32_t     key32;
    uint32_t     rand32;
    uint32_t     szt32;
    uint32_t     szd32;
    uint32_t     szb32;
    uint32_t     w32;
    size_t       i;

    key32  = read32(buf - LOCKOMATIC_OFF + 0x116 + 0x3a);

    if (calc_rand_lockomatic(buf, &rand32)) {
	LOG_ERROR("Cannot determine random number\n");
	return 1;
    }

    key32 ^= rand32;

    rand32 = dec0de_routs_lockomatic(buf - LOCKOMATIC_OFF + 0x188, 0x284,
				     rand32);

    rand32 = dec0de_routs_lockomatic(buf - LOCKOMATIC_OFF + 0x21e, 0x1ee,
				     0x88dd6a16);

    key32 ^= rand32;
    key32 ^= (uint32_t) 0x00030000;

    (void) dec0de_routs_lockomatic(buf - LOCKOMATIC_OFF + 0x2e0, 0x12c, key32);

    key32  = key32 >> 16;
    key32 ^= (uint32_t) 0x1bcc8462;

    for (i = 0; i < size; i += SIZE_32) {
	w32 = read32(buf + i);

	w32   ^= key32;
	key32 += 3;
	key32  = ROL32(key32, 5);

	write32(w32, buf + i);
    }

    szt32 = read32(buf - LOCKOMATIC_OFF + 0x33c);
    write32(szt32, (unsigned char*)&hdr->ph_tlen);

    szd32 = read32(buf - LOCKOMATIC_OFF + 0x340);
    write32(szd32, (unsigned char*)&hdr->ph_dlen);

    szb32 = read32(buf - LOCKOMATIC_OFF + 0x344);
    write32(szb32, (unsigned char*)&hdr->ph_blen);

    write32(0x0, (unsigned char*)&hdr->ph_slen);
    write32(0x0, (unsigned char*)&hdr->ph_res1);
    write32(0x0, (unsigned char*)&hdr->ph_prgflags);
    write16(0x0, (unsigned char*)&hdr->ph_absflag);

    return 0;
}

static pattern_t pattern1_lockomatic = {
    0xf6,
    90,
    {
	0x49, 0xfa, 0xff, 0xfe, 0x77, 0x23, 0x24, 0x39,
	0x00, 0x00, 0x03, 0xee, 0x34, 0x07, 0x48, 0x40,
	0xb5, 0x00, 0x51, 0xcb, 0xff, 0xf2, 0x77, 0x7f,
	0x4e, 0xd6, 0x12, 0x34, 0x00, 0x00, 0x03, 0xb0,
	0x43, 0xf8, 0x00, 0x08, 0x08, 0x50, 0x36, 0x00,
	0x41, 0xfa, 0xff, 0xf6, 0x43, 0xfa, 0x00, 0x3e,
	0x2e, 0x18, 0xbf, 0x80, 0x56, 0x80, 0xb1, 0xc9,
	0x65, 0x00, 0xff, 0xf6, 0x54, 0x8c, 0x2e, 0x0c,
	0xbf, 0x80, 0x2e, 0x2f, 0x00, 0x02, 0xbf, 0x80,
	0x21, 0xfc, 0x00, 0x00, 0x03, 0xee, 0x00, 0x10,
	0x21, 0xfc, 0x00, 0x00, 0x03, 0xb0, 0x00, 0x24,
	0x4e, 0x75,
    },
};

static pattern_t pattern2_lockomatic = {
    LOCKOMATIC_OFF,
    28,
    {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
    },
};

static pattern_t* patterns_lockomatic[] = {
    &pattern1_lockomatic,
    &pattern2_lockomatic,
    NULL,
};

static prot_t prot_lockomatic = {
    .name     = "Lock-o-matic v1.3 by Yoda from The Marvellous V8",
    .offset   = LOCKOMATIC_OFF,
    .patterns = patterns_lockomatic,
    .dec0de   = dec0de_lockomatic,
};

/*****************************************************************************
 * Dec0der
 *****************************************************************************/

static prot_t* prots[] = {
    &prot_tp1,
    &prot_ral_lp,
    &prot_ral_mp,
    &prot_sly,
    &prot_cooper5,
    &prot_cooper6,
    &prot_ab100,
    &prot_ab140a,
    &prot_ab140b,
    &prot_ab160,
    &prot_ab161,
    &prot_zippy205,
    &prot_zippy206,
    &prot_lockomatic,
    NULL,
};

static int dec0de_prog (prog_t* prog)
{
    prot_t*        prot;
    pattern_t*     pattern;
    unsigned char* buf;
    unsigned int   i;
    unsigned int   j;
    int            diag = 1;

    for (i = 0; (prot = prots[i]) != NULL; i++) {
	ASSERT(!(prot->offset & 0x1));
	if (prog->size < prot->offset) {
	    continue;
	}
	for (j = 0; (pattern = prot->patterns[j]) != NULL; j++) {
	    if (prog->size < pattern->offset + pattern->count) {
		break;
	    }
	    buf = prog->buf + pattern->offset;
	    if (memcmp(buf, pattern->buf, pattern->count) != 0) {
		break;
	    }
	}
	if (pattern == NULL) {
	    break;
	}
    }

    if (prot) {
	LOG_INFO("Program '%s' is enc0ded with " PP_LINEBRK "%s\n",
		 prog->name, prot->name);
	prog->prot = prot;
	diag = prot->dec0de(prog->buf + prot->offset,
			    prog->size - prot->offset);
	if (diag == 0) {
	    diag = fixup_prog(prog);
	}
    } else {
	LOG_ERROR("Unrecognized protection for program '%s'\n", prog->name);
    }

    return diag;
}

static int dec0de (const char* sname, const char* dname)
{
    prog_t* prog;
    int     diag = 1;

    prog = load_prog(sname);
    if (prog) {
	diag = dec0de_prog(prog);
	if ((diag == 0) && dname) {
	    LOG_INFO("Saving dec0ded program as '%s'\n", dname);
	    diag = save_prog(prog, dname);
	}
	release_prog(prog);
    }

    return diag;
}

static void list_prots (void)
{
    prot_t*      prot;
    unsigned int i;

    LOG_INFO("Supported protections are:\n" PP_LINEBRK);

    for (i = 0; (prot = prots[i]) != NULL; i++) {
	LOG_INFO("  %s\n", prot->name);
    }
}

/*****************************************************************************
 * Help
 *****************************************************************************/

static void usage (char** argv)
{
    LOG_INFO(
    "Usage: %s <command> [<source_file>] [<destination_file>]\n"
    "Remove encryption systems used to protect GEMDOS programs.\n"
    "\n"
    "Possible commands are:\n"
    "  -d ... dec0de <source_file> into <destination_file>\n"
    "  -t ... test <source_file>\n"
    "  -l ... list supported protections\n"
    "  -h ... display this help\n"
    "  -i ... provide detailed information\n"
    "  -v ... output version information\n"
    "\n"
    "This tool has been developed by Orion from The Replicants.\n"
    "Report bugs or unsupported protections to orion.replicants@gmail.com\n",
    PROG_NAME(argv)
    );
}

static void info (void)
{
    LOG_INFO_MORE(
    DEC0DE_BANNER
    "\n"
    "Remove encryption systems used to protect GEMDOS programs.\n"
    "\n"
    "On Atari ST, some encryption systems were often used to protect\n"
    "programs against reverse-engineering or ripping: the original program\n"
    "was encrypted and transformed into a self-decrypting program.\n"
    "\n"
    "Most popular protections are Illegal's Anti-bitos, Cameo's Cooper...\n"
    "\n"
    "This tool merely removes such protections, thus enabling to restore\n"
    "the original unprotected programs.\n"
    "\n"
    "If a protected program crashes under your emulator or on your machine,\n"
    "or if you want to rip a scrolltext, music or picture, then this tool is\n"
    "made for you.\n"
    "\n"
    );
    LOG_INFO_MORE(
    "If the resulting unprotected program is packed, then you can use the\n"
    "well known depackers (New Depack, Naughty Unpacker...) to obtain the\n"
    "original uncompressed file.\n"
    "\n"
    "Depackers links:\n"
    "- New Depack                https://demozoo.org/productions/96097/\n"
    "- The Naughty Unpacker      https://demozoo.org/productions/75456/\n"
    "- The UPX packer/unpacker   https://upx.github.io/\n"
    "\n"
    "Friend links:\n"
    "- Replicants Memorial Site  http://replicants.free.fr/index.php\n"
    "- Replicants on Demozoo     https://demozoo.org/groups/31491/\n"
    "- The Fuzion Shrine         http://fuzionshrine.omiquel.lautre.net\n"
    "- Fuzion on Demozoo         https://demozoo.org/groups/31618/\n"
    "\n"
    );
    LOG_INFO(
    "Greetings to all Atari ST sceners, past and present.\n"
    "\n"
    "Thanks to all Atari ST enthusiasts who contribute to keep the Atari ST\n"
    "scene and spirit alive.\n"
    "\n"
    "Special thanks to the following people:\n"
    "Maartau (the protection collector) for his contribution to this tool,\n"
    "Mr Nours for his essential Fuzion Shrine website,\n"
    "Jace from ST Knights for his support to the Replicants,\n"
    "Brume and Marcer for their amazing archiving effort,\n"
    "Lotek Style for his great work on Demozoo.\n"
    "\n"
    "Warm hello to all Replicants and Fuzion members, especially Ellfire,\n"
    "Cameo, Kasar, Squat, JackTBS, Docno, Illegal, Snake, Excalibur, Fury...\n"
    "\n"
    "You can report bugs or unsupported protections to:\n"
    "orion.replicants@gmail.com or orion.fuzion@gmail.com\n"
    "\n"
    "The development of this tool required a huge reverse-engineering\n"
    "and protections cracking effort. This has been done using adebug only.\n"
    "No emulator debugger (like Steem Debug) or cartridge has been used ;)\n"
    "\n"
    "The Replicants rules forever...\n"
    );
}

static void version (void)
{
    LOG_INFO(DEC0DE_BANNER);
}

static void try_help (char** argv)
{
    LOG_ERROR("Try '%s -h' for more information.\n", argv[0]);
}

/*****************************************************************************
 * Atari ST specific code
 *****************************************************************************/

#if defined (TARGET_ST)

/*
 * Atari Application Environment Services.
 *
 * See GEM Programmer's Guide - Volume 2 - AES,
 * http://dev-docs.atariforge.org/files/GEM_AES_v1_Jan-1989.pdf
 */
static struct {
    int      init_done;
    uint16_t global[16];
    /*
     * opcode
     * int_in size in words
     * int_out size in words
     * addr_in size in longs
     * addr_out size in longs
     */
    uint16_t ctrl[5];
    uint16_t int_in[16];
    uint16_t int_out[16];
    void*    addr_in[16];
    void*    addr_out[16];
    void*    params_block[6];
} aes;

/*
 * Atari Line-A Emulator.
 *
 * See http://toshyp.atari.org/en/006.html
 *
 * For negative offsets, see S.A.L.A.D. - Still Another Line A Document
 * by Mark Jansen - Atari Corporation,
 * https://mikro.naprvyraz.sk/docs/GEM/SALAD.TXT
 */
static void*     linea_param_blk;
static uint16_t* cell_x_max_p;
static uint16_t* mouse_hid_count_p;
static int       mouse_is_hidden;

/*
 * Saved color palette.
 *
 * See http://toshyp.atari.org/en/Screen_functions.html#Setcolor
 */
static int16_t   colors[16];

/*
 * Exiting after using interactive mode?
 */
static int       ia_mode_exit;

/*
 * GEMDOS functions.
 *
 * See http://toshyp.atari.org/en/005013.html
 * or
 * http://info-coach.fr/atari/documents/_mydoc/Hitchhikers-Guide-V1.1.pdf
 */

/*
 * Print (Cconws).
 */
static void print (const char* txt)
{
    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	%0,%%sp@-			\n\t"
	    "move.w	#9,%%sp@-			\n\t"
	    "trap	#1				\n\t"
	    "addq.l	#6,%%sp				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    :
	    : "g" (txt)
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);
}

/*
 * Key wait (Crawcin).
 */
static int key_wait (void)
{
    uint32_t key;

    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	#7,%%sp@-			\n\t"
	    "trap	#1				\n\t"
	    "addq.l	#2,%%sp				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    "						\n\t"
	    "move.l	%%d0, %0			\n\t"
	    : "=d" (key)
	    :
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

    return (int) (key & ((uint32_t) 0xff));
}

/*
 * Get current drive (Dgetdrv).
 */
static unsigned int cur_drv_get (void)
{
    uint16_t drv;

    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	#25,%%sp@-			\n\t"
	    "trap	#1				\n\t"
	    "addq.l	#2,%%sp				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    "						\n\t"
	    "move.w	%%d0, %0			\n\t"
	    : "=d" (drv)
	    :
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

    if (drv > 25) {
	drv = 0;
    }

    return ((unsigned int) drv) + 1;
}

/*
 * Get current directory (Dgetpath).
 */
static int cur_dir_get (unsigned int drv, char* dir)
{
    int32_t diag;

    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	%1,%%sp@-			\n\t"
	    "move.l	%2,%%sp@-			\n\t"
	    "move.w	#71,%%sp@-			\n\t"
	    "trap	#1				\n\t"
	    "addq.l	#8,%%sp				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    "						\n\t"
	    "move.l	%%d0, %0			\n\t"
	    : "=d" (diag)
	    : "g" ((uint16_t) drv), "g" (dir)
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

    return (int) diag;
}

/*
 * Get current path.
 */
static void cur_path_get (char* path)
{
    unsigned int drv;
    unsigned int len;
    int          diag;

    drv = cur_drv_get();

    path[0] = (char) (drv - 1 + 'A');
    path[1] = ':';
    path[2] = '\0';

    diag = cur_dir_get(drv, path + 2);
    if (diag != 0) {
	path[2] = '\0';
    }

    len = strlen(path);
    if (path[len - 1] != '\\') {
	path[len] = '\\';
	path[len + 1] = '\0';
    }
}

/*
 * XBIOS functions.
 *
 * See http://toshyp.atari.org/en/004014.html
 */

/*
 * Supexec.
 */
static int32_t supexec (int32_t (*func) (void))
{
     int32_t diag;

    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	%1,%%sp@-			\n\t"
	    "move.w	#38,%%sp@-			\n\t"
	    "trap	#14				\n\t"
	    "addq.l	#6,%%sp				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    "						\n\t"
	    "move.l	%%d0, %0			\n\t"
	    : "=d" (diag)
	    : "g" (func)
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

    return diag;
}

/*
 * Getrez.
 */
static unsigned int getrez (void)
{
    uint16_t rez;

    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	#4,%%sp@-			\n\t"
	    "trap	#14				\n\t"
	    "addq.l	#2,%%sp				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    "						\n\t"
	    "move.w	%%d0, %0			\n\t"
	    : "=d" (rez)
	    :
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

    return (unsigned int) rez;
}

#if 0 /* Unused */

/*
 * Setrez.
 */
static void setrez (unsigned int rez)
{
    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	%0,%%sp@-			\n\t"
	    "move.l	#-1,%%sp@-			\n\t"
	    "move.l	#-1,%%sp@-			\n\t"
	    "move.w	#5,%%sp@-			\n\t"
	    "trap	#14				\n\t"
	    "add.l	#12,%%sp			\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    :
	    : "g" ((uint16_t) (rez))
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);
}

#endif

/*
 * Setcolor.
 */
static int16_t setcolor (unsigned int colornum, int16_t color)
{
    int16_t oldcolor;

    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	%1,%%sp@-			\n\t"
	    "move.w	%2,%%sp@-			\n\t"
	    "move.w	#7,%%sp@-			\n\t"
	    "trap	#14				\n\t"
	    "addq.l	#6,%%sp				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    "						\n\t"
	    "move.w	%%d0, %0			\n\t"
	    : "=d" (oldcolor)
	    : "g" (color), "g" ((uint16_t) (colornum))
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

    return oldcolor;
}

/*
 * System variables.
 */

static int32_t conterm_setup (void)
{
     __asm__ __volatile__
	(
	    "move.b	#6,0x484.w			\n\t"
	    :
	    :
	    : "cc", "memory"
	);

     return 0;
}

static int32_t conterm_restore (void)
{
     __asm__ __volatile__
	(
	    "move.b	#7,0x484.w			\n\t"
	    :
	    :
	    : "cc", "memory"
	);

     return 0;
}

/*
 * Line-A functions.
 */

static int linea_init (void)
{
    void* linea_addr;

      __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	#0, %%a0			\n\t"
	    "dc.w	0xa000				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    "						\n\t"
	    "move.l	%%a0, %0			\n\t"
	    : "=a" (linea_addr)
	    :
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

      if (!linea_addr || !(*(void**)((uint8_t*)linea_addr + 8))) {
	  print("Line-A initialization failed\n\r");
	  return 1;
      }

      linea_param_blk   = linea_addr;
      cell_x_max_p      = (uint16_t*)((uint8_t*)linea_param_blk - 0x02c);
      mouse_hid_count_p = (uint16_t*)((uint8_t*)linea_param_blk - 0x256);
      mouse_is_hidden   = (*mouse_hid_count_p != 0);

      return 0;
}

static void linea_showm (void)
{
    if (!linea_param_blk) {
	return;
    }

    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	%0,%%a0				\n\t"
	    "move.l	%%a0@(8),%%a1			\n\t"
	    "move.w	#0,%%a1@ 			\n\t"
	    "dc.w	0xa009				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    :
	    : "g" (linea_param_blk)
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);
}

static void linea_hidem (void)
{
    if (!linea_param_blk) {
	return;
    }

    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	%0,%%a0				\n\t"
	    "move.l	%%a0@(8),%%a1			\n\t"
	    "move.w	#0,%%a1@ 			\n\t"
	    "dc.w	0xa00a				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    :
	    : "g" (linea_param_blk)
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);
}

/*
 * AES functions.
 */

static int aes_call (void)
{
    int32_t diag;

    __asm__ __volatile__
	(
	    "moveml	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	#200,%%d0			\n\t"
	    "move.l	%1,%%d1				\n\t"
	    "trap	#2				\n\t"
	    "						\n\t"
	    "moveml	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    "						\n\t"
	    "move.l	%%d0, %0			\n\t"
	    : "=d" (diag)
	    : "g" (aes.params_block)
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

    return (int) diag;
}

static void aes_reset (void)
{
    unsigned int i;

    for (i = 0; i < 5; i++) {
	aes.ctrl[i] = 0;
    }
    for (i = 0; i < 16; i++) {
	aes.int_in[i] = 0;
    }
    for (i = 0; i < 16; i++) {
	aes.int_out[i] = 0;
    }
    for (i = 0; i < 16; i++) {
	aes.addr_in[i] = 0;
    }
    for (i = 0; i < 16; i++) {
	aes.addr_out[i] = 0;
    }
}

static int aes_appl_init (void)
{
    aes.params_block[0] = aes.ctrl;
    aes.params_block[1] = aes.global;
    aes.params_block[2] = aes.int_in;
    aes.params_block[3] = aes.int_out;
    aes.params_block[4] = aes.addr_in;
    aes.params_block[5] = aes.addr_out;

    aes_reset();

    aes.ctrl[0] = 10;	/* opcode - appl_init */
    aes.ctrl[2] = 1;	/* int_out size in words */

    aes.int_out[0] = 0xffff;

    (void) aes_call();

    if (((int16_t)aes.int_out[0]) < 0) {
	print("AES initialization (aes_appl_init) failed\n\r");
	return 1;
    }

    aes.init_done = 1;

    return 0;
}

static void aes_appl_exit (void)
{
    if (!aes.init_done) {
	return;
    }

    aes_reset();

    aes.ctrl[0] = 19;	/* opcode - appl_exit */
    aes.ctrl[2] = 1;	/* int_out size in words */

    (void) aes_call();

    if (aes.int_out[0] == 0) {
	print("AES cleanup (aes_appl_exit) failed\n\r");
    }
}

static int aes_file_selector (unsigned int name_reset, char* path)
{
    static char dir[256];
    static char name[16];
    char*       p;

    ASSERT(aes.init_done);

    aes_reset();

    aes.ctrl[0] = 90;		/* opcode - fsel_input */
    aes.ctrl[2] = 2;		/* int_out size in words */
				/* (fs_ireturn & fs_iexbutton) */
    aes.ctrl[3] = 2;		/* addr_in size in longs */

    aes.addr_in[0] = dir;	/* fs_iinpath */
    aes.addr_in[1] = name;	/* fs_iinsel */

    if (dir[0] == '\0') {
	cur_path_get(dir);
	strcat(dir, "*.*");
    }

    if (name_reset) {
	memset(name, '\0', 16);
    }

    (void) aes_call();

    path[0] = '\0';

    if (aes.int_out[0] == 0) {
	print("AES file selector (fsel_input) failed\n\r");
	/* Error */
	return 1;
    }

    if ((aes.int_out[1] == 0) || (name[0] == '\0')) {
	/* No file selected */
	return 1;
    }

    strcpy(path, dir);
    p = strrchr(path, '\\');
    p = p ? p + 1 : path;
    strcpy(p, name);

    return 0;
}

/*
 * Interactive (IA) mode services.
 */

static int ia_mode_avail (void)
{
    ASSERT(mouse_hid_count_p);
    return !mouse_is_hidden;
}

static int ia_mode_enter (void)
{
    char    path[256];
    prog_t* prog;
    int     key;
    int     wait_return;
    int     diag;

    prog        = NULL;
    wait_return = 0;

    do {

	print(
	    CLEAR_HOME
	    DEC0DE_BANNER "\r"
	    "\n\r"
	    REV_ON " 1 " REV_OFF "   Dec0de a protected GEMDOS program\n\r"
	    REV_ON " 2 " REV_OFF "   List supported protections\n\r"
	    REV_ON " 3 " REV_OFF "   Detailed Information\n\r"
	    REV_ON " 4 " REV_OFF "   Exit\n\r"
	    );

	key = key_wait();
	if ((key >= 'a') && (key <= 'z')) {
	    key = key + 'A' - 'a';
	}

	print(CLEAR_HOME);

	switch(key)
	{
	case '1':
	{
	    print("Select a GEMDOS program");

	    linea_showm();
	    diag = aes_file_selector(1, path);
	    linea_hidem();
	    if (diag) {
		break;
	    }

	    print(CLEAR_HOME);

	    prog = load_prog(path);
	    if (!prog) {
		wait_return = 1;
		break;
	    }

	    print(CLEAR_HOME);

	    diag = dec0de_prog(prog);
	    if (diag) {
		wait_return = 1;
		break;
	    }

	    print("\n\rSave dec0ded program? " REV_ON " (Y/N) " REV_OFF);

	    do {
		key = key_wait();
		if ((key >= 'a') && (key <= 'z')) {
		    key = key + 'A' - 'a';
		}
	    } while ((key != 'Y') && (key != 'N'));

	    if (key == 'N') {
		break;
	    }

	    print(CLEAR_HOME "Choose a non-existing destination file name");

	    linea_showm();
	    diag = aes_file_selector(0, path);
	    linea_hidem();
	    if (diag) {
		break;
	    }

	    print(CLEAR_HOME);

	    diag = save_prog(prog, path);
	    if (diag) {
		wait_return = 1;
	    }
	}
	break;

	case '2':
	    list_prots();
	    wait_return = 1;
	    break;

	case '3':
	    info();
	    wait_return = 1;
	    break;

	default:
	    break;
	}

	if (prog) {
	    release_prog(prog);
	    prog = NULL;
	}

	if (wait_return) {
	    print(REV_ON "\n\rPress any key to return to the menu" REV_OFF);
	    key_wait();
	    wait_return = 0;
	}

    } while (key != '4');

    ia_mode_exit = 1;

    return 0;
}

/*
 * Program start/exit hooks.
 */

static int prog_atstart (void)
{
    int16_t      color;
    unsigned int rez;
    unsigned int i;

    if (linea_init()) {
	return 1;
    }

    linea_hidem();

    print(CLEAR_HOME CUR_OFF WRAP_ON);

    (void) supexec(conterm_setup);

    rez = getrez();
    for (i = 0; i < 16; i++) {
	if ((rez == 0 && i == 15) ||
	    (rez == 1 && i == 3)  ||
	    (rez == 2 && i == 1)) {
	    color = 0x0;
	} else if (rez <= 2) {
	    color = 0xfff;
	} else {
	    color = -1;
	}
	colors[i] = setcolor(i, color);
    }

    if ((1 + *cell_x_max_p) < 80) {
	print("Insufficient screen resolution,\n\r"
	      "try medium or higher resolution.\n\r");
	return 1;
    }

    return aes_appl_init();
}

static void prog_atexit (void)
{
    unsigned int i;

    if (!ia_mode_exit) {
	print(REV_ON "\n\rPress any key to quit" REV_OFF);
	key_wait();
    }

    print(CLEAR_HOME);

    for (i = 0; i < 16; i++) {
	setcolor(i, colors[i]);
    }

    (void) supexec(conterm_restore);

    linea_showm();

    aes_appl_exit();
}

#endif /* TARGET_ST */

/*****************************************************************************
 * Main entry point
 *****************************************************************************/

int do_main (int argc, char* argv[])
{
    const char* cmd;
    const char* src;
    const char* dst;
    char        c;

    if (argc < 2) {
	if (IA_MODE_AVAIL()) {
	    return IA_MODE_ENTER();
	}
	LOG_ERROR("Missing command\n");
	try_help(argv);
	return 1;
    }

    cmd = argv[1];
    if (cmd[0] == '-' && cmd[1] != '\0' && cmd[2] == '\0') {
	c = cmd[1];
	c = ((c >= 'A') && (c <= 'Z')) ? c + 'a' - 'A' : c;
    } else {
	c = '\0';
    }

    switch (c) {

    case 'd':
	if (argc == 4) {
	    src = argv[2];
	    dst = argv[3];
	    break;
	}
	if (argc > 4) {
	    LOG_ERROR("Unexpected parameter: '%s'\n", argv[4]);
	} else if (argc == 3) {
	    LOG_ERROR("Missing destination file\n");
	} else {
	    LOG_ERROR("Missing source file\n");
	}
	try_help(argv);
	return 1;

    case 't':
	if (argc == 3) {
	    src = argv[2];
	    dst = NULL;
	    break;
	}
	if (argc > 3) {
	    LOG_ERROR("Unexpected parameter: '%s'\n", argv[3]);
	} else {
	    LOG_ERROR("Missing source file\n");
	}
	try_help(argv);
	return 1;

    case 'l':
	if (argc == 2) {
	    list_prots();
	    return 0;
	}
	LOG_ERROR("Unexpected parameter: '%s'\n", argv[2]);
	try_help(argv);
	return 1;

    case 'h':
	if (argc == 2) {
	    usage(argv);
	    return 0;
	}
	LOG_ERROR("Unexpected parameter: '%s'\n", argv[2]);
	try_help(argv);
	return 1;

    case 'i':
	if (argc == 2) {
	    info();
	    return 0;
	}
	LOG_ERROR("Unexpected parameter: '%s'\n", argv[2]);
	try_help(argv);
	return 1;

    case 'v':
	if (argc == 2) {
	    version();
	    return 0;
	}
	LOG_ERROR("Unexpected parameter: '%s'\n", argv[2]);
	try_help(argv);
	return 1;

    default:
	LOG_ERROR("Invalid command: '%s'\n", cmd);
	try_help(argv);
	return 1;
    }

    return dec0de(src, dst);
}

int main (int argc, char* argv[])
{
    int diag;

    diag = PROG_ATSTART();
    if (diag == 0) {
	diag = do_main(argc, argv);
    }
    PROG_ATEXIT();

    return diag;
}
