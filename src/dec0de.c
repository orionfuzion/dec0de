/*****************************************************************************
 *
 * $DEC0DE v1.1, Nov 2017.
 *
 * Remove encryption systems used to protect Atari ST programs.
 *
 * This source file can be compiled on any Operating Systems supporting gcc.
 * For non-Linux systems, the following gcc ports are available:
 * - gcc for Mac OS X   https://github.com/kennethreitz/osx-gcc-installer
 * - gcc for Windows    http://www.mingw.org
 * - gcc for Atari      http://vincent.riviere.free.fr/soft/m68k-atari-mint
 *
 * Depending on the target Operating System, run gcc as follows:
 * - For Linux:
 *   $ gcc -O -Wall -Wextra -m32 -static dec0de.c -o dec0de
 * - For Mac OS X:
 *   $ gcc -O -Wall -Wextra -m32 -mmacosx-version-min=10.5 dec0de.c -o dec0de
 * - For Windows:
 *   $ gcc -O -Wall -Wextra -std=c99 dec0de.c -o dec0de.exe
 * - For Atari ST:
 *   $ m68k-atari-mint-gcc -O -Wall -Wextra dec0de.c -o dec0de.prg
 *   or
 *   $ m68k-atari-mint-gcc -O -Wall -Wextra dec0de.c -o dec0de.ttp
 *
 * On Linux, Mac or Windows, run the resulting program from the command prompt.
 * To obtain usage information, run the program as follows:
 * $ dec0de -h
 *
 * On Atari ST, launch dec0de.prg or dec0de.ttp from the GEM desktop.
 * dec0de.prg provides an interactive mode, while dec0de.ttp expects
 * parameters to be provided through the command line.
 *
 * Versions history:
 *
 * - v1.0, Dec 2016, initial version supporting:
 *   NTM/Cameo Toxic Packer v1.0,
 *   R.AL Little Protection v01 & Megaprot v0.02,
 *   Orion Sly Packer v2.0,
 *   Cameo Cooper v0.5 & v0.6,
 *   Illegal Anti-bitos v1.0, v1.4, v1.6 & v1.61,
 *   Zippy Little Protection v2.05 & v2.06,
 *   Yoda Lock-o-matic v1.3.
 *
 * - v1.1, Nov 2017, adds support for:
 *   Criminals In Disguise (CID) Encrypter v1.0bp,
 *   Rob Northen Copylock Protection System series 1 (1988) & series 2 (1989).
 *
 * Code & reverse engineering: Orion ^ The Replicants ^ Fuzion
 * Reverse engineering:        Maartau ^ Atari Legend ^ Elite
 * ASCII logo:                 Senser ^ Effect ^ Vectronix
 *
 * Git repository: https://github.com/orionfuzion/dec0de
 * Contact:        orion.replicants@gmail.com or orion.fuzion@gmail.com
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

#define DEC0DE_VERSION		"1.1"

#define DEC0DE_DATE		"Nov 2017"

#define DEC0DE_VERSION_FULL						\
    "$" DEC0DE_NAME " v" DEC0DE_VERSION	", " DEC0DE_DATE "."

#define DEC0DE_AUTHOR							\
    "Orion ^ The Replicants"

#define DEC0DE_TEAM							\
    DEC0DE_AUTHOR " + Maartau ^ Atari Legend"

#define DEC0DE_REPO							\
    "https://github.com/orionfuzion/dec0de"

#define DEC0DE_EMAIL							\
    "orion.replicants@gmail.com"

#if defined(__atarist__)
#define TARGET_ST
#else
#undef  TARGET_ST
#endif

/* For compatibility with Windows open() */
#ifndef O_BINARY
#define O_BINARY		0
#endif

//#define DEBUG

static int log_count;

#define LOG_INFO(_f, _a...)						\
    do {								\
	fprintf(stdout, _f, ##_a);					\
	fflush(stdout);							\
	log_count++;							\
    } while (0)

#define LOG_ERROR(_f, _a...)						\
    do {								\
	fprintf(stderr, _f, ##_a);					\
	fflush(stderr);							\
	log_count++;							\
    } while (0)

#define LOG_WARN(_f, _a...)						\
    do {								\
	fprintf(stdout, _f, ##_a);					\
	fflush(stdout);							\
	log_count++;							\
    } while (0)

#define ASSERT(_a)							\
    do {								\
	if (!(_a)) {							\
	    LOG_ERROR("Assertion failed at %s:%d\n",			\
		      __FUNCTION__, __LINE__);				\
	    abort();							\
	}								\
    } while (0)

#define __ASM_STR2(s)		# s
#define __ASM_STR(s)		__ASM_STR2(s)

#define USED			__attribute__((used))

#define MARKER_MAGIC		0xdec0de11

struct pattern_t;
struct prot_t;
struct prog_t;

/*
 * Protection identification pattern.
 */
typedef struct pattern_t {
    unsigned int    type;
    size_t          offset;
    size_t          eoffset;
    size_t          delta;
    size_t          count;
    size_t          ecount;
    unsigned char*  buf;
    unsigned char*  mask;
} pattern_t;

/*
 * Decoding function.
 */
typedef int (*decode_func_t) (struct prog_t* prog,
			      unsigned char* buf,
			      size_t         size);

/*
 * Protection description.
 */
typedef struct prot_t {
    struct prot_t*  parent;
    const char*     name;
    unsigned char   varnum;
    size_t          doffset;
    pattern_t**     patterns;
    decode_func_t   decode;
    void*           private;
} prot_t;

/*
 * Patterns and protections declaration macros.
 */

#define PATTERN_NONE		0
#define PATTERN_PROG		1
#define PATTERN_BIN		2
#define PATTERN_ANY		(PATTERN_PROG | PATTERN_BIN)

#define PATTERN_NEXT		((size_t) -2)

#define PATTERN_BUFFER(_p...)	{ _p, }

#define DECLARE_PATTERN(_name, _type, _offset, _delta, _count, _buf)	\
    static unsigned char _name ## __buf[]  = _buf;			\
    static pattern_t     _name = {					\
	.type   = _type,						\
	.offset = _offset,						\
	.delta  = _delta,						\
	.count  = _count,						\
	.buf    = _name ## __buf,					\
	.mask   = NULL,							\
    }

#define DECLARE_PATTERN_WITH_MASK(_name, _type, _offset, _delta,	\
				  _count, _buf,	_mask)			\
    static unsigned char _name ## __buf[] = _buf;			\
    static unsigned char _name ## __msk[] = _mask;			\
    static pattern_t     _name = {					\
	.type   = _type,						\
	.offset = _offset,						\
	.delta  = _delta,						\
	.count  = _count,						\
	.buf    = _name ## __buf,					\
	.mask   = _name ## __msk,					\
    }

#define PATTERNS_LIST(_l...)	{ _l, NULL, }

static pattern_t pattern_none = { .type = PATTERN_NONE, };

#define DECLARE_PROTECTION(_name, _desc, _doffset, _plist,		\
			   _func, _priv)				\
    static pattern_t* _name ## patterns[] = _plist;			\
    static prot_t     _name = {						\
	.parent   = NULL,						\
	.name     = _desc,						\
	.varnum   = 0,							\
	.doffset  = _doffset,						\
	.patterns = _name ## patterns,					\
	.decode   = _func,						\
	.private  = _priv,						\
    }

#define DECLARE_PROTECTION_PARENT(_name, _desc, _varnum, _doffset,	\
				  _plist, _func, _priv)			\
    static pattern_t* _name ## patterns[] = _plist;			\
    static prot_t     _name = {						\
	.parent   = &_name,						\
	.name     = _desc,						\
	.varnum   = _varnum,						\
	.doffset  = _doffset,						\
	.patterns = _name ## patterns,					\
	.decode   = _func,						\
	.private  = _priv,						\
    }

#define DECLARE_PROTECTION_VARIANT(_name, _parent, _varnum, _doffset,	\
				   _plist, _func, _priv)		\
    static pattern_t* _name ## patterns[] = _plist;			\
    static prot_t     _name = {						\
	.parent   = _parent,						\
	.name     = NULL,						\
	.varnum   = _varnum,						\
	.doffset  = _doffset,						\
	.patterns = _name ## patterns,					\
	.decode   = _func,						\
	.private  = _priv,						\
    }

#define PROT_DECODE(_p)							\
    ((_p)->decode ? (_p)->decode :					\
     ((_p)->parent ? (_p)->parent->decode : NULL))

/*
 * Program description.
 */
typedef struct prog_t {
    char*           name;	/* File name */
    size_t          fsize;	/* File size */
    size_t          hsize;	/* Program header size (if any) */
    size_t          size;	/* Effective program size */
    size_t          dsize;	/* Decoded program size */
    size_t          doffset;	/* Decoded program offset */
    unsigned int    binary;	/* Decoded program is binary (not a GEMDOS) */
    prot_t*         prot;	/* Corresponding protection */
    unsigned char*  text;	/* Text buffer */
    unsigned char*  marker;	/* Marker at buffer's end */
    unsigned char   buf[];	/* File buffer */
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

/*
 * Instruction pattern matching description.
 */
typedef struct instr_match_t {
    uint32_t op32[2];
    uint32_t mask32[2];
    uint16_t stride;
} instr_match_t;

/*****************************************************************************
 * Platform-specific behavior
 *****************************************************************************/

#if defined(TARGET_ST)

static int  prog_atstart (void);
static void prog_atexit  (void);

static int  ia_mode_avail (void);
static int  ia_mode_enter (void);

static void pp_newline (void);

static int  key_wait (void);

/*
 * VT-52 Terminal Control Sequences.
 *
 * See http://toshyp.atari.org/en/VT_52_terminal.html#VT-52_20terminal
 */

#define CLEAR_HOME		"\33E"
#define CLEAR_DOWN		"\33J"
#define CLEAR_SOL		"\33o"
#define CUR_OFF			"\33f"
#define SAVE_POS		"\33j"
#define LOAD_POS		"\33k"
#define REV_ON			"\33p"
#define REV_OFF			"\33q"
#define WRAP_ON			"\33v"
#define WRAP_OFF		"\33w"

#define PP_LINEBRK		"\n"
#define PP_NEWLINE()		pp_newline()

#define IA_MODE_AVAIL()		ia_mode_avail()
#define IA_MODE_ENTER()		ia_mode_enter()

#define PROG_ATSTART()		prog_atstart()
#define PROG_ATEXIT()		prog_atexit()

#define PROG_NAME(_a)							\
    ({									\
	static const char* _pname = DEC0DE_NAME;			\
	(void) (_a);							\
	_pname;								\
    })

#define LOG_INFO_MORE(_t)						\
    do {								\
	LOG_INFO(_t "\n" REV_ON "Press any key to continue" REV_OFF);	\
	key_wait();							\
	LOG_INFO(CLEAR_HOME);						\
    } while (0)

#else /* !TARGET_ST */

#define PP_LINEBRK		""
#define PP_NEWLINE()		do { } while (0)

#define IA_MODE_AVAIL()		({ 0; })
#define IA_MODE_ENTER()		({ 1; })

#define PROG_ATSTART()		({ 0; })
#define PROG_ATEXIT()		do { } while (0)

#define PROG_NAME(_a)		((_a)[0])

#define LOG_INFO_MORE(_t)	LOG_INFO(_t "\n")

#endif /* !TARGET_ST */

/*****************************************************************************
 * Decoding helper routines
 *****************************************************************************/

#define SIZE_32		sizeof(uint32_t)

static inline uint32_t read32 (const unsigned char* buf)
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

static inline uint16_t read16 (const unsigned char* buf)
{
    uint16_t w16;

#if defined(TARGET_ST)
    w16  = *(uint16_t*) buf;
#else
    w16  = 0;
    w16 |= (uint16_t) (((uint16_t) buf[0]) << 8);
    w16 |= (uint16_t) (((uint16_t) buf[1]) << 0);
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

static inline uint8_t read8 (const unsigned char* buf)
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

static inline int cmp_instr (uint32_t w32_1, uint32_t w32_2,
			     instr_match_t* instr)
{
    return ((instr->op32[0] == (w32_1 & instr->mask32[0])) &&
	    (instr->op32[1] == (w32_2 & instr->mask32[1])));
}

/*****************************************************************************
 * Program loading, fixup & saving
 *****************************************************************************/

/*
 * Release resources allocated to the currently loaded protected program.
 */
static void release_prog (prog_t* prog)
{
    if (prog->name) {
	free(prog->name);
    }
    free(prog);
}

/*
 * Load a protected program and create a program descriptor.
 */
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

    if ((((size_t)off) <= sizeof(prog_hdr_t)) ||
	(((size_t)off) > (8 * 1024 * 1024))) {
	off = 0;
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

    prog->fsize  = (size_t) off;
    prog->marker = prog->buf + sz_buf - SIZE_32;

    off = lseek(fd, 0, SEEK_SET);
    if (off == (off_t) -1) {
	LOG_ERROR("Cannot seek to start of file '%s': %s\n",
		  name, strerror(errno));
	goto err;
    }

    count = prog->fsize;
    buf   = prog->buf;

    while (count) {
	sz = read(fd, buf, count);
	if (sz == (ssize_t) -1) {
	    if (errno == EINTR) {
		continue;
	    }
	    LOG_ERROR("Failed to read %zu bytes from file '%s': %s\n",
		      count, name, strerror(errno));
	    goto err;
	}
	if (sz == 0) {
	    break;
	}
	count -= (size_t) sz;
	buf   += sz;
    }

    if (count) {
	LOG_ERROR("Unexpected EOF while reading from file '%s', file size=%zu"
		  " bytes, unread bytes=%zu, last read result=%zd\n",
		  name, prog->fsize, count, (size_t) sz);
	goto err;
    }

    while (buf != prog->marker) {
	*buf = '\0';
	buf++;
    }
    write32(MARKER_MAGIC, prog->marker);

    prog->hsize = ((read16(prog->buf) == (uint16_t) 0x601a) ?
		   sizeof(prog_hdr_t) : 0);
    prog->size  = prog->fsize - prog->hsize;
    prog->text  = prog->buf   + prog->hsize;

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

/*
 * Save the decoded program.
 */
static int save_prog (prog_t* prog, const char* name)
{
    unsigned char* buf;
    size_t         count;
    ssize_t        sz;
    int            fd;

    ASSERT(prog->prot && prog->dsize && prog->doffset);

    fd = open(name, O_BINARY | O_RDWR | O_CREAT | O_EXCL, 0666);
    if (fd == -1) {
	LOG_ERROR("Cannot create file '%s': %s\n", name, strerror(errno));
	return 1;
    }

    buf   = prog->text + prog->doffset;
    count = prog->dsize;

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

/*
 * Dump the header of the decoded program in case of error.
 */
static void dump_hdr (prog_t* prog)
{
    size_t         doffset = prog->doffset;
    unsigned char* dbuf    = prog->text + doffset;
    unsigned int   i;

    PP_NEWLINE();
    LOG_ERROR("File size: %zu bytes\n", prog->fsize);
    LOG_ERROR("Dec0ded program offset: %zu bytes\n", prog->hsize + doffset);
    LOG_ERROR("Dec0ded program size: %zu bytes\n",   prog->size  - doffset);
    LOG_ERROR("Dec0ded header: ");
    for (i = 0; i < (unsigned int) sizeof(prog_hdr_t); i++) {
	LOG_ERROR("%02x", (unsigned int) dbuf[i]);
    }
    LOG_ERROR("\n");
}

/*
 * Performs checks and fixes on the decoded program prior to saving it.
 */
static int fixup_prog (prog_t* prog)
{
    prot_t*        prot = prog->prot;
    unsigned char* dbuf;
    prog_hdr_t*    hdr;
    size_t         doffset;
    size_t         sz_dec;
    size_t         sz_text;
    size_t         sz_data;
    size_t         sz_bss;
    size_t         sz_symb;
    size_t         sz;
    size_t         i;
    uint32_t       res1;

    ASSERT(sizeof(prog_hdr_t) == 28);
    ASSERT(prot);

    /*
     * Actual decoded program offset and size.
     */
    doffset = prog->doffset;
    if (!doffset) {
	prog->doffset = doffset = prot->doffset;
	ASSERT(doffset);
    }
    sz_dec = prog->dsize;
    if (!sz_dec) {
	prog->dsize = sz_dec = prog->size - doffset;
    }

    /*
     * Check for unexpected buffer overflow during decrypting.
     */
    if (read32(prog->marker) != (uint32_t) MARKER_MAGIC) {
	LOG_ERROR("Buffer overflow detected after dec0ding program\n");
	return 1;
    }

    /*
     * Do not perform GEMDOS fixup checking if decoded program is binary.
     */
    if (prog->binary) {
	return 0;
    }

    /*
     * The program size must be greater than the GEMDOS header size.
     */
    if ((ssize_t) sz_dec < (ssize_t) sizeof(prog_hdr_t)) {
	LOG_ERROR("Invalid dec0ded program size=%zu bytes\n", sz_dec);
	return 1;
    }

    dbuf   = prog->text + doffset;
    hdr    = (prog_hdr_t*) dbuf;

    sz_text = (size_t) read32((unsigned char*)&hdr->ph_tlen);
    sz_data = (size_t) read32((unsigned char*)&hdr->ph_dlen);
    sz_bss  = (size_t) read32((unsigned char*)&hdr->ph_blen);
    sz_symb = (size_t) read32((unsigned char*)&hdr->ph_slen);

    /*
     * Check text size.
     */
    if (sz_text > sz_dec - sizeof(prog_hdr_t)) {
	LOG_ERROR("Invalid text size=%zu bytes\n", sz_text);
	goto dump;
    }

    /*
     * Check data size.
     */
    if (sz_data > sz_dec - sizeof(prog_hdr_t)) {
	LOG_ERROR("Invalid data size=%zu bytes\n", sz_data);
	goto dump;
    }

    /*
     * Check symbols size.
     */
    if (sz_symb > sz_dec - sizeof(prog_hdr_t)) {
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

    if (sz > sz_dec) {
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
	if (sz + SIZE_32 > sz_dec) {
	    LOG_ERROR("Truncated starting fixup offset\n");
	    goto dump;
	}
	/*
	 * A non-zero fixup offset indicates that a relocation table is
	 * actually present.
	 */
	rel_off = ((((uint32_t)read8(dbuf + sz + SIZE_8*0)) << 24) |
		   (((uint32_t)read8(dbuf + sz + SIZE_8*1)) << 16) |
		   (((uint32_t)read8(dbuf + sz + SIZE_8*2)) <<  8) |
		   (((uint32_t)read8(dbuf + sz + SIZE_8*3)) <<  0));
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
	    for (;;) {
		if (sz + SIZE_8 > sz_dec) {
		    /*
		     * Allow non-null terminated relocation table.
		     */
		    LOG_WARN("Warning: unexpected non-null terminated "
			     "relocation table\n");
		    break;
		}
		off8 = read8(dbuf + sz);
		sz  += SIZE_8;
		if (off8 == 0) {
		    break;
		} else if (off8 == 1) {
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
	    }
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
	write8(0, dbuf + sz + SIZE_8*0);
	write8(0, dbuf + sz + SIZE_8*1);
	write8(0, dbuf + sz + SIZE_8*2);
	write8(0, dbuf + sz + SIZE_8*3);
	/*
	 * Buffer overflow is safely handled here since an extra 32-bits word
	 * has been provisioned at buffer allocation time.
	 */
	sz += SIZE_32;
    }

    for (i = 0; (ssize_t)i < (ssize_t)(sz_dec - sz); i++) {
	write8('\0', dbuf + sz + i);
    }

    /*
     * Some crypters may corrupt the branch value, reset it explicitly.
     */
    write16(0x601a, (unsigned char*)&hdr->ph_branch);

    /*
     * Save the effective size of the GEMDOS program.
     */
    prog->dsize = sz;

    return 0;

dump:
    LOG_ERROR("Program dec0ding failed!\n");
    dump_hdr(prog);
    return 1;
}

/*****************************************************************************
 * Toxic Packer v1.0 by NTM/Cameo ^ The Replicants
 *****************************************************************************/

#define TP1_OFF 0x1f2

static int decode_tp1 (prog_t* prog, unsigned char* buf, size_t size)
{
    uint32_t key32 = 0xbabebabe;
    uint16_t key16;
    uint16_t w16;
    size_t   i;

    (void) prog;

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

DECLARE_PATTERN(pattern1_tp1,
    PATTERN_ANY,
    0x94, 0, 80,
    PATTERN_BUFFER(
    0x42, 0xb9, 0x00, 0xff, 0xfa, 0x06,	/* clr.l $fffa06 */
    0x2b, 0x47, 0x00, 0x24,		/* move.l d7,$24(a5) */
    0x2b, 0x47, 0x00, 0x10,		/* move.l d7,$10(a5) */
    0xe4, 0x98,				/* ror.l #2,d0 */
    0xd0, 0xad, 0x00, 0x24,		/* add.l $24(a5),d0 */
    0x90, 0xad, 0x00, 0x10,		/* sub.l $10(a5),d0 */
    0x46, 0x79, 0x00, 0xff, 0x82, 0x40,	/* not.w $ff8240 */
    0x4e, 0x73,				/* rte */
    0x20, 0x3c, 0x12, 0x34, 0x56, 0x78,	/* move.l #$12345678,d0 */
    0x41, 0xfa, 0x01, 0x36,		/* lea pc+$138,a0 */
    0x43, 0xfa, 0x2d, 0xf2,		/* lea pc+$2df4,a1 */
    0x20, 0x2a, 0x00, 0x24,		/* move.l $24(a2),d0 */
    0xb1, 0x58,				/* 1: eor.w d0,(a0)+ */
    0xe6, 0x58,				/* ror.w #3,d0 */
    0x06, 0x40, 0x98, 0x76,		/* addi.w #$8976,d0 */
    0x4e, 0x42,				/* trap #2 */
    0xb3, 0xc8,				/* cmpa.l a0,a1 */
    0x6c, 0x00, 0xff, 0xf2,		/* bge 1b*/
    0x21, 0xf8, 0x02, 0x00, 0x00, 0x68,	/* move.l $200.w,$68.w */
    0x23, 0xf8, 0x02, 0x04,
    0x00, 0xff, 0xfa, 0x06		/* move.l $204,$fffa06 */
    )
    );

DECLARE_PROTECTION(prot_tp1,
    "Toxic Packer v1.0 by NTM/Cameo ^ The Replicants",
    TP1_OFF,
    PATTERNS_LIST(
    &pattern1_tp1
    ),
    decode_tp1,
    NULL
    );

/*****************************************************************************
 * Little Protection v01 by R.AL ^ The Replicants
 * Supposedly installed by the Toxic Packer v2.0 by NTM/Cameo ^ The Replicants
 *****************************************************************************/

#define RAL_LP_OFF 0x356

static int decode_ral_lp (prog_t* prog, unsigned char* buf, size_t size)
{
    uint32_t key32 = 0x6085c752;
    uint16_t w16;
    size_t   i;

    (void) prog;

    for (i = 0; i < size; i += SIZE_16) {
	key32  = (key32 & (uint32_t) 0x0000ffff) * (uint32_t) 0x00003141;
	key32 += 1;

	w16    = read16(buf + i);

	w16   ^= (uint16_t) (key32 & (uint32_t) 0x0000ffff);

	write16(w16, buf + i);
    }

    return 0;
}

DECLARE_PATTERN(pattern1_ral_lp,
    PATTERN_ANY,
    0x3c, 0, 56,
    PATTERN_BUFFER(
    0x11, 0xd8, 0x00, 0x7f,		/* move.b (a0)+, $7c.w */
    0xd0, 0xb8, 0x00, 0x7c,		/* add.l $7c.w,d0 */
    0xb1, 0xfc, 0x00, 0x00, 0x35, 0x3a, /* cmpa.l #$353a,a0 */
    0x6d, 0x04,				/* blt.s 1f */
    0x41, 0xf8, 0x32, 0x00,		/* lea $3200.w,a0 */
    0xd0, 0xb8, 0x00, 0x24,		/* 1: add.l $24.w,d0 */
    0xd0, 0xaf, 0x00, 0x02,		/* add.l 2(a7),d0 */
    0x00, 0x57, 0xa7, 0x10,		/* ori.w #$a710,(a7) */
    0x4e, 0x73,				/* rte */
    0x42, 0x80,				/* clr.l d0 */
    0x42, 0xb8, 0x00, 0x7c,		/* clr.l $7c.w */
    0x41, 0xf8, 0x32, 0x00,		/* lea $3200,a0 */
    0x21, 0xfc, 0x00, 0x00, 0x32, 0x22,
    0x00, 0x24,				/* move.l #$3222,$24.w */
    0x46, 0xfc, 0xa7, 0x00		/* move #$a700,sr */
    )
    );

DECLARE_PROTECTION(prot_ral_lp,
    "Little Protection v01 by R.AL ^ The Replicants",
    RAL_LP_OFF,
    PATTERNS_LIST(
    &pattern1_ral_lp
    ),
    decode_ral_lp,
    NULL
    );

/*****************************************************************************
 * Megaprot v0.02 by R.AL ^ The Replicants
 * Installed by the Toxic Packer v3.0 by NTM/Cameo ^ The Replicants
 * https://demozoo.org/productions/95784/
 *****************************************************************************/

#define RAL_MP_OFF 0x822

static int decode_ral_mp (prog_t* prog, unsigned char* buf, size_t size)
{
    uint32_t key32 = 0xe45d2af8;
    uint32_t w32;
    uint32_t bit1;
    uint32_t bit21;
    size_t   i;

    (void) prog;

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

DECLARE_PATTERN(pattern1_ral_mp,
    PATTERN_ANY,
    0x36, 0, 50,
    PATTERN_BUFFER(
    0x20, 0x78, 0x04, 0x26,		/* movea.l $426.w,a0 */
    0x20, 0xb8, 0x04, 0x2a,		/* move.l $42a.w,(a0) */
    0x20, 0x6f, 0x00, 0x02,		/* movea.l 2(a7),a0 */
    0x21, 0xc8, 0x04, 0x26,		/* move.l a0,$426.w */
    0x21, 0xd0, 0x04, 0x2a,		/* move.l (a0),$42a.w */
    0x20, 0x28, 0xff, 0xfc,		/* move.l -4(a0),d0 */
    0x46, 0x80,				/* not.l d0 */
    0x48, 0x40,				/* swap d0 */
    0xb1, 0x90,				/* eor.l d0,(a0) */
    0x4e, 0x73,				/* rte */
    0x41, 0xfa, 0xff, 0xde,		/* lea pc-$20,a0 */
    0x21, 0xc8, 0x00, 0x24,		/* move.l a0,$24.w */
    0x41, 0xfa, 0xff, 0xc8,		/* lea pc-$36,a0 */
    0x21, 0xc8, 0x00, 0x10,		/* move.l a0,$10.w */
    0x4a, 0xfc				/* illegal */
    )
    );

DECLARE_PATTERN(pattern2_ral_mp,
    PATTERN_ANY,
    0x81a, 0, 8,
    PATTERN_BUFFER(
    0x63, 0x73, 0x97, 0xeb, 0xd8, 0x13, 0xd2, 0xfa /* Encrypted code */
    )
    );

DECLARE_PROTECTION(prot_ral_mp,
    "Megaprot v0.02 by R.AL ^ The Replicants",
    RAL_MP_OFF,
    PATTERNS_LIST(
    &pattern1_ral_mp,
    &pattern2_ral_mp
    ),
    decode_ral_mp,
    NULL
    );

/*****************************************************************************
 * Sly Packer v2.0 by Orion ^ The Replicants
 * https://demozoo.org/productions/127902/
 *****************************************************************************/

#define SLY_OFF 0x720

static int calc_rand_sly (unsigned char* buf, uint16_t* rand)
{
    uint32_t w32;
    uint16_t rand16;

    w32    = read32(buf - SLY_OFF + 0x67c);
    w32    = w32 ^ (uint32_t) 0xbbb7dc8a;

    rand16 = (uint16_t) (w32 & (uint32_t) 0x0000ffff);

    *rand  = rand16;

    return 0;
}

static int decode_sly (prog_t* prog, unsigned char* buf, size_t size)
{
    uint32_t key32;
    uint16_t rand16;
    uint16_t w16;
    size_t   i;

    (void) prog;

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

DECLARE_PATTERN(pattern1_sly,
    PATTERN_ANY,
    0xac, 0, 28,
    PATTERN_BUFFER(
    0x41, 0xf8, 0x82, 0x09,		/* lea $ffff8209.w,a0 */
    0x10, 0x10,				/* move.b (a0),d0 */
    0x12, 0x10,				/* 1: move.b (a0),d1 */
    0xb2, 0x00,				/* cmp.b d0,d1 */
    0x67, 0xfa,				/* beq.s 1b */
    0x02, 0x01, 0x00, 0x1f,		/* andi.b #$1f,d1 */
    0x94, 0x01,				/* sub.b d1,d2 */
    0xe5, 0x29,				/* lsl.b d2,d1 */
    0x4f, 0xf8, 0x00, 0x14,		/* lea $14.w,a7 */
    0x46, 0xfc, 0xff, 0xff		/* move #$ffff,sr */
    )
    );

DECLARE_PATTERN(pattern2_sly,
    PATTERN_ANY,
    0x6e2, 0, 22,
    PATTERN_BUFFER(
    0xd0, 0xb8, 0x00, 0x24,		/* add.l $24.w,d0 */
    0xb3, 0x80,				/* eor.l d1,d0 */
    0x48, 0x40,				/* swap d0 */
    0x51, 0xca, 0xff, 0xf4,		/* dbf d2,pc-$a */
    0xb1, 0x91,				/* eor.l d0,(a1) */
    0x4c, 0xf8, 0x07, 0x07, 0x00, 0x40,	/* movem.l $40.w,d0-d2/a0-a2 */
    0x4e, 0x73				/* rte */
    )
    );

DECLARE_PROTECTION(prot_sly,
    "Sly Packer v2.0 by Orion ^ The Replicants",
    SLY_OFF,
    PATTERNS_LIST(
    &pattern1_sly,
    &pattern2_sly
    ),
    decode_sly,
    NULL
    );

/*****************************************************************************
 * Cooper v0.5 by Cameo ^ The Replicants
 * https://demozoo.org/productions/96052/
 *****************************************************************************/

#define COOPER5_OFF 0x6d0

static int calc_rand_cooper5 (unsigned char* buf, uint16_t* rand)
{
    uint32_t w32;
    uint16_t rand16;

    w32    = read32(buf - COOPER5_OFF + 0x3a6);

    w32   ^= (uint32_t) 0x0b364000;

    rand16 = (uint16_t) 0x1c86 + (uint16_t) (w32 & (uint32_t) 0x0000ffff);

    *rand  = rand16;

    return 0;
}

static int decode_cooper5 (prog_t* prog, unsigned char* buf, size_t size)
{
    uint32_t key32;
    uint16_t rand16;
    uint8_t  w8;
    size_t   i;

    (void) prog;

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

#define PATTERN_TVD_COOPER						\
    0x20, 0x78, 0x00, 0x24,		/* movea.l $24.w,a0 */		\
    0xd0, 0xe8, 0x00, 0x02,		/* adda.w 2(a0),a0 */		\
    0x7c, 0x45,				/* moveq #$45,d6 */		\
    0x42, 0xb8, 0x00, 0x10,		/* clr.l $10.w */		\
    0x42, 0xb8, 0xfa, 0x06,		/* clr.l $fffffa06.w */		\
    0x49, 0xd0,				/* lea (a0),a4 */		\
    0xbb, 0x58,				/* 1: eor.w d5,(a0)+ */		\
    0x51, 0xce, 0xff, 0xfc,		/* dbf d6,1b */			\
    0x60, 0x08,				/* bra.s 3f */			\
    0x7c, 0x45,				/* moveq #$45,d6 */		\
    0xbb, 0x5c,				/* 2: eor.w d5,(a4)+ */		\
    0x51, 0xce, 0xff, 0xfc,		/* dbf d6,2b */			\
    0x4e, 0x73				/* 3: rte */

#define PATTERN_TRACE_COOPER						\
    0xdb, 0x97,				/* add.l d5,(a7) */		\
    0x22, 0x97,				/* move.l (a7),(a1) */		\
    0x23, 0x57, 0x00, 0x0c,		/* move.l (a7),$c(a1) */	\
    0x3e, 0x93,				/* move.w (a3),(a7) */		\
    0x06, 0x57, 0x0b, 0xe7,		/* addi.w #$be7,(a7) */		\
    0x46, 0xfc,	0xff, 0xff		/* move #$ffff,sr */

DECLARE_PATTERN(pattern1_cooper5,
    PATTERN_ANY,
    0x620, 0, 38,
    PATTERN_BUFFER(
    PATTERN_TVD_COOPER
    )
    );

DECLARE_PATTERN(pattern2_cooper5,
    PATTERN_ANY,
    0x136, 0, 18,
    PATTERN_BUFFER(
    PATTERN_TRACE_COOPER
    )
    );

DECLARE_PROTECTION(prot_cooper5,
    "Cooper v0.5 by Cameo ^ The Replicants",
    COOPER5_OFF,
    PATTERNS_LIST(
    &pattern1_cooper5,
    &pattern2_cooper5
    ),
    decode_cooper5,
    NULL
    );

/*****************************************************************************
 * Cooper v0.6 by Cameo ^ The Replicants
 * https://demozoo.org/productions/127892/
 *****************************************************************************/

#define COOPER6_OFF 0x782

static int calc_rand_cooper6 (unsigned char* buf, uint16_t* rand)
{
    uint32_t w32;
    uint16_t rand16;

    w32    = read32(buf - COOPER6_OFF + 0x460);

    w32   ^= (uint32_t) 0x48028910;

    rand16 = (uint16_t) 0x1c86 + (uint16_t) (w32 & (uint32_t) 0x0000ffff);

    *rand  = rand16;

    return 0;
}

static int decode_cooper6 (prog_t* prog, unsigned char* buf, size_t size)
{
    uint32_t key32;
    uint32_t rand32;
    uint16_t rand16;
    uint8_t  w8;
    size_t   i;

    (void) prog;

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

DECLARE_PATTERN(pattern1_cooper6,
    PATTERN_ANY,
    0x6d2, 0, 38,
    PATTERN_BUFFER(
    PATTERN_TVD_COOPER
    )
    );

DECLARE_PATTERN(pattern2_cooper6,
    PATTERN_ANY,
    0xf4, 0, 18,
    PATTERN_BUFFER(
    PATTERN_TRACE_COOPER
    )
    );

DECLARE_PROTECTION(prot_cooper6,
    "Cooper v0.6 by Cameo ^ The Replicants",
    COOPER6_OFF,
    PATTERNS_LIST(
    &pattern1_cooper6,
    &pattern2_cooper6
    ),
    decode_cooper6,
    NULL
    );

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

static int decode_abx (prog_t* prog, unsigned char* buf, uint16_t sub_count,
		       size_t size, size_t size_orig, uint16_t reloc)
{
    uint16_t key16;
    uint8_t  key8;
    uint16_t rand16;
    uint16_t w16;
    uint8_t  w8;
    uint32_t i;

    (void) prog;

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
 * Anti-bitos v1.0 by Illegal ^ The Replicants
 *****************************************************************************/

#define AB100_OFF 0x432

static int decode_ab100 (prog_t* prog, unsigned char* buf, size_t size)
{
    return decode_abx(prog,
		      buf,
		      2,
		      (size_t) (read16(buf - AB100_OFF + 0x14) << 1),
		      size,
		      read16(buf - AB100_OFF + 0x16));
}

#define PATTERN_INIT_AB							\
    0x41, 0xfa, 0x00, 0xa6,		/* lea pc+$a8,a0 */		\
    0x43, 0xfa, 0x00, 0xce,		/* lea pc+$d0,a1 */		\
    0x45, 0xfa, 0x00, 0x90,		/* lea pc+$92,a2 */		\
    0x21, 0xc8, 0x00, 0x10,		/* move.l a0,$10.w */		\
    0x21, 0xc9, 0x00, 0x80,		/* move.l a1,$80.w */		\
    0x21, 0xca, 0x00, 0x24		/* move.l a2,$24.w */

#define PATTERN_TVD_AB							\
    0x48, 0x50,				/* pea (a0) */			\
    0x20, 0x6f, 0x00, 0x06,		/* movea.l 6(a7),a0 */		\
    0x4e, 0x40,				/* trap #0 */			\
    0x4a, 0xfc,				/* illegal */			\
    0x20, 0x5f,				/* movea.l (a7)+,a0 */		\
    0x4e, 0x73,				/* rte */			\
    0x48, 0xe7, 0xc0, 0xc0,		/* movem.l d0-d1/a0-a1,-(a7) */	\
    0x22, 0x48,				/* movea.l a0,a1 */		\
    0x20, 0x28, 0xff, 0xf4,		/* move.l -$c(a0),d0 */		\
    0x22, 0x28, 0xff, 0xf0,		/* move.l -$10(a0),d1 */	\
    0xb1, 0x81,				/* eor.l d0,d1 */		\
    0x46, 0x81				/* not.l d1 */

DECLARE_PATTERN(pattern1_ab100,
    PATTERN_ANY,
    0x84, 0,  20,
    PATTERN_BUFFER(
    0x41, 0xfa, 0xff, 0x92,		/* lea pc-$6c,a0 */
    0x30, 0xb8, 0x82, 0x40,		/* move.w $ffff8240.w,(a0) */
    0x11, 0xf8, 0xfa, 0x07, 0x00, 0xf4,	/* move.b $fffffa07.w,$f4.w */
    0x11, 0xf8,	0xfa, 0x09, 0x00, 0xf8	/* move.b $fffffa09.w,$f8.w */
    )
    );

DECLARE_PATTERN(pattern2_ab100,
    PATTERN_ANY,
    0x9c, 0, 36,
    PATTERN_BUFFER(
    PATTERN_INIT_AB,
    0x21, 0xfc, 0x00, 0x0f,
    0x80, 0x00, 0x00, 0x30,		/* move.l #$f8000,$30.w */
    0x46, 0xfc, 0xa3, 0x00		/* move #$a300,sr */
    )
    );

DECLARE_PATTERN(pattern3_ab100,
    PATTERN_ANY,
    0x136, 0, 38,
    PATTERN_BUFFER(
    PATTERN_TVD_AB,
    0x0a, 0x81, 0x12, 0x34, 0x56, 0x78	/* eori.l #$12345678,d1 */
    )
    );

DECLARE_PATTERN(pattern4_ab100,
    PATTERN_ANY,
    0x0, 0, 2,
    PATTERN_BUFFER(
    0x60, 0x30				/* bra.s pc+$32 */
    )
    );

DECLARE_PROTECTION(prot_ab100,
    "Anti-bitos v1.0 by Illegal ^ The Replicants",
    AB100_OFF,
    PATTERNS_LIST(
    &pattern1_ab100,
    &pattern2_ab100,
    &pattern3_ab100,
    &pattern4_ab100
    ),
    decode_ab100,
    NULL
    );

/*****************************************************************************
 * Anti-bitos v1.4 (a & b) by Illegal ^ The Replicants
 * https://demozoo.org/productions/123960/
 *****************************************************************************/

#define AB140A_OFF 0x676
#define AB140B_OFF 0x670

static int decode_ab140a (prog_t* prog, unsigned char* buf, size_t size)
{
    return decode_abx(prog,
		      buf,
		      2,
		      (size_t) (read16(buf - AB140A_OFF + 0x1a) << 1),
		      size,
		      read16(buf - AB140A_OFF + 0x1c));
}

DECLARE_PATTERN(pattern1_ab140a,
    PATTERN_ANY,
    0x8a, 0, 20,
    PATTERN_BUFFER(
    0x11, 0xfc, 0x00, 0x12, 0xfc, 0x02,	/* move.b #$12,$fffffc02.w */
    0x41, 0xfa, 0xff, 0x8c,		/* lea pc-$72,a0 */
    0x30, 0xb8, 0x82, 0x40,		/* move.w $ffff8240.w,(a0) */
    0x11, 0xf8, 0xfa, 0x07, 0x00, 0xf4	/* move.b $fffffa07.w,$f4.w */
    )
    );

DECLARE_PATTERN(pattern2_ab140a,
    PATTERN_ANY,
    0xa8, 0, 36,
    PATTERN_BUFFER(
    PATTERN_INIT_AB,
    0x21, 0xfc, 0x00, 0x0f,
    0x00, 0x00, 0x00, 0x30,		/* move.l #$f0000,$30.w */
    0x46, 0xfc, 0xa3, 0x00		/* move #$a300,sr */
    )
    );

DECLARE_PATTERN(pattern3_ab140a,
    PATTERN_ANY,
    0x142, 0, 38,
    PATTERN_BUFFER(
    PATTERN_TVD_AB,
    0x0a, 0x81, 0x12, 0x34, 0x56, 0x78	/* eori.l #$12345678,d1 */
    )
    );

DECLARE_PATTERN(pattern4_ab140a,
    PATTERN_ANY,
    0x0, 0, 2,
    PATTERN_BUFFER(
    0x60, 0x36				/* bra.s pc+$38 */
    )
    );

DECLARE_PROTECTION_PARENT(prot_ab140a,
    "Anti-bitos v1.4 by Illegal ^ The Replicants",
    'a',
    AB140A_OFF,
    PATTERNS_LIST(
    &pattern1_ab140a,
    &pattern2_ab140a,
    &pattern3_ab140a,
    &pattern4_ab140a
    ),
    decode_ab140a,
    NULL
    );

static int decode_ab140b (prog_t* prog, unsigned char* buf, size_t size)
{
    return decode_abx(prog,
		      buf,
		      2,
		      (size_t) (read16(buf - AB140B_OFF + 0x1a) << 1),
		      size,
		      read16(buf - AB140B_OFF + 0x1c));
}

DECLARE_PATTERN(pattern1_ab140b,
    PATTERN_ANY,
    0x8a, 0, 20,
    PATTERN_BUFFER(
    0x41, 0xfa, 0xff, 0x92,		/* lea pc-$6c,a0 */
    0x30, 0xb8, 0x82, 0x40,		/* move.w $ffff8240.w,(a0) */
    0x11, 0xf8, 0xfa, 0x07, 0x00, 0xf4,	/* move.b $fffffa07.w,$f4.w */
    0x11, 0xf8,	0xfa, 0x09, 0x00, 0xf8	/* move.b $fffffa09.w,$f8.w */
    )
    );

DECLARE_PATTERN(pattern2_ab140b,
    PATTERN_ANY,
    0xa2, 0, 36,
    PATTERN_BUFFER(
    PATTERN_INIT_AB,
    0x21, 0xfc, 0x00, 0x0f,
    0x00, 0x00, 0x00, 0x30,		/* move.l #$f0000,$30.w */
    0x46, 0xfc, 0xa3, 0x00		/* move #$a300,sr */
    )
    );

DECLARE_PATTERN(pattern3_ab140b,
    PATTERN_ANY,
    0x13c, 0, 38,
    PATTERN_BUFFER(
    PATTERN_TVD_AB,
    0x0a, 0x81, 0x12, 0x34, 0x56, 0x78	/* eori.l #$12345678,d1 */
    )
    );

DECLARE_PATTERN(pattern4_ab140b,
    PATTERN_ANY,
    0x0, 0, 2,
    PATTERN_BUFFER(
     0x60, 0x36				/* bra.s pc+$38 */
    )
    );

DECLARE_PROTECTION_VARIANT(prot_ab140b,
    &prot_ab140a,
    'b',
    AB140B_OFF,
    PATTERNS_LIST(
    &pattern1_ab140b,
    &pattern2_ab140b,
    &pattern3_ab140b,
    &pattern4_ab140b
    ),
    decode_ab140b,
    NULL
    );

/*****************************************************************************
 * Anti-bitos v1.6 by Illegal ^ The Replicants
 * https://demozoo.org/productions/127893/
 *****************************************************************************/

#define AB160_OFF 0x5fc

static int decode_ab160 (prog_t* prog, unsigned char* buf, size_t size)
{
    return decode_abx(prog,
		      buf,
		      3,
		      (size_t) (read32(buf - AB160_OFF + 0x2e) << 1),
		      size,
		      read16(buf - AB160_OFF + 0x32));
}

DECLARE_PATTERN(pattern1_ab160,
    PATTERN_ANY,
    0x7e, 0, 36,
    PATTERN_BUFFER(
    PATTERN_INIT_AB,
    0x21, 0xfc, 0x00, 0x0f,
    0x00, 0x00, 0x00, 0x30,		/* move.l #$f0000,$30.w */
    0x46, 0xfc, 0xa3, 0x00		/* move #$a300,sr */
    )
    );

DECLARE_PATTERN(pattern2_ab160,
    PATTERN_ANY,
    0x118, 0, 38,
    PATTERN_BUFFER(
    PATTERN_TVD_AB,
    0x0a, 0x81, 0x52, 0x45, 0x50, 0x53	/* eori.l #'REPS',d1 */
    )
    );

DECLARE_PATTERN(pattern3_ab160,
    PATTERN_ANY,
    0x0, 0, 2,
    PATTERN_BUFFER(
    0x60, 0x38				/* bra.s pc+$3a */
    )
    );

DECLARE_PROTECTION(prot_ab160,
    "Anti-bitos v1.6 by Illegal ^ The Replicants",
    AB160_OFF,
    PATTERNS_LIST(
    &pattern1_ab160,
    &pattern2_ab160,
    &pattern3_ab160
    ),
    decode_ab160,
    NULL
    );

/*****************************************************************************
 * Anti-bitos v1.61 by Illegal ^ The Replicants
 *****************************************************************************/

#define AB161_OFF 0x646

static int decode_ab161 (prog_t* prog, unsigned char* buf, size_t size)
{
    return decode_abx(prog,
		      buf,
		      3,
		      (size_t) (read32(buf - AB161_OFF + 0x32) << 1),
		      size,
		      read16(buf - AB161_OFF + 0x36));
}

DECLARE_PATTERN(pattern1_ab161,
    PATTERN_ANY,
    0x82, 0, 36,
    PATTERN_BUFFER(
    PATTERN_INIT_AB,
    0x21, 0xfc, 0x00, 0x0f,
    0x00, 0x00, 0x00, 0x30,		/* move.l #$f0000,$30.w */
    0x46, 0xfc, 0xa3, 0x00		/* move #$a300,sr */
    )
    );

DECLARE_PATTERN(pattern2_ab161,
    PATTERN_ANY,
    0x11c, 0, 38,
    PATTERN_BUFFER(
    PATTERN_TVD_AB,
    0x0a, 0x81, 0x52, 0x45, 0x50, 0x53	/* eori.l #'REPS',d1 */
    )
    );

DECLARE_PATTERN(pattern3_ab161,
    PATTERN_ANY,
    0x0, 0, 2,
    PATTERN_BUFFER(
    0x60, 0x3c				/* bra.s pc+$3e */
    )
    );

DECLARE_PROTECTION(prot_ab161,
    "Anti-bitos v1.61 by Illegal ^ The Replicants",
    AB161_OFF,
    PATTERNS_LIST(
    &pattern1_ab161,
    &pattern2_ab161,
    &pattern3_ab161
    ),
    decode_ab161,
    NULL
    );

/*****************************************************************************
 * Generic Zippy's Little Protection decrypting routines
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

static int decode_zippy20x (prog_t* prog, unsigned char* buf, size_t size)
{
    uint32_t key32;
    uint32_t rand32;
    uint8_t  w8;
    size_t   i;

    (void) prog;

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
 * Little Protection v2.05 by Zippy ^ The Medway Boys
 *****************************************************************************/

#define ZIPPY205_OFF 0x652

#define PATTERN_TVD_ZIPPY						\
    0x90, 0x10,				/* sub.b (a0),d0 */		\
    0x02, 0x40, 0x00, 0xff,		/* andi.w #$ff,d0 */		\
    0x51, 0xc8, 0xff, 0xfe,		/* 1: dbf d0,1b */		\
    0xbf, 0x95,				/* eor.l d7,(a5) */		\
    0xee, 0x9f,				/* ror.l #7,d7 */		\
    0x2c, 0x6f, 0x00, 0x02,		/* movea.l 2(a7),a6 */		\
    0xde, 0x10,				/* add.b (a0),d7 */		\
    0x40, 0xc0,				/* move sr,d0 */		\
    0xb1, 0x07,				/* eor.b d0,d7 */		\
    0xbf, 0x96,				/* eor.l d7,(a6) */		\
    0x2a, 0x4e,				/* movea.l a6,a5 */		\
    0x4e, 0x73				/* rte */

#define PATTERN_TRACE_ZIPPY						\
    0x21, 0xfc, 0x00, 0x07, 0x70, 0x00,					\
    0x00, 0x24,				/* move.l #$77000,$24.w */	\
    0x21, 0xfc, 0x12, 0x34, 0x56, 0x78,					\
    0x00, 0x10,				/* move.l #$12345678,$10.w */	\
    0x4c, 0xfa, 0x7f, 0xff, 0x00, 0x20,	/* movem.l pc+$22,d0-a6*/	\
    0x4e, 0x72, 0x23, 0x00,		/* stop #$2300 */		\
    0x4e, 0x72, 0x23, 0x00,		/* stop #$2300 */		\
    0x46, 0xfc,	0x27, 0x00,		/* move #$2700,sr */		\
    0x12, 0x10,				/* 1: move.b (a0),d1 */		\
    0x67, 0xfc,				/* beq.s 1b */			\
    0x90, 0x01,				/* sub.b d1,d0 */		\
    0xe1, 0x28,				/* lsl.b d0,d0 */		\
    0x4b, 0xfa, 0xff, 0xca,		/* lea pc-$34,a5 */		\
    0x46, 0xfc,	0xa7, 0x00		/* move #$a700,sr */

DECLARE_PATTERN(pattern1_zippy205,
    PATTERN_ANY,
    0xe4, 0, 30,
    PATTERN_BUFFER(
    PATTERN_TVD_ZIPPY
    )
    );

DECLARE_PATTERN(pattern2_zippy205,
    PATTERN_ANY,
    0x10c, 0, 50,
    PATTERN_BUFFER(
    PATTERN_TRACE_ZIPPY
    )
    );

DECLARE_PATTERN(pattern3_zippy205,
    PATTERN_ANY,
    0x2c, 0, 20,
    PATTERN_BUFFER(
    0x4d, 0xfa, 0xfe, 0xd2,		/* lea pc-$12c,a6 */
    0x23, 0xcf, 0x00, 0x00, 0x01, 0x04,	/* move.l a7,start+$104 */
    0x40, 0xc0,				/* move sr,d0 */
    0x08, 0x00, 0x00, 0x0d,		/* btst #$d,d0 */
    0x66, 0x00, 0x00, 0xc4		/* bne pc+$c6 */
    )
    );

DECLARE_PROTECTION(prot_zippy205,
    "Little Protection v2.05 by Zippy ^ The Medway Boys",
    ZIPPY205_OFF,
    PATTERNS_LIST(
    &pattern1_zippy205,
    &pattern2_zippy205,
    &pattern3_zippy205
    ),
    decode_zippy20x,
    NULL
    );

/*****************************************************************************
 * Little Protection v2.06 by Zippy ^ The Medway Boys
 *****************************************************************************/

#define ZIPPY206_OFF 0x64e

DECLARE_PATTERN(pattern1_zippy206,
    PATTERN_ANY,
    0xe0, 0, 30,
    PATTERN_BUFFER(
    PATTERN_TVD_ZIPPY
    )
    );

DECLARE_PATTERN(pattern2_zippy206,
    PATTERN_ANY,
    0x108, 0, 50,
    PATTERN_BUFFER(
    PATTERN_TRACE_ZIPPY
    )
    );

DECLARE_PATTERN(pattern3_zippy206,
    PATTERN_ANY,
    0x2c, 0, 20,
    PATTERN_BUFFER(
    0x4d, 0xfa, 0xfe, 0xd2,		/* lea pc-$12c,a6 */
    0x4b, 0xfa, 0x00, 0xce,		/* lea pc+$d0,a5 */
    0x2a, 0x8f,				/* move.l a7,(a5) */
    0x40, 0xc0,				/* move sr,d0 */
    0x08, 0x00, 0x00, 0x0d,		/* btst #$d,d0 */
    0x66, 0x00, 0x00, 0xc0		/* bne pc+$c2 */
    )
    );

DECLARE_PROTECTION(prot_zippy206,
    "Little Protection v2.06 by Zippy ^ The Medway Boys",
    ZIPPY206_OFF,
    PATTERNS_LIST(
    &pattern1_zippy206,
    &pattern2_zippy206,
    &pattern3_zippy206
    ),
    decode_zippy20x,
    NULL
    );

/*****************************************************************************
 * Lock-o-matic v1.3 by Yoda ^ The Marvellous V8
 *****************************************************************************/

#define LOCKOMATIC_OFF 0x3fc

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
    unsigned char* tr_start = buf - LOCKOMATIC_OFF + 0xfa;
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

static uint32_t decode_routs_lockomatic (unsigned char* buf, unsigned int size,
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

static int decode_lockomatic (prog_t* prog, unsigned char* buf, size_t size)
{
    prog_hdr_t*  hdr = (prog_hdr_t*) buf;
    uint32_t     key32;
    uint32_t     rand32;
    uint32_t     szt32;
    uint32_t     szd32;
    uint32_t     szb32;
    uint32_t     w32;
    size_t       i;

    (void) prog;

    key32  = read32(buf - LOCKOMATIC_OFF + 0xfa + 0x3a);

    if (calc_rand_lockomatic(buf, &rand32)) {
	LOG_ERROR("Cannot determine random number\n");
	return 1;
    }

    key32 ^= rand32;

    rand32 = decode_routs_lockomatic(buf - LOCKOMATIC_OFF + 0x16c, 0x284,
				     rand32);

    rand32 = decode_routs_lockomatic(buf - LOCKOMATIC_OFF + 0x202, 0x1ee,
				     0x88dd6a16);

    key32 ^= rand32;
    key32 ^= (uint32_t) 0x00030000;

    (void) decode_routs_lockomatic(buf - LOCKOMATIC_OFF + 0x2c4, 0x12c, key32);

    key32  = key32 >> 16;
    key32 ^= (uint32_t) 0x1bcc8462;

    for (i = 0; i < size; i += SIZE_32) {
	w32 = read32(buf + i);

	w32   ^= key32;
	key32 += 3;
	key32  = ROL32(key32, 5);

	write32(w32, buf + i);
    }

    szt32 = read32(buf - LOCKOMATIC_OFF + 0x320);
    write32(szt32, (unsigned char*)&hdr->ph_tlen);

    szd32 = read32(buf - LOCKOMATIC_OFF + 0x324);
    write32(szd32, (unsigned char*)&hdr->ph_dlen);

    szb32 = read32(buf - LOCKOMATIC_OFF + 0x328);
    write32(szb32, (unsigned char*)&hdr->ph_blen);

    write32(0x0, (unsigned char*)&hdr->ph_slen);
    write32(0x0, (unsigned char*)&hdr->ph_res1);
    write32(0x0, (unsigned char*)&hdr->ph_prgflags);
    write16(0x0, (unsigned char*)&hdr->ph_absflag);

    return 0;
}

DECLARE_PATTERN(pattern1_lockomatic,
    PATTERN_ANY,
    0xda, 0, 90,
    PATTERN_BUFFER(
    0x49, 0xfa, 0xff, 0xfe,			/* lea pc,a4 */
    0x77, 0x23,					/* dc.w $7723 */
    0x24, 0x39, 0x00, 0x00, 0x03, 0xee,		/* 1: move.l $3ee,d2 */
    0x34, 0x07,					/* move.w d7,d2 */
    0x48, 0x40,					/* swap d0 */
    0xb5, 0x00,					/* eor.b d2,d0 */
    0x51, 0xcb, 0xff, 0xf2,			/* dbf d3,1b */
    0x77, 0x7f,					/* dc.w $777f*/
    0x4e, 0xd6,					/* jmp (a6) */
    0x12, 0x34, 0x00, 0x00, 0x03, 0xb0,		/* data */
    0x43, 0xf8, 0x00, 0x08,			/* lea $8.w,a1 */
    0x08, 0x50, 0x36, 0x00,			/* bchg #0,(a0) */
    0x41, 0xfa, 0xff, 0xf6,			/* lea pc-$8,a0 */
    0x43, 0xfa, 0x00, 0x3e,			/* lea pc+$40,a1 */
    0x2e, 0x18,					/* 2: move.l (a0)+,d7 */
    0xbf, 0x80,					/* eor.l d7,d0 */
    0x56, 0x80,					/* addq.l #3,d0 */
    0xb1, 0xc9,					/* cmpa.l a1,a0 */
    0x65, 0x00, 0xff, 0xf6,			/* bcs 2b */
    0x54, 0x8c,					/* addq.l #2,a4 */
    0x2e, 0x0c,					/* move.l a4,d7 */
    0xbf, 0x80,					/* eor.l d7,d0 */
    0x2e, 0x2f, 0x00, 0x02,			/* move.l 2(a7),d7 */
    0xbf, 0x80,					/* eor.l d7,d0 */
    0x21, 0xfc, 0x00, 0x00, 0x03, 0xee,
    0x00, 0x10,					/* move.l #$3ee,$10.w */
    0x21, 0xfc, 0x00, 0x00, 0x03, 0xb0,
    0x00, 0x24,					/* move.l #$3b0,$24.w */
    0x4e, 0x75					/* rts */
    )
    );

DECLARE_PATTERN(pattern2_lockomatic,
    PATTERN_ANY,
    LOCKOMATIC_OFF, 0, 28,
    PATTERN_BUFFER(
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
    )
    );

DECLARE_PROTECTION(prot_lockomatic,
    "Lock-o-matic v1.3 by Yoda ^ The Marvellous V8",
    LOCKOMATIC_OFF,
    PATTERNS_LIST(
    &pattern1_lockomatic,
    &pattern2_lockomatic
    ),
    decode_lockomatic,
    NULL
    );

/*****************************************************************************
 * CID Encrypter v1.0bp by Mad + RAM ^ Criminals In Disguise (CID)
 *****************************************************************************/

#define CID10_OFF 0x680

static int decode_cid10 (prog_t* prog, unsigned char* buf, size_t size)
{
    uint16_t key16_1;
    uint16_t key16_2;
    uint16_t w16;
    size_t   i;

    (void) prog;

    size    = (size_t) read32(buf - CID10_OFF + 0x6);

    key16_1 = read16(buf - CID10_OFF + 0x216);
    key16_2 = read16(buf - CID10_OFF + 0x218);

    for (i = 0; i < size; i += SIZE_16) {
	w16      = read16(buf + i);

	w16     ^= key16_1;
	w16     ^= key16_2;

	key16_2 += key16_1;
	key16_1 += key16_2;

	write16(w16, buf + i);
    }

    return 0;
}

DECLARE_PATTERN(pattern1_cid10,
    PATTERN_ANY,
    0xa6, 0, 34,
    PATTERN_BUFFER(
    0x13, 0xfc, 0x00, 0x0a,
    0xff, 0xff, 0xfa, 0x21,		/* move.b #$a,$fffffa21 */
    0x13, 0xfc, 0x00, 0x03,
    0xff, 0xff, 0xfa, 0x1b,		/* move.b #3,$fffffa1b */
    0x46, 0xfc, 0x25, 0x00,		/* move #$2500,sr */
    0x48, 0x79, 0x00, 0x00, 0x00, 0xf2,	/* pea start+$f2 */
    0x23, 0xdf, 0x00, 0x00, 0x00, 0x10,	/* move.l (a7)+,$10 */
    0x4a, 0xfc				/* illegal */
    )
    );

DECLARE_PATTERN(pattern2_cid10,
    PATTERN_ANY,
    0x4c4, 0, 54,
    PATTERN_BUFFER(
    0x41, 0xf9, 0x00, 0x00, 0x06, 0x80,	/* lea start+$680,a0 */
    0x20, 0x39, 0x00, 0x00, 0x00, 0x06,	/* move.l start+$6,d0 */
    0xe2, 0x88,				/* lsr.l #1,d0 */
    0x32, 0x39, 0x00, 0x00, 0x00, 0x0a,	/* move.w pc+$a,d1 */
    0x34, 0x39, 0x00, 0x00, 0x02, 0x16,	/* move.w pc+$216,d2 */
    0x36, 0x39, 0x00, 0x00, 0x02, 0x18,	/* move.w pc+$218,d3 */
    0x23, 0xfc, 0x00, 0x00, 0x04, 0xf6,
    0x00, 0x00, 0x00, 0x10,		/* move.l #start+$4f6,$10 */
    0x22, 0x7c, 0x00, 0x00, 0x00, 0x00,	/* movea.l #0,a1 */
    0x60, 0x76,				/* bra.s pc+$78 */
    0x30, 0xc7,				/* move.w d7,(a0)+ */
    0xce, 0x41				/* and.w d1,d7 */
    )
    );

DECLARE_PATTERN(pattern3_cid10,
    PATTERN_ANY,
    0x560, 0, 28,
    PATTERN_BUFFER(
    0x53, 0x80,				/* subq.l #1,d0 */
    0x2f, 0x7c, 0x00, 0x00, 0x05, 0x78,
    0x00, 0x02,				/* move.l #start+$578,2(a7) */
    0x4e, 0x73,				/* rte */
    0x3e, 0x10,				/* 1: move.w (a0),d7 */
    0xb5, 0x47,				/* eor.w d2,d7 */
    0xb7, 0x47,				/* eor.w d3,d7 */
    0xd6, 0x42,				/* add.w d2,d3 */
    0xd4, 0x43,				/* add.w d3,d2 */
    0x4a, 0xfc,				/* illegal */
    0x4a, 0x80,				/* tst.l d0 */
    0x66, 0xf0				/* bne.s 1b */
    )
    );

DECLARE_PROTECTION(prot_cid10,
    "CID Encrypter v1.0bp by Mad + RAM ^ Criminals In Disguise",
    CID10_OFF,
    PATTERNS_LIST(
    &pattern1_cid10,
    &pattern2_cid10,
    &pattern3_cid10
    ),
    decode_cid10,
    NULL
    );

/*****************************************************************************
 *
 * Copylock Protection System by Rob Northen - Generic helper routines
 *
 * https://en.wikipedia.org/wiki/Rob_Northen_copylock
 *
 * Copylock systems can be divided into 2 series:
 * - Copylock systems series 1, created in 1988.
 * - Copylock systems series 2, created in 1989.
 *
 * Each series can be subdivided into 2 types:
 * - The wrapper type: self-decrypting program.
 * - The internal type: self-decrypting routine inside a host program.
 *
 * Both series use the "Trace Vector Decoder" (TVD) technique to obfuscate
 * the protection code. Every instruction is decrypted, run and then encrypted
 * again before moving on to the next instruction:
 * https://en.wikipedia.org/wiki/Trace_vector_decoder
 *
 * - Series 1 uses a single and static (in place) TVD routine.
 *   Each instruction is decrypted by XOR-ing it with the preceding encrypted
 *   instruction.
 *   http://www.atari-wiki.com/index.php/Rob_Northern_Decrypted1
 *
 * - Series 2 uses two different TVD routines, which are dynamically installed
 *   (pushed onto the stack).
 *   The first TVD routine decrypts each instruction by XOR-ing it with a key
 *   dynamically computed from registers sr, d1 and d2.
 *   Therefore the decoding of a new instruction depends on the result of the
 *   execution of the previous instructions.
 *   This TVD routine is only used for sequential instructions. It cannot be
 *   used for loops.
 *   The second TVD routine decrypts each instruction by XOR-ing it with a key
 *   computed from a magic value and the preceding encrypted instruction.
 *   This TVD routine is used for complex code (with loops), such as the
 *   key disk reading.
 *
 * Both series check if the exception vectors have been modified to prevent
 * the execution under a debugger.
 *
 * Both series read a key disk to compute a serial key in order to:
 * - decrypt the original unprotected program (wrapper type).
 * - return that serial key to the caller of the protected routine
 *   (internal type), so it can be checked on return or later.
 *
 * The serial key may also be used for extra tricks: stored in memory for
 * deferred checking, used to compute an extra magic key (also stored in
 * memory), used to decrypt portions of memory...
 *
 * In both series:
 * - The encrypted code of the internal type is in charge of reading the
 *   key disk and optionally of performing some extra tricks (vectors checking,
 *   special serial key usage as described above).
 * - The encrypted code of the wrapper type is similar to that of the internal
 *   type, but in addition:
 *   + The serial key is used to decrypt the original (wrapped) program,
 *     which is installed to its final destination and then executed.
 *     That program may be a GEMDOS program (it is then relocated by the
 *     protection code) or a raw binary program.
 *   + Some extra encrypted code is executed at the beginning of the
 *     protection, before reading the key disk.
 *     In series 1, it consists in nested decryption loops (each loop decrypts
 *     the rest of the protection).
 *     In series 2, it consists in a large number of sequential encrypted
 *     instructions which perform checks on the TDV routine, the SR value...
 *     Such extra encrypted code is of no use other than making the protection
 *     more difficult to trace under a debugger.
 *
 * Dec0de handles Rob Northen Copylock Systems as follows:
 * - When a wrapper type is provided, dec0de extracts the original unprotected
 *   program and provides useful details about the Copylock protection: the
 *   serial number and the memory address it is saved to, the use of extra
 *   tricks in the protection (extra magic value, special serial key usage).
 *   Such details may be needed to properly crack the protected software.
 * - When an internal type is provided, dec0de only provides the details needed
 *   to crack the protection (such as the serial number and how it is used).
 *
 * To this end, dec0de works as follows:
 * - It first performs static analysis of the protection in order to determine
 *   the location of the different parts of the protection and its behavior.
 * - It then performs dynamic (run-time) analysis of the protection in order
 *   to get the serial key and, in case of a wrapper type, to decrypt the
 *   protected program and to determine the destination where it will be
 *   executed.
 *
 * The dynamic analysis can only be performed on an Atari ST (protection code
 * must be partially executed). Therefore, Copylock protections can be removed
 * only if dec0de is run on a real or emulated Atari ST.
 *
 * When run on Linux, Mac OS or Windows, dec0de provides as much information
 * as possible, but the decryption process is skipped.
 *
 *****************************************************************************/

#define SERIAL_USAGE_NONE_ROBN		0x00
#define SERIAL_USAGE_DECODE_PROG_ROBN	0x01
#define SERIAL_USAGE_RETURN_ROBN	0x02
#define SERIAL_USAGE_SAVE_MEM_ROBN	0x04
#define SERIAL_USAGE_MAGIC_MEM_ROBN	0x08
#define SERIAL_USAGE_EOR_MEM_ROBN	0x10
#define SERIAL_USAGE_OTHER_MEM_ROBN	0x20
#define SERIAL_USAGE_UNKNOWN_ROBN	0x40

/*
 * Static and dynamic/run-time information about a Rob Northen Protection
 * system.
 */
typedef struct info_robn_t {
    uint32_t  magic32;
    /*
     * Static info: location of the different parts of the protection.
     */
    ssize_t   prog_off;
    ssize_t   start_off;
    ssize_t   pushtramp_off;
    ssize_t   decode_off;
    ssize_t   reloc_off;
    ssize_t   vecs_off;
    ssize_t   keydisk_off;
    ssize_t   serial_off;
    size_t    subrout_sz;

    int       serial_usage;

    /*
     * Dynamic (run-time) info: serial key value, final program destination...
     */
    int       prot_run;
    int       keydisk_hit;
    int       serial_valid;
    int       magic_valid;
    int       dstexec_valid;

    uint32_t  serial;
    uint32_t* serial_dst_addr;

    uint32_t  magic;
    uint32_t* magic_dst_addr;

    void*     dst_addr;
    size_t    entry_off;
    size_t    prog_len;
    size_t    zeroes_len;
} info_robn_t;

/*
 * Serial key usage.
 */
static struct {
    int         flag;
    const char* str;
} serial_usage_flag2str[] = {
    { SERIAL_USAGE_DECODE_PROG_ROBN, "Program dec0ding",         },
    { SERIAL_USAGE_RETURN_ROBN,      "Returned to the caller",   },
    { SERIAL_USAGE_SAVE_MEM_ROBN,    "Saved in memory",          },
    { SERIAL_USAGE_MAGIC_MEM_ROBN,   "Turned into a magic",      },
    { SERIAL_USAGE_EOR_MEM_ROBN,     "Xor-ed in memory",         },
    { SERIAL_USAGE_OTHER_MEM_ROBN,   "External memory dec0ding", },
    { SERIAL_USAGE_UNKNOWN_ROBN,     "Unknown",                  },
    { 0,                             NULL,                       },
};

/*
 * Initialize the static/run-time info.
 */
static void init_info_robn (info_robn_t* info)
{
    memset(info, 0, sizeof(info_robn_t));

    info->prog_off      = -1;
    info->start_off     = -1;
    info->pushtramp_off = -1;
    info->decode_off    = -1;
    info->reloc_off     = -1;
    info->vecs_off      = -1;
    info->keydisk_off   = -1;
    info->serial_off    = -1;

    info->serial_usage  = SERIAL_USAGE_NONE_ROBN;
}

/*
 * Dump the static/run-time info.
 * Works for both series and both types.
 */
static int print_info_robn (info_robn_t* info, const unsigned char* buf)
{
    unsigned int i;

    if (info) {

	PP_NEWLINE();

	LOG_INFO("Protection information:\n");

	LOG_INFO("Vectors anti-hijacking ... %s\n",
		 (info->vecs_off >= 0) ? "Yes" : "No");

	LOG_INFO("Key disk usage ........... %s\n",
		 (info->keydisk_off >= 0) ? "Yes" : "No");

	if (info->keydisk_off >= 0) {
	    const char* m = "Serial usage ............. %s\n";
	    const char* n = "                           %s\n";

	    for (i = 0; (serial_usage_flag2str[i].str != NULL); i++) {
		if (info->serial_usage & serial_usage_flag2str[i].flag) {
		    LOG_INFO(m, serial_usage_flag2str[i].str);
		    m = n;
		}
	    }

	    if (info->serial_valid) {
		if (info->serial != 0) {
		    LOG_INFO("Serial number ............ $%08x\n",
			     info->serial);
		} else {
		    LOG_INFO("Serial number ............ Invalid\n");
		}
	    } else {
		LOG_INFO("Serial number ............ %s\n",
			 info->keydisk_hit ? "Undefined" : "Unread");
	    }

	    if (info->serial_dst_addr) {
		LOG_INFO("Serial dest. address ..... $%zx\n",
			 (size_t) info->serial_dst_addr);
	    }

	    if (info->magic_valid) {
		LOG_INFO("Magic number ............. $%08x\n",
			 info->magic);
		if (info->magic_dst_addr) {
		    LOG_INFO("Magic dest. address ...... $%zx\n",
			     (size_t) info->magic_dst_addr);
		}
	    }
	}

	LOG_INFO("Enc0ded program type ..... %s\n",
		 (info->decode_off < 0) ? "None" :
		 ((info->prog_off < 0) ? "Unknown" :
		  ((info->reloc_off >= 0) ? "GEMDOS" : "Binary")));

	if (info->decode_off < 0) {
	    LOG_INFO("Protected subroutine ..... %s\n",
		     (info->subrout_sz != 0) ? "Yes" : "No");
	    LOG_INFO("Resume code offset ....... 0x%zx\n",
		     (size_t) info->prog_off);
	}

	if (info->dstexec_valid) {
	    if (info->dst_addr) {
		LOG_INFO("Dest. address ............ $%zx\n",
			 (size_t) info->dst_addr);
	    } else {
		LOG_INFO("Dest. address ............ Load address\n");
	    }

	    LOG_INFO("Entry offset ............. $%zx\n",
		     info->entry_off);

	    LOG_INFO("Program length ........... $%zx\n",
		     info->prog_len);

	    LOG_INFO("Zeroes length ............ $%zx\n",
		     info->zeroes_len);
	}

#ifdef DEBUG
	LOG_INFO("Magic32 .................. $%08x\n", info->magic32);
#endif

	if (info->decode_off < 0) {
	    PP_NEWLINE();

	    LOG_WARN("This Copylock Protection System contains "
		     "no enc0ded program\n");

	    if (info->serial_off < 0) {
		PP_NEWLINE();

		LOG_WARN("This Copylock Protection System uses "
			 "the serial number %s\n"
			 "Further (manual) investigation is needed\n",
			 info->serial_usage & SERIAL_USAGE_OTHER_MEM_ROBN ?
			 "to decrypt external data" : "in an unknown way");

		return 1;
	    }
	}
    }

#if defined (TARGET_ST)
    ASSERT(info && info->prot_run);
#else
    if (!info || !info->prot_run) {
	PP_NEWLINE();

	LOG_WARN(
	    "%s, "
	    "the native protection code has to be partially executed\n"
	    "You must therefore run the " DEC0DE_NAME " tool on Atari ST\n",
	    (!info || (info->decode_off >= 0)) ?
	    "To dec0de this Copylock Protection System" :
	    "To determine the serial number");

	return 1;
    }
#endif

    if (info->decode_off < 0) {
	if (info->serial_valid && (info->serial == 0)) {
	    PP_NEWLINE();

	    LOG_ERROR("Serial reading failed, "
		      "original key disk is required!\n");
	}

	return 1;
    }

    if (/*
	 * Unknown/binary prog & wrong keydisk (serial is valid,
	 *                                      but equal to zero).
	 */
	(((info->prog_off < 0) || (info->reloc_off < 0)) &&
	 info->serial_valid && (info->serial == 0))
	||
	/*
	 * GEMDOS prog & wrong keydisk (keydisk was used, but prog header
	 *                              was not correctly decrypted).
	 */
	((info->reloc_off >= 0) && info->keydisk_hit &&
	 buf && (read16(buf) != (uint16_t) 0x601a))
	) {

	PP_NEWLINE();

	LOG_ERROR("Program dec0ding failed, "
		  "original key disk is required!\n");

	return 1;
    }

    PP_NEWLINE();

    return 0;
}

/*
 * Check the size of a Rob Northen protection.
 */
static int check_size_robn (prog_t* prog, info_robn_t* info)
{
    ssize_t sz = (ssize_t) prog->size;

    ASSERT(info->prog_off);

    if (/* Internal protection */
	(info->decode_off < 0) && (info->prog_off > sz)) {
	LOG_ERROR("Truncated protection code\n");
	return 1;
    }

    if (/* Wrapped binary program */
	((info->decode_off >= 0) && (info->reloc_off < 0) &&
	 (info->prog_off >= sz)) ||
	/* Wrapped GEMDOS program */
	((info->reloc_off >= 0) &&
	 (info->prog_off + (ssize_t) sizeof(prog_hdr_t) >= sz))) {
	LOG_ERROR("Truncated protected program\n");
	return 1;
    }

    return 0;
}

/*****************************************************************************
 *
 * Copylock Protection System series 1 (1988) by Rob Northen
 *
 * Static analysis of the protection.
 *
 * Some well-known code patterns are searched in the protection.
 * It can be done for the internal type only, for which the decryption
 * scheme is simple.
 * It cannot be done for the wrapper type which uses nested decryption loops.
 * Therefore the wrapper type requires dynamic (run-time) analysis (available
 * on Atari ST only).
 *
 *****************************************************************************/

#define ROBN88_OFF			0x0

#define PROT_FLAGS_ROBN88(_p)		((int)(size_t)((_p)->private))
#define PROT_PRIV_ROBN88(_f)		((void*)(size_t)(_f))

#define PROT_TVD_FSHARK_ROBN88		(1 << 0)
#define PROT_TVD_COMMON_ROBN88		(1 << 1)
#define PROT_TVD_MASK_ROBN88		(PROT_TVD_FSHARK_ROBN88 |	\
					 PROT_TVD_COMMON_ROBN88)
#define PROT_FORCE_SUP_ROBN88		(1 << 2)

#if defined (TARGET_ST)
static int decode_native_robn88 (prog_t* prog, info_robn_t* info);
#endif

/*
 * Simple decryption scheme of the internal type: each instruction is
 * encrypted/decrypted by XOR-ing it with the preceding instruction.
 */
static inline uint32_t get_decoded_intr_robn88 (unsigned char* buf)
{
    uint32_t key32;
    uint32_t w32;

    key32 = read32(buf - SIZE_32);
    key32 = ~key32;
    key32 = SWAP32(key32);

    w32   = read32(buf);
    w32  ^= key32;

    return w32;
}

/*
 * Search for a code pattern in a portion of the protection.
 */
static ssize_t get_pattern_offset_robn88 (unsigned char* buf,
					  size_t         offset,
					  ssize_t        size,
					  uint16_t*      pattern,
					  unsigned int   wcount)
{
    uint32_t     w32;
    uint16_t     w16;
    unsigned int i;

    size  = (size + (ssize_t) (SIZE_16 - 1)) & (ssize_t) ~(SIZE_16 - 1);
    size -= (ssize_t) (SIZE_16 * wcount);

    for (; size >= 0; offset += SIZE_16, size -= (ssize_t) SIZE_16) {

	w32 = get_decoded_intr_robn88(buf + offset);

	w16 = (uint16_t) (w32 >> 16);
	if (pattern[0] && (pattern[0] != w16)) {
	    continue;
	}
	if (wcount == 1) {
	    return (ssize_t) offset;
	}

	w16 = (uint16_t) (w32 & (uint32_t) 0x0000ffff);
	if (pattern[1] != w16) {
	    continue;
	}

	for (i = 2; i < wcount; i++) {
	    if (pattern[i] != read16(buf + offset + (SIZE_16 * i))) {
		break;
	    }
	}

	if (i == wcount) {
	    return (ssize_t) offset;
	}
    }

    return (ssize_t) -1;
}

/*
 * First perform static analysis (internal type only), and then call
 * decode_native_robn88() to perform dynamic (run-time) analysis.
 * If run on a non-ST platform, the function stops after the static analysis
 * and dumps the collected information (if available).
 */
static int decode_robn88 (prog_t* prog, unsigned char* buf, size_t size)
{
    /*
     * Keydisk usage, specific pattern.
     * st $43e.l
     */
    static uint16_t keydisk_pattern[] = { 0x50f9, 0x0000, 0x043e, };
    /*
     * Return from an internal encrypted routine, specific pattern.
     * move.l a0,2(sp)
     */
    static uint16_t resume_pattern[]  = { 0x2f48, 0x0002,         };
    /*
     * Exception vectors checking, specific pattern.
     * instr #$fc0000,operand
     */
    static uint16_t vecs_pattern[]    = { 0x0000, 0x00fc, 0x0000, };
    /*
     * Serial key saving in memory, specific pattern.
     * move.l d0,$1c(a0)
     */
    static uint16_t serial_pattern[]  = { 0x2140, 0x001c,         };

    info_robn_t info;
    ssize_t     sz;
    ssize_t     offset;
    ssize_t     resume_off;
    uint32_t    w32;
    int16_t     s16;

    ASSERT(buf == prog->text);

    init_info_robn(&info);

    offset = (ssize_t) (prog->prot->patterns[4]->eoffset +
			prog->prot->patterns[4]->ecount);
    buf  += offset;
    size -= (size_t) offset;

    if ((ssize_t) size <= (ssize_t) (SIZE_16 * 8)) {
	LOG_ERROR("Truncated protection code\n");
	return 1;
    }

    sz = (ssize_t) ((size > 4096) ? 4096 : size);

    info.keydisk_off = get_pattern_offset_robn88(buf,
						 0,
						 sz,
						 keydisk_pattern,
						 3);
    if (info.keydisk_off >= 0) {

	/*
	 * Internal type detected. Static analysis is possible.
	 */

	/*
	 * Locate the end of the protection code.
	 */
	resume_off = get_pattern_offset_robn88(buf,
					       (size_t) info.keydisk_off,
					       sz - info.keydisk_off,
					       resume_pattern,
					       2);
	if (resume_off >= 0 ) {
	    w32 = get_decoded_intr_robn88(buf + resume_off - SIZE_32);
	    /* lea resume_address(pc),a0 */
	    s16 = (int16_t) (w32 >> 16);
	    if (s16 == 0x41fa) {
		s16 = (int16_t) (w32 & (uint32_t) 0x0000ffff);
		info.prog_off = (ssize_t) s16 + resume_off - (ssize_t) SIZE_16;
	    }
	}

	if (info.prog_off < 0) {
	    LOG_ERROR("Cannot locate the end of the protection code\n");
	    goto unsupp;
	}

	/*
	 * Search for vectors checking.
	 */
	info.vecs_off = get_pattern_offset_robn88(buf,
						  0,
						  resume_off,
						  vecs_pattern,
						  3);

	/*
	 * Determine how the serial number is used.
	 */
	info.serial_off = get_pattern_offset_robn88(buf,
					       0,
					       resume_off,
					       serial_pattern,
					       2);
	if (info.serial_off >= 0) {
	    /*
	     * Serial number is saved into memory (usually at address $24)
	     * and it is returned to the caller.
	     */
	    info.serial_usage    = SERIAL_USAGE_RETURN_ROBN;
	    info.serial_usage   |= SERIAL_USAGE_SAVE_MEM_ROBN;

	    info.serial_dst_addr = (void*) (size_t) (8 + serial_pattern[1]);
	} else {
	    /*
	     * Unknown serial number usage.
	     */
	    info.serial_usage    = SERIAL_USAGE_UNKNOWN_ROBN;
	}

	info.keydisk_off += offset;
	info.prog_off    += offset;

	if (info.vecs_off >= 0) {
	    info.vecs_off += offset;
	}
	if (info.serial_off >= 0) {
	    info.serial_off += offset;
	}

	if (check_size_robn(prog, &info)) {
	    return 1;
	}
    } else {
	info.decode_off = 0;
    }

#if defined (TARGET_ST)
    if ((info.decode_off >= 0) || (info.serial_off >= 0)) {
	/*
	 * Continue with dynamic analysis.
	 */
	return decode_native_robn88(prog, &info);
    }
#endif

    return print_info_robn(info.decode_off < 0 ? &info : NULL, NULL);

unsupp:
    LOG_ERROR("This variant of the Copylock Protection System "
	      "is not supported\n");

    return 1;
}

/*
 * Rob Northen protection code has evolved slightly over time. In particular
 * the protection prolog (non-encrypted code) which is parsed by dec0de to
 * automatically recognize the protection has changed a bit multiple times.
 * Here are the known protection prolog variants of the series 1.
 */

#define PATTERN_SWITCHSUPILL_ROBN88	/* 22 bytes */			\
    0x48, 0x7a, 0x00, 0x0e,		/* pea 1f(pc) */		\
    0x2f, 0x3c, 0x00, 0x05, 0x00, 0x04,	/* move.l #$50004,-(a7) */	\
    0x4e, 0x4d,				/* trap #$d */			\
    0x50, 0x8f,				/* addq.l #8,a7 */		\
    0x4a, 0xfc,				/* illegal */			\
    0x23, 0xc0, 0x00, 0x00, 0x00, 0x10	/* 1: move.l d0,$10 */

#define PATTERN_SWITCHSUPPRIV1_ROBN88	/* 30 bytes */			\
    0x48, 0x7a, 0x00, 0x14,		/* pea 1f(pc) */		\
    0x2f, 0x3c, 0x00, 0x05, 0x00, 0x08,	/* move.l #$50008,-(a7) */	\
    0x4e, 0x4d,				/* trap #$d */			\
    0x50, 0x8f,				/* addq.l #8,a7 */		\
    0x40, 0xc1,				/* move sr,d1 */		\
    0x00, 0x7c, 0x20, 0x00,		/* ori.w #$2000,sr */		\
    0x5d, 0x8f,				/* subq.l #6,a7 */		\
    0x5c, 0x8f,				/* 1: addq.l #6,a7 */		\
    0x23, 0xc0, 0x00, 0x00, 0x00, 0x20	/* move.l d0,$20 */

#define PATTERN_SWITCHSUPPRIV2_ROBN88	/* 28 bytes */			\
    0x48, 0x7a, 0x00, 0x12,		/* pea 1f(pc) */		\
    0x2f, 0x3c, 0x00, 0x05, 0x00, 0x08,	/* move.l #$50008,-(a7) */	\
    0x4e, 0x4d,				/* trap #$d */			\
    0x50, 0x8f,				/* addq.l #8,a7 */		\
    0x00, 0x7c, 0x20, 0x00,		/* ori.w #$2000,sr */		\
    0x5d, 0x8f,				/* subq.l #6,a7 */		\
    0x5c, 0x8f,				/* 1: addq.l #6,a7 */		\
    0x23, 0xc0, 0x00, 0x00, 0x00, 0x20	/* move.l d0,$20 */

#define PATTERN_TRIGILL_ROBN88(_o1, _o2)/* 10 bytes */			\
    0x41, 0xfa, _o1, _o2,		/* lea pc+2+_o1_o2,a0 */	\
    0x23, 0xc8, 0x00, 0x00, 0x00, 0x10	/* move.l a0,$10 */

#define PATTERN_MASK_TRIGILL_ROBN88(_o1, _o2)				\
    0xff, 0xff, _o1, _o2,						\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff

#define PATTERN_ILLVEC1_ROBN88(_o1, _o2, _o3, _o4) /* 58 bytes */	\
    0x48, 0xe7, 0x80, 0xc0,		/* movem.l d0/a0-a1,-(a7) */	\
    0x41, 0xfa, 0x00, 0x34,		/* lea 1f(pc),a0 */		\
    0x23, 0xc8, 0x00, 0x00, 0x00, 0x24,	/* move.l a0,$24 */		\
    0x41, 0xfa, _o1, _o2,		/* lea pc+2+_o1_o2,a0 */	\
    0x23, 0xc8, 0x00, 0x00, 0x00, 0x20,	/* move.l a0,$20 */		\
    0x06, 0xaf, 0x00, 0x00, 0x00, 0x02,					\
    0x00, 0x0e,				/* addi.l #2,$e(a7) */		\
    0x00, 0x2f, 0x00, 0x07, 0x00, 0x0c,	/* ori.b #7,$c(a7) */		\
    0x08, 0x6f, 0x00, 0x07, 0x00, 0x0c,	/* bchg #7,$c(a7) */		\
    0x43, 0xfa, _o3, _o4,		/* lea pc+2+_o3_o4,a1 */	\
    0x67, 0x1a,				/* beq.s 3f */			\
    0x20, 0x51,				/* movea.l (a1),a0 */		\
    0x20, 0xa9, 0x00, 0x04,		/* move.l 4(a1),(a0) */		\
    0x60, 0x26				/* bra.s 4f */

#define PATTERN_MASK_ILLVEC1_ROBN88(_o1, _o2, _o3, _o4)			\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, _o1, _o2,						\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff,								\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, _o3, _o4,						\
    0xff, 0xff,								\
    0xff, 0xff,								\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff

#define PATTERN_ILLVEC2_ROBN88(_o1, _o2) /* 46 bytes */			\
    0x48, 0xe7, 0x80, 0xc0,		/* movem.l d0/a0-a1,-(a7) */	\
    0x41, 0xfa, 0x00, 0x28,		/* lea 1f(pc),a0 */		\
    0x23, 0xc8, 0x00, 0x00, 0x00, 0x24,	/* move.l a0,$24 */		\
    0x41, 0xfa, _o1, _o2,		/* lea pc+2+_o1_o2,a0 */	\
    0x23, 0xc8, 0x00, 0x00, 0x00, 0x20,	/* move.l a0,$20 */		\
    0x00, 0x2f, 0x00, 0x07, 0x00, 0x0c,	/* ori.b #7,$c(a7) */		\
    0x08, 0x6f, 0x00, 0x07, 0x00, 0x0c,	/* bchg #7,$c(a7) */		\
    0x06, 0xaf, 0x00, 0x00, 0x00, 0x02,					\
    0x00, 0x0e,				/* addi.l #2,$e(a7) */		\
    0x60, 0x08				/* bra.s 2f */

#define PATTERN_MASK_ILLVEC2_ROBN88(_o1, _o2)				\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, _o1, _o2,						\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff,								\
    0xff, 0xff

#define PATTERN_TVD1_ROBN88(_o1, _o2) /* 44 bytes */			\
    0x02, 0x7c, 0xf8, 0xff,		/* 1: andi.w #$f8ff,sr */	\
    0x48, 0xe7, 0x80, 0xc0,		/* movem.l d0/a0-a1,-(a7) */	\
    0x43, 0xfa, _o1, _o2,		/* 2: lea pc+2+_o1_o2,a1 */	\
    0x20, 0x51,				/* movea.l (a1),a0 */		\
    0x20, 0xa9, 0x00, 0x04,		/* move.l 4(a1),(a0) */		\
    0x20, 0x6f, 0x00, 0x0e,		/* 3: movea.l $e(a7),a0 */	\
    0x22, 0x88,				/* move.l a0,(a1) */		\
    0x23, 0x50, 0x00, 0x04,		/* move.l (a0),4(a1) */		\
    0x20, 0x28, 0xff, 0xfc,		/* move.l -4(a0),d0 */		\
    0x46, 0x80,				/* not.l d0 */			\
    0x48, 0x40,				/* swap d0 */			\
    0xb1, 0x90,				/* eor.l d0,(a0) */		\
    0x4c, 0xdf, 0x03, 0x01,		/* 4: movem.l (a7)+,d0/a0-a1 */	\
    0x4e, 0x73				/* rte */

#define PATTERN_MASK_TVD1_ROBN88(_o1, _o2)				\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, _o1, _o2,						\
    0xff, 0xff,								\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff,								\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff,								\
    0xff, 0xff,								\
    0xff, 0xff,								\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff

#define PATTERN_TVD2_ROBN88(_o1, _o2)	/* 50 bytes */			\
    0x02, 0x7c, 0xf8, 0xff,		/* 1: andi.w #$f8ff,sr */	\
    0x48, 0xe7, 0x80, 0xc0,		/* movem.l d0/a0-a1,-(a7) */	\
    0x43, 0xfa, _o1, _o2,		/* 2: lea pc+2+_o1_o2,a1 */	\
    0x20, 0x51,				/* movea.l (a1),a0 */		\
    0x20, 0x28, 0xff, 0xfc,		/* move.l -4(a0),d0 */		\
    0x90, 0x83,				/* sub.l d3,d0 */		\
    0x46, 0x80,				/* not.l d0 */			\
    0x48, 0x40,				/* swap d0 */			\
    0xb1, 0x90,				/* eor.l d0,(a0) */		\
    0x20, 0x6f, 0x00, 0x0e,		/* 3: movea.l $e(a7),a0 */	\
    0x20, 0x28, 0xff, 0xfc,		/* move.l -4(a0),d0 */		\
    0x90, 0x83,				/* sub.l d3,d0 */		\
    0x46, 0x80,				/* not.l d0 */			\
    0x48, 0x40,				/* swap d0 */			\
    0xb1, 0x90,				/* eor.l d0,(a0) */		\
    0x22, 0x88,				/* move.l a0,(a1) */		\
    0x4c, 0xdf, 0x03, 0x01,		/* 4: movem.l (a7)+,d0/a0-a1 */	\
    0x4e, 0x73				/* rte */

#define PATTERN_MASK_TVD2_ROBN88(_o1, _o2)				\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, _o1, _o2,						\
    0xff, 0xff,								\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff,								\
    0xff, 0xff,								\
    0xff, 0xff,								\
    0xff, 0xff,								\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff,								\
    0xff, 0xff,								\
    0xff, 0xff,								\
    0xff, 0xff,								\
    0xff, 0xff,								\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff

DECLARE_PATTERN_WITH_MASK(pattern_bra_robn88,
    PATTERN_ANY,
    0x0, 0x0, 2,
    PATTERN_BUFFER(
    0x60, 0x72
    ),
    PATTERN_BUFFER(
    0xff, 0x00
    )
    );

DECLARE_PATTERN(pattern_switchsupill_robn88,
    PATTERN_ANY,
    0x80, 0x40, 22,
    PATTERN_BUFFER(
    PATTERN_SWITCHSUPILL_ROBN88
    )
    );

DECLARE_PATTERN(pattern_switchsuppriv1_robn88,
    PATTERN_ANY,
    0x40, 0x40, 30,
    PATTERN_BUFFER(
    PATTERN_SWITCHSUPPRIV1_ROBN88
    )
    );

DECLARE_PATTERN(pattern_switchsuppriv2_robn88,
    PATTERN_ANY,
    0x80, 0x40, 28,
    PATTERN_BUFFER(
    PATTERN_SWITCHSUPPRIV2_ROBN88
    )
    );

DECLARE_PATTERN_WITH_MASK(pattern_trigill_robn88,
    PATTERN_ANY,
    PATTERN_NEXT, 0x40, 10,
    PATTERN_BUFFER(
    PATTERN_TRIGILL_ROBN88(0x00, 0x8a)
    ),
    PATTERN_BUFFER(
    PATTERN_MASK_TRIGILL_ROBN88(0x00, 0x00)
    )
    );

DECLARE_PATTERN_WITH_MASK(pattern_trigillbin_robn88,
    PATTERN_ANY,
    0x90, 0x60, 10,
    PATTERN_BUFFER(
    PATTERN_TRIGILL_ROBN88(0x00, 0x8a)
    ),
    PATTERN_BUFFER(
    PATTERN_MASK_TRIGILL_ROBN88(0x00, 0x00)
    )
    );

DECLARE_PATTERN_WITH_MASK(pattern_illvec1_robn88,
    PATTERN_ANY,
    PATTERN_NEXT, 0xa0, 58,
    PATTERN_BUFFER(
    PATTERN_ILLVEC1_ROBN88(0x01, 0xf4, 0xfe, 0xe0)
    ),
    PATTERN_BUFFER(
    PATTERN_MASK_ILLVEC1_ROBN88(0x00, 0x00, 0x00, 0x00)
    )
    );

DECLARE_PATTERN_WITH_MASK(pattern_illvec2_robn88,
    PATTERN_ANY,
    PATTERN_NEXT, 0x80, 46,
    PATTERN_BUFFER(
    PATTERN_ILLVEC2_ROBN88(0x01, 0xa2)
    ),
    PATTERN_BUFFER(
    PATTERN_MASK_ILLVEC2_ROBN88(0x00, 0x00)
    )
    );

DECLARE_PATTERN_WITH_MASK(pattern_tvd1_robn88,
    PATTERN_ANY,
    PATTERN_NEXT, 0x0, 44,
    PATTERN_BUFFER(
    PATTERN_TVD1_ROBN88(0xfe, 0xca)
    ),
    PATTERN_BUFFER(
    PATTERN_MASK_TVD1_ROBN88(0x00, 0x00)
    )
    );

DECLARE_PATTERN_WITH_MASK(pattern_tvd2_robn88,
    PATTERN_ANY,
    PATTERN_NEXT, 0x0, 50,
    PATTERN_BUFFER(
    PATTERN_TVD2_ROBN88(0xff, 0x02)
    ),
    PATTERN_BUFFER(
    PATTERN_MASK_TVD2_ROBN88(0x00, 0x00)
    )
    );

DECLARE_PROTECTION_PARENT(prot_robn88a,
    "Copylock Protection System series 1 (1988) by Rob Northen",
    'a',
    ROBN88_OFF,
    PATTERNS_LIST(
    &pattern_bra_robn88,
    &pattern_switchsupill_robn88,
    &pattern_trigill_robn88,
    &pattern_illvec1_robn88,
    &pattern_tvd1_robn88
    ),
    decode_robn88,
    PROT_PRIV_ROBN88(PROT_TVD_COMMON_ROBN88)
    );

DECLARE_PROTECTION_VARIANT(prot_robn88b,
    &prot_robn88a,
    'b',
    ROBN88_OFF,
    PATTERNS_LIST(
    &pattern_bra_robn88,
    &pattern_switchsuppriv2_robn88,
    &pattern_trigill_robn88,
    &pattern_illvec1_robn88,
    &pattern_tvd1_robn88
    ),
    NULL,
    PROT_PRIV_ROBN88(PROT_TVD_COMMON_ROBN88)
    );

DECLARE_PROTECTION_VARIANT(prot_robn88c,
    &prot_robn88a,
    'c',
    ROBN88_OFF,
    PATTERNS_LIST(
    &pattern_bra_robn88,
    &pattern_switchsuppriv1_robn88,
    &pattern_trigill_robn88,
    &pattern_illvec2_robn88,
    &pattern_tvd1_robn88
    ),
    NULL,
    PROT_PRIV_ROBN88(PROT_TVD_COMMON_ROBN88)
    );

DECLARE_PROTECTION_VARIANT(prot_robn88d,
    &prot_robn88a,
    'd',
    ROBN88_OFF,
    PATTERNS_LIST(
    &pattern_bra_robn88,
    &pattern_switchsuppriv1_robn88,
    &pattern_trigill_robn88,
    &pattern_illvec2_robn88,
    &pattern_tvd2_robn88
    ),
    NULL,
    PROT_PRIV_ROBN88(PROT_TVD_FSHARK_ROBN88)
    );

DECLARE_PROTECTION_VARIANT(prot_robn88e,
    &prot_robn88a,
    'e',
    ROBN88_OFF,
    PATTERNS_LIST(
    &pattern_bra_robn88,
    &pattern_none,
    &pattern_trigillbin_robn88,
    &pattern_illvec1_robn88,
    &pattern_tvd1_robn88
    ),
    NULL,
    PROT_PRIV_ROBN88(PROT_TVD_COMMON_ROBN88 | PROT_FORCE_SUP_ROBN88)
    );

/*****************************************************************************
 *
 * Copylock Protection System series 2 (1989) by Rob Northen
 *
 * Static analysis of the protection.
 * Some well-known code patterns are searched in the protection.
 * It can be done for both the wrapper and the internal types.
 *
 * The series 2 uses two different TDV routines.
 * - The first TDV routine uses a complex decryption scheme. It runs in the
 *   first part of protection where encrypted instructions are aimed at
 *   preventing the rest of the protection to be reached under a debugger.
 * - The second TDV routine uses a simple decryption scheme. It runs in the
 *   heart of the protection where the key disk is read and the decryption
 *   of the wrapped program is performed.
 * Therefore, mainly the code encrypted with the second TDV method needs to be
 * parsed by dec0de for the static analysis.
 * Fortunately, the decryption scheme for that part is simple.
 *
 *****************************************************************************/

#define ROBN89_OFF			0x0

#define PROT_FLAGS_ROBN89(_p)		((int)(size_t)((_p)->private))
#define PROT_PRIV_ROBN89(_f)		((void*)(size_t)(_f))

#define PROT_FORCE_SUP_ROBN89		(1 << 0)

#if defined (TARGET_ST)
static int decode_native_robn89 (prog_t* prog, info_robn_t* info);
#endif

/*
 * Get the 32-bit key used to decrypt the current instruction.
 * Such key is computed by adding a magic value to the preceding encrypted
 * instruction.
 */
static inline uint32_t get_decode_key32_robn89 (unsigned char* buf,
						uint32_t       magic32)
{
    uint32_t key32;

    key32  = read32(buf - SIZE_32);
    key32 += magic32;

    return key32;
}

/*
 * Search for the code which is used at the end of the protection to stop
 * the TVD mode and resume the normal execution.
 *
 * The beginning of this code (4 instructions) is encrypted with the second
 * TVD method, while the rest of it is encrypted with the first TVD method.
 * Indeed, the first TVD routine is reenabled on purpose at the end of the
 * protection, so that the latest instructions are executed using this more
 * hostile method (which is also used at the beginning of the protection).
 *
 * The code in question installs a "trampoline" routine which will run
 * in the normal execution mode of the CPU (TVD disabled).
 * In the case of the wrapper type, the "trampoline" routine is in charge of
 * copying the decrypted program to its final destination and starting
 * its execution.
 * In the case of the internal type, it is in charge of returning to the
 * caller.
 *
 * In order to find that code, only the pattern which corresponds to the
 * first three instructions of the code is searched.
 *
 * As seen above, this pattern is encrypted with the second TVD method.
 * The corresponding decryption scheme works as follows: each instruction
 * is decrypted by XOR-ing it with a key computed from a magic value and
 * the preceding encrypted instruction.
 * The magic value is the same for all encrypted instructions. Therefore,
 * it can be easily deduced during the search of the code pattern.
 *
 * The offset of the code pattern and the magic value are returned.
 *
 * In addition, the offset of the end of the protection (which corresponds to
 * the offset of the embedded program for the wrapper type) is also determined
 * and returned (see comments below for details).
 */
static ssize_t get_start_offset_robn89 (unsigned char* buf,
					size_t         size,
					uint32_t*      pmagic32,
					ssize_t*       prog_offset)
{
    uint32_t magic32;
    uint32_t key32;
    uint32_t w32;
    uint16_t w16;
    size_t   limit;
    size_t   i;
    size_t   j;

    for (i = 0;
	 (ssize_t) i <= (ssize_t) (size - (SIZE_16 * 10));
	 i += SIZE_16) {

	j       = i;
	w32     = read32(buf + j);
	w32    ^= (uint32_t) 0x4dfa0010;	/* lea pc+$12,a6 */
	magic32 = w32 - read32(buf + j - SIZE_32);

	j      += SIZE_32;
	w32     = read32(buf + j);
	key32   = get_decode_key32_robn89(buf + j, magic32);
	w32    ^= key32;

	if (w32 != (uint32_t) 0x2c2efffc) {	/* move.l -4(a6),d6 */
	    continue;
	}

	j      += SIZE_32;
	w32     = read32(buf + j);
	key32   = get_decode_key32_robn89(buf + j, magic32);
	w32    ^= key32;

	if (w32 != (uint32_t) 0xdcb90000) {	/* add.l $8.l,d6 */
	    continue;
	}

	/*
	 * The pattern has been found, the magic value have been discovered.
	 */

	limit = i + (SIZE_32 * 64);
	if (limit > size - (SIZE_16 * 3)) {
	    limit = size - (SIZE_16 * 3);
	}

	/*
	 * Determine the offset of the end of the protection.
	 *
	 * The last instructions of the protection are always executed
	 * using the first TVD routine (which is reactivated on purpose).
	 * The very last instruction of the protection is 'move.l a7,$24.l'.
	 * With the first TVD method, each instruction is decrypted using a
	 * different 32-bit key whose value depends on the execution of the
	 * previous instructions.
	 * But, for a given instruction, the same 32-bit key is used to
	 * decrypt each 32-bit part of that instruction.
	 * Because the 'move.l a7,$24.l' instruction is 6 bytes long, the
	 * corresponding 32-bit key is used to decrypt both the first 4 bytes
	 * and the last 2 bytes of the instruction.
	 * It is enough to guess the magic value and find the instruction.
	 */
	for (j = i + (SIZE_32 * 4); j <= limit; j += SIZE_16) {

	    w32   = read32(buf + j);
	    key32 = w32 ^ (uint32_t) 0x23cf0000; /* move.l a7,<addr>.l */

	    w16   = read16(buf + j + SIZE_32);
	    w16  ^= (uint16_t) (key32 >> 16);

	    if (w16 == (uint16_t) 0x0024) {	 /* <addr> == $24 */
		*pmagic32    = magic32;
		*prog_offset = (ssize_t) (j + (SIZE_16 * 3));
		return (ssize_t) i;
	    }
	}
    }

    *prog_offset = (ssize_t) -1;
    return (ssize_t) -1;
}

/*
 * Search for the instruction which pushes the beginning of the "trampoline"
 * routine onto the stack.
 *
 * This code is encrypted using the first TVD method (see above function
 * for details).
 */
static ssize_t get_pushtramp_offset_robn90 (unsigned char* buf,
					    size_t         prog_offset,
					    size_t         size)
{
    uint32_t key32;
    uint32_t w32;
    uint16_t w16;
    size_t   i;

    for (buf += prog_offset, i = SIZE_16 * 3; i <= size; i += SIZE_16) {

	/*
	 * Search for the 'move.l #$bd96bdae,-(a7)' instruction.
	 *
	 * Trampoline start (stack bottom):
	 *   #$bd96: eor.l d6,(a6)
	 *   #$bdae: eor.l d6,<offset>(a6)
	 *   [...]
	 *   andi.w #$7fff,(a7)
	 *   rte
	 */

	w32   = read32(buf - i);
	key32 = w32 ^ (uint32_t) 0x2f3cbd96;

	w32   = read32(buf - i + SIZE_32);
	w16   = (uint16_t) ((w32 ^ key32) >> 16);

	if (w16 == (uint16_t) 0xbdae) {
	    return (ssize_t) (prog_offset - i);
	}
    }

    return (ssize_t) -1;
}

/*
 * Get the size of the protected subroutine, if any.
 *
 * In the case of the internal type, a specific subroutine provided by the
 * vendor of the protected software can be encrypted, linked to the
 * protection and called from it.
 * Such subroutine can interact with the host program to perform specific
 * tricks.
 *
 * The size of the protected subroutine is encoded in the before-last
 * instruction of the protection and encrypted with the first TVD method.
 * The instruction is 'adda.l #<size>,a4'.
 *
 * As explained in 'get_start_offset_robn89()', the first TVD method uses
 * a different 32-bit key to encrypt each instruction.
 * But the same 32-bit key is used to encrypt each 32-bit part of a long
 * instruction.
 * In the present case, it is supposed that the size of the subroutine is
 * less than 64K so that it can be encoded in the low 16-bit word of the
 * instruction opcode, as follows: #$d9fc0000xxxx, where <xxxx> is the size
 * of the subroutine.
 * Knowing the first 32-bit part of the instruction, in both the encrypted and
 * decrypted forms, enables to determine the 32-bit key which is used to
 * encrypt/decrypt the whole instruction.
 */
static size_t get_subrout_size_robn90 (unsigned char* buf,
				       size_t         prog_offset)
{
    uint32_t w32;
    uint16_t w16;

    w32  = read32(buf + prog_offset - (SIZE_16 * 6));
    w32 ^= 0xd9fc0000;			/* adda.l #0,a4 */

    w16  = read16(buf + prog_offset - (SIZE_16 * 6) + SIZE_32);
    w16 ^= (uint16_t) (w32 >> 16);

    return (size_t) w16;
}

/*
 * Locate a code pattern in the heart of the protection which is encrypted
 * with the second TVD method.
 *
 * An array of code patterns is passed to the function.
 * The idea is to be able to locate a particular code logic that may have
 * been implemented differently over time.
 *
 * The magic value which is used by the second TVD method must be passed to
 * the function. It is discovered by 'get_start_offset_robn89()'.
 *
 * The size parameter indicates the amount of protected code to be parsed
 * as well as the direction of the parsing: if the size is negative,
 * the parsing should be done by descending address order.
 * If the size is positive, it the parsing should be done by ascending address
 * order.
 */
static ssize_t get_pattern_offset_robn89 (unsigned char*  buf,
					  ssize_t         offset,
					  ssize_t         size,
					  uint32_t        magic32,
					  instr_match_t** patterns)
{
    uint32_t       key32;
    uint32_t       w32_1;
    uint32_t       w32_2;
    ssize_t        sz_left;
    ssize_t        sz_next;
    ssize_t        limit;
    ssize_t        i;
    ssize_t        c;
    ssize_t        l;
    unsigned int   j;
    unsigned int   k;
    instr_match_t* p;

    if (size < 0) {
	size    = -size;
	sz_next = (ssize_t) -SIZE_16;
    } else {
	sz_next = SIZE_16;
    }

    size   = (size + (ssize_t) (SIZE_16 - 1)) & (ssize_t) ~(SIZE_16 - 1);
    size  -= (ssize_t) (SIZE_32 * 2);
    offset = (sz_next < 0) ? offset - (ssize_t) (SIZE_32 * 2) : offset;

    if ((size < 0) || (offset < 0)) {
	return (ssize_t) -1;
    }

    sz_left = size;
    i       = offset;
    limit   = (sz_next < 0) ? offset : offset + size;
    do {

	key32  = get_decode_key32_robn89(buf + i, magic32);

	w32_1  = read32(buf + i);
	w32_2  = read32(buf + i + SIZE_32);
	w32_1 ^= key32;
	w32_2 ^= key32;

	j = 0;
	p = patterns[0];
	do {
	    if (cmp_instr(w32_1, w32_2, &p[0])) {
		break;
	    }
	} while ((p = patterns[++j]) != 0);

	if (!p) {
	    continue;
	}

	j = 0;
	p = patterns[0];
	do {

	    k = 0;
	    c = i;
	    do {
		key32  = get_decode_key32_robn89(buf + c, magic32);

		w32_1  = read32(buf + c);
		w32_2  = read32(buf + c + SIZE_32);
		w32_1 ^= key32;
		w32_2 ^= key32;

		if (!cmp_instr(w32_1, w32_2, &p[k])) {
		    break;
		}

		l = p[k++].stride;

		if (l == 0) {
		    return (ssize_t) i;
		}

		c += l;
	    } while (c <= limit); /* 8 bytes are available above limit */

	} while ((p = patterns[++j]) != 0);

    } while (((sz_left -= (ssize_t) SIZE_16) >= 0) &&
	     ((i += sz_next) >= 0));

    return (ssize_t) -1;
}

/*
 * Instructions pattern for program decoding.
 */
static instr_match_t decode_pattern1_robn89[] = {
    /* lea here(pc),a6 */
    { { 0x4dfafffe, 0x00000000 }, { 0xffffffff, 0x00000000 },  4, },
    /* adda.l #offset,a6 */
    { { 0xddfc0000, 0x00000000 }, { 0xffff0000, 0x00000000 },  6, },
    /* move.l #size,d6 */
    { { 0x2c3c0000, 0x00000000 }, { 0xffff0000, 0x00000000 },  0, },
};

static instr_match_t* decode_patterns_robn89[] = {
    decode_pattern1_robn89,
    NULL,
};

/*
 * Instructions pattern for program relocation.
 */
static instr_match_t reloc_pattern1_robn89[] = {
    /* lea here(pc),a6 */
    { { 0x4dfafffe, 0x00000000 }, { 0xffffffff, 0x00000000 },  4, },
    /* move.l a6,d6 */
    { { 0x2c0e0000, 0x00000000 }, { 0xffff0000, 0x00000000 },  0, },
};

static instr_match_t* reloc_patterns_robn89[] = {
    reloc_pattern1_robn89,
    NULL,
};

/*
 * Instructions pattern for vectors checking.
 */
static instr_match_t vecs_pattern1_robn89[] = {
    /* move.l (a0)+,d0 */
    { { 0x20180000, 0x00000000 }, { 0xffff0000, 0x00000000 },  4, },
    /* andi.l #$ffffff,d0 */
    { { 0x028000ff, 0xffff0000 }, { 0xffffffff, 0xffff0000 },  6, },
    /* cmp.l #$400000,d0 */
    { { 0xb0bc0040, 0x00000000 }, { 0xffffffff, 0xffff0000 },  0, },
};

static instr_match_t* vecs_patterns_robn89[] = {
    vecs_pattern1_robn89,
    NULL,
};

/*
 * Instructions patterns for keydisk reading.
 */
static instr_match_t keydisk_pattern1_robn89[] = {
    /* move.w $43e.l,-(a7) */
    { { 0x3f390000, 0x043e0000 }, { 0xffffffff, 0xffff0000 },  6, },
    /* st $43e.l */
    { { 0x50f90000, 0x043e0000 }, { 0xffffffff, 0xffff0000 },  0, },
};
static instr_match_t keydisk_pattern2_robn89[] = {
    /* move.w $43e.l,-offset(ax) */
    { { 0x30790000, 0x043e0000 }, { 0xf0ffffff, 0xffff0000 },  8, },
    /* st $43e.l */
    { { 0x50f90000, 0x043e0000 }, { 0xffffffff, 0xffff0000 },  0, },
};

static instr_match_t* keydisk_patterns_robn89[] = {
    keydisk_pattern1_robn89,
    keydisk_pattern2_robn89,
    NULL,
};

/*
 * Instructions pattern for serial usage.
 * External protection type: serial is saved at a given memory address.
 */
static instr_match_t serial_dst_pattern1_robn89[] = {
    /* move.l d0,$address */
    { { 0x23c00000, 0x00000000 }, { 0xffff0000, 0x00000000 },  6, },
    /* moveq #0,d[0|1] */
    { { 0x70000000, 0x00000000 }, { 0xfdff0000, 0x00000000 },  0, },
};

static instr_match_t* serial_dst_patterns_robn89[] = {
    serial_dst_pattern1_robn89,
    NULL,
};

/*
 * Instructions pattern for serial usage.
 * Internal protection type: end of serial usage, d0 and d1 are cleared.
 *
 */
static instr_match_t serial_end_pattern1_robn89[] = {
    /* moveq #0,d[0|1] */
    { { 0x70000000, 0x00000000 }, { 0xfdff0000, 0x00000000 },  2, },
    /* moveq #0,d[0|1] */
    { { 0x70000000, 0x00000000 }, { 0xfdff0000, 0x00000000 },  2, },
    /* lea pc+$12,a6 */
    { { 0x4dfa0010, 0x00000000 }, { 0xffffffff, 0x00000000 },  0, },
};

static instr_match_t* serial_end_patterns_robn89[] = {
    serial_end_pattern1_robn89,
    NULL,
};

/*
 * Instructions pattern for serial usage.
 * Internal protection type: serial is saved into the stack
 *                           in order to be returned to the caller.
 */
static instr_match_t serial_stack_pattern1_robn89[] = {
    /* move.l d0,offset0(a7) */
    { { 0x2f400000, 0x00000000 }, { 0xffffff00, 0x00000000 },  4, },
    /* move.l d1,offset1(a7) */
    { { 0x2f410000, 0x00000000 }, { 0xffffff00, 0x00000000 },  0, },
};

static instr_match_t* serial_stack_patterns_robn89[] = {
    serial_stack_pattern1_robn89,
    NULL,
};

/*
 * Instructions pattern for serial usage.
 * Internal protection type: serial is xor'ed into memory whose address
 *                           is read from the stack.
 */
static instr_match_t serial_eor_pattern1_robn89[] = {
    /* move.l offset0(a7),a6 */
    { { 0x2c6f0000, 0x00000000 }, { 0xffff0000, 0x00000000 },  4, },
    /* eor.l d0,(a6) */
    { { 0x01960000, 0x00000000 }, { 0x0fff0000, 0x00000000 },  2, },
    /* move.l d1,offset1(a7) */
    { { 0x2f410000, 0x00000000 }, { 0xffffff00, 0x00000000 },  0, },
};

static instr_match_t* serial_eor_patterns_robn89[] = {
    serial_eor_pattern1_robn89,
    NULL,
};

/*
 * First perform static analysis, and then call decode_native_robn89()
 * to perform dynamic (run-time) analysis.
 * If run on a non-ST platform, the function stops after the static analysis
 * and dumps the collected information.
 */
static int decode_robn89 (prog_t* prog, unsigned char* buf, size_t size)
{
    info_robn_t info;
    ssize_t     offset;
    ssize_t     limit_off;
    ssize_t     serial_end_off = -1;
    ssize_t     serial_sav_off;
    ssize_t     search_sz;
    uint32_t    key32;
    uint32_t    w32;
    uint32_t    addr32;

    ASSERT(buf == prog->text);

    init_info_robn(&info);

    offset = (ssize_t) (prog->prot->patterns[1]->eoffset +
			prog->prot->patterns[1]->ecount);
    buf  += offset;
    size -= (size_t) offset;

    if ((ssize_t) size <= (ssize_t) (SIZE_16 * 8)) {
	LOG_ERROR("Truncated protection code\n");
	return 1;
    }

    /*
     * Locate the end of the protection and discover the magic value
     * used by the second TVD method.
     */
    info.start_off = get_start_offset_robn89(buf,
					     size,
					     &info.magic32,
					     &info.prog_off);
    if (info.start_off < 0) {
	LOG_ERROR("Cannot locate the end of the protection code\n");
	goto unsupp;
    }

    /*
     * Locate the trampoline code installer.
     */
    info.pushtramp_off = get_pushtramp_offset_robn90(
				buf,
				(size_t) info.prog_off,
				(size_t) (info.prog_off - info.start_off));
    if (info.pushtramp_off < 0) {
	LOG_ERROR("Cannot locate the trampoline code\n");
	goto unsupp;
    }

    /*
     * Locate the code snippet that decrypts the wrapped program.
     * If found, the protection is a wrapper type otherwise it is an
     * internal type.
     */
    info.decode_off = get_pattern_offset_robn89(buf,
						info.start_off,
						-info.start_off,
						info.magic32,
						decode_patterns_robn89);

    if (info.decode_off >= 0) {
	/*
	 * Wrapper type: locate the relocation code pattern.
	 * If found, the wrapped program is a GEMDOS program otherwise it is
	 * a binary program.
	 */
	limit_off       = info.decode_off;
	info.reloc_off  = get_pattern_offset_robn89(buf,
					info.decode_off,
					info.start_off - info.decode_off,
					info.magic32,
					reloc_patterns_robn89);
    } else {
	/*
	 * Internal type: locate the protected subroutine, if any.
	 */
	limit_off       = info.start_off;
	info.subrout_sz = get_subrout_size_robn90(buf,
						  (size_t) info.prog_off);
    }

    limit_off += (ssize_t) (SIZE_32 * 2);

    /*
     * Search for vectors checking.
     */
    info.vecs_off = get_pattern_offset_robn89(buf,
					      limit_off,
					      -limit_off,
					      info.magic32,
					      vecs_patterns_robn89);

    /*
     * Search for keydisk reading.
     */
    info.keydisk_off = get_pattern_offset_robn89(buf,
						 limit_off,
						 -limit_off,
						 info.magic32,
						 keydisk_patterns_robn89);

    if (info.keydisk_off >= 0) {
	search_sz = limit_off - info.keydisk_off;

	if (info.decode_off >= 0) {
	    /*
	     * Keydisk is used by a wrapper type protection.
	     * Determine if the serial is saved into memory.
	     */
	    info.serial_off   = info.decode_off;
	    info.serial_usage = SERIAL_USAGE_DECODE_PROG_ROBN;

	    serial_sav_off = get_pattern_offset_robn89(buf,
						limit_off,
						-search_sz,
						info.magic32,
						serial_dst_patterns_robn89);
	    if (serial_sav_off >= 0) {
		/*
		 * Serial is saved into memory, determine the destination
		 * address.
		 */
		info.serial_usage |= SERIAL_USAGE_SAVE_MEM_ROBN;

		addr32  = 0;
		key32   = get_decode_key32_robn89(buf + serial_sav_off,
					      info.magic32);
		w32     = read32(buf + serial_sav_off) ^ key32;
		addr32 |= (w32 & (uint32_t) 0x0000ffff) << 16;
		w32     = read32(buf + serial_sav_off + SIZE_32) ^ key32;
		addr32 |= (w32 & (uint32_t) 0xffff0000) >> 16;

		info.serial_dst_addr = (void*) (size_t) addr32;
	    }
	} else {
	    /*
	     * Keydisk is used by an internal type protection.
	     * Determine how the serial is used.
	     */
	    serial_end_off = get_pattern_offset_robn89(buf,
						limit_off,
						-search_sz,
						info.magic32,
						serial_end_patterns_robn89);
	    if (serial_end_off >= 0) {
		/*
		 * Serial is used for some extra tricks.
		 * Determine which one.
		 */
		if (search_sz > (ssize_t) (SIZE_32 * 8)) {
		    search_sz = (ssize_t) (SIZE_32 * 8);
		}

		info.serial_off = get_pattern_offset_robn89(buf,
						limit_off,
						-search_sz,
						info.magic32,
						serial_stack_patterns_robn89);
		if (info.serial_off >= 0) {
		    /*
		     * Serial is merely returned to the caller.
		     */
		    info.serial_usage = SERIAL_USAGE_RETURN_ROBN;
		} else {
		    /*
		     * Otherwise, serial is used for some memory decoding.
		     * Determine which one.
		     */
		    info.serial_off = get_pattern_offset_robn89(buf,
						limit_off,
						-search_sz,
						info.magic32,
						serial_eor_patterns_robn89);
		    if (info.serial_off >= 0) {
			/*
			 * Serial is used to XOR a 32-bit word in memory.
			 */
			info.serial_usage = SERIAL_USAGE_EOR_MEM_ROBN;
		    } else {
			/*
			 * Serial is used to perform complex memory decoding.
			 */
			info.serial_usage = SERIAL_USAGE_OTHER_MEM_ROBN;
		    }
		}
	    } else {
		/*
		 * Serial seems not to be used or is used in an unknown manner.
		 */
		info.serial_usage = SERIAL_USAGE_UNKNOWN_ROBN;
	    }
	}
    }

    info.prog_off += offset;

    info.start_off     += offset;
    info.pushtramp_off += offset;

    if (info.decode_off >= 0) {
	info.decode_off += offset;
    }

    if (info.reloc_off >= 0) {
	info.reloc_off += offset;
    }

    if (info.vecs_off >= 0) {
	info.vecs_off += offset;
    }

    if (info.keydisk_off >= 0) {
	info.keydisk_off += offset;
    }

    if (info.serial_off >= 0) {
	info.serial_off += offset;
    }

    if (check_size_robn(prog, &info)) {
	return 1;
    }

#if defined (TARGET_ST)
    if ((info.decode_off >= 0) || (info.serial_off >= 0)) {
	/*
	 * Continue with dynamic analysis.
	 */
	return decode_native_robn89(prog, &info);
    }
#endif

    return print_info_robn(&info, NULL);

unsupp:
    LOG_ERROR("This variant of the Copylock Protection System "
	      "is not supported\n");

    return 1;
}

/*
 * Rob Northen protection code has evolved slightly over time. In particular
 * the protection prolog (non-encrypted code) which is parsed by dec0de to
 * automatically recognize the protection has changed a bit multiple times.
 * Here are the known protection prolog variants of the series 2.
 */

#define PATTERN_SWITCHSUPILL_ROBN89	/* 24 bytes */			\
    0x48, 0xe7, 0xe0, 0xe0,		/* movem.l d0-d2/a0-a2,-(a7) */	\
    0x48, 0x7a, 0x00, 0x12,		/* pea pc+$14 */		\
    0x2f, 0x3c, 0x00, 0x05, 0x00, 0x04,	/* move.l #$50004,-(a7) */	\
    0x4e, 0x4d,				/* trap #$d */			\
    0x50, 0x4f,				/* addq.[w|l] #8,a7 */		\
    0x4c, 0xdf, 0x07, 0x07,		/* movem.l (a7)+,d0-a2/a0-a2 */	\
    0x4a, 0xfc				/* illegal */

#define PATTERN_MASK_SWITCHSUPILL_ROBN89				\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff,								\
    0xff, 0x0f,				/* 0x504f | 0x508f */		\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff

#define PATTERN_SWITCHSUP_ROBN89	/* 8 bytes */			\
    0x42, 0xa7,				/* clr.l,-(a7) */		\
    0x3f, 0x3c, 0x00, 0x20,		/* move.w #32,-(a7) */		\
    0x4e, 0x41				/* trap #1 */

#define PATTERN_CACHE_ROBN89(_o1, _o2)	/* 20 bytes */			\
    0x20, 0x4f,				/* movea.l a7,a0 */		\
    0x4e, 0x7a, 0x00, 0x02,		/* MOVEC CACR,d0 */		\
    0x2f, 0x40, _o1, _o2,		/* move.l d0,_o1_o2(a7) */	\
    0x08, 0x80, 0x00, 0x00,		/* bclr #0,d0 */		\
    0x4e, 0x7b, 0x00, 0x02,		/* MOVEC d0,CACR */		\
    0x2e, 0x48				/* movea.l a0,a7 */

#define PATTERN_MASK_CACHE_ROBN89(_o1, _o2)				\
    0xff, 0xff,								\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, _o1, _o2,						\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff, 0xff, 0xff,						\
    0xff, 0xff

#define PATTERN_TVD_ROBN89		/* 66 bytes */			\
    0x4c, 0xfa, 0x7f, 0xff, 0x00, 0x02,	/* movem.l pc+$4,d0-a6 */	\
    0x2f, 0x3c, 0x4e, 0x73, 0x00, 0x00,	/* move.l #$4e730000,-(a7) */	\
    0x2f, 0x3c, 0x00, 0x00, 0x00, 0x10,	/* move.l #$10,-(a7) */		\
    0x2f, 0x3c, 0x00, 0x04, 0xdd, 0xb9,	/* move.l #$4ddb9,-(a7) */	\
    0x2f, 0x3c, 0xbd, 0x96, 0xbd, 0xae,	/* move.l #$bd96bdae,-(a7) */	\
    0x2f, 0x3c, 0xb3, 0x86, 0xb5, 0x86,	/* move.l #$b386b586,-(a7) */	\
    0x2f, 0x3c, 0xd0, 0x46, 0xd2, 0x46,	/* move.l #$d046d246,-(a7) */	\
    0x2f, 0x3c, 0x02, 0x46, 0xa7, 0x1f,	/* move.l #$246a71f,-(a7) */	\
    0x2f, 0x3c, 0x00, 0x02, 0x3c, 0x17,	/* move.l #$23c17,-(a7) */	\
    0x2f, 0x3c, 0x00, 0x04, 0x2c, 0x6f,	/* move.l #$42c6f,-(a7) */	\
    0x2f, 0x3c, 0xbd, 0x96, 0xbd, 0xae	/* move.l #$bd96bdae,-(a7) */

#define PATTERN_MASK_TVD_ROBN89						\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,					\
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff

DECLARE_PATTERN_WITH_MASK(pattern_switchsupill_robn89,
    PATTERN_ANY,
    0x0, 0x10, 24,
    PATTERN_BUFFER(
    PATTERN_SWITCHSUPILL_ROBN89
    ),
    PATTERN_BUFFER(
    PATTERN_MASK_SWITCHSUPILL_ROBN89
    )
    );

DECLARE_PATTERN(pattern_switchsup_robn89,
    PATTERN_ANY,
    0x0, 0x10, 8,
    PATTERN_BUFFER(
    PATTERN_SWITCHSUP_ROBN89
    )
    );

DECLARE_PATTERN_WITH_MASK(pattern_init1_robn89,
    PATTERN_ANY,
    PATTERN_NEXT, 0x20, 116,
    PATTERN_BUFFER(
    0x48, 0xe7, 0xff, 0xff,		/* movem.l d0-a7,-(a7) */
    0x48, 0x7a, 0x00, 0x1a,		/* pea pc+$1c */
    0x23, 0xdf, 0x00, 0x00, 0x00, 0x10,	/* move.l (a7)+,$10 */
    PATTERN_CACHE_ROBN89(0x00, 0x3c),
    PATTERN_TVD_ROBN89,
    0x23, 0xcf, 0x00, 0x00, 0x00, 0x24,	/* move.l a7,$24 */
    0x00, 0x7c, 0xa7, 0x1f,		/* ori.w #$a71f,sr */
    0x5c, 0xb9, 0x00, 0x00, 0x00, 0x24	/* addq.l #6,$24 */
    ),
    PATTERN_BUFFER(
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    PATTERN_MASK_CACHE_ROBN89(0xff, 0x00),
    PATTERN_MASK_TVD_ROBN89,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    )
    );

DECLARE_PATTERN_WITH_MASK(pattern_init2_robn89,
    PATTERN_ANY,
    PATTERN_NEXT, 0x20, 110,
    PATTERN_BUFFER(
    0x48, 0xe7, 0xff, 0xff,		/* movem.l d0-a7,-(a7) */
    0x48, 0x7a, 0x00, 0x18,		/* pea pc+$1a [!] */
    0x21, 0xdf, 0x00, 0x10,		/* move.l (a7)+,$10.w [!] */
    PATTERN_CACHE_ROBN89(0x00, 0x3c),
    PATTERN_TVD_ROBN89,
    0x21, 0xcf, 0x00, 0x24,		/* move.l a7,$24.w [!] */
    0x00, 0x7c, 0xa7, 0x1f,		/* ori.w #$a71f,sr */
    0x5c, 0xb8, 0x00, 0x24		/* addq.l #6,$24.w [!] */
    ),
    PATTERN_BUFFER(
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    PATTERN_MASK_CACHE_ROBN89(0xff, 0x00),
    PATTERN_MASK_TVD_ROBN89,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff
    )
    );

DECLARE_PROTECTION_PARENT(prot_robn89a,
    "Copylock Protection System series 2 (1989) by Rob Northen",
    'a',
    ROBN89_OFF,
    PATTERNS_LIST(
    &pattern_switchsupill_robn89,
    &pattern_init1_robn89
    ),
    decode_robn89,
    NULL
    );

DECLARE_PROTECTION_VARIANT(prot_robn89b,
    &prot_robn89a,
    'b',
    ROBN89_OFF,
    PATTERNS_LIST(
    &pattern_switchsupill_robn89,
    &pattern_init2_robn89
    ),
    NULL,
    NULL
    );

DECLARE_PROTECTION_VARIANT(prot_robn89c,
    &prot_robn89a,
    'c',
    ROBN89_OFF,
    PATTERNS_LIST(
    &pattern_switchsup_robn89,
    &pattern_init1_robn89
    ),
    NULL,
    NULL
    );

DECLARE_PROTECTION_VARIANT(prot_robn89d,
    &prot_robn89a,
    'd',
    ROBN89_OFF,
    PATTERNS_LIST(
    &pattern_switchsup_robn89,
    &pattern_init2_robn89
    ),
    NULL,
    NULL
    );

DECLARE_PROTECTION_VARIANT(prot_robn89e,
    &prot_robn89a,
    'e',
    ROBN89_OFF,
    PATTERNS_LIST(
    &pattern_none,
    &pattern_init1_robn89
    ),
    NULL,
    PROT_PRIV_ROBN89(PROT_FORCE_SUP_ROBN89)
    );

DECLARE_PROTECTION_VARIANT(prot_robn89f,
    &prot_robn89a,
    'f',
    ROBN89_OFF,
    PATTERNS_LIST(
    &pattern_none,
    &pattern_init2_robn89
    ),
    NULL,
    PROT_PRIV_ROBN89(PROT_FORCE_SUP_ROBN89)
    );

/*****************************************************************************
 * Decoder
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
    &prot_cid10,
    &prot_robn88a,
    &prot_robn88b,
    &prot_robn88c,
    &prot_robn88d,
    &prot_robn88e,
    &prot_robn89a,
    &prot_robn89b,
    &prot_robn89c,
    &prot_robn89d,
    &prot_robn89e,
    &prot_robn89f,
    NULL,
};

/*
 * Pattern matching routines.
 */

static int pattern_cmp (const unsigned char* buf1,
			const unsigned char* buf2,
			size_t sz)
{
    const uint16_t* buf16_1 = (const uint16_t*) buf1;
    const uint16_t* buf16_2 = (const uint16_t*) buf2;

    do {
	if (*buf16_1++ != *buf16_2++) {
	    return 1;
	}
	sz -= SIZE_16;
    } while (sz);

    return 0;
}

static int pattern_cmp_mask (const unsigned char* buf1,
			     const unsigned char* buf2,
			     const unsigned char* mask,
			     size_t sz)
{
    const uint16_t* buf16_1 = (const uint16_t*) buf1;
    const uint16_t* buf16_2 = (const uint16_t*) buf2;
    const uint16_t* msk16   = (const uint16_t*) mask;
    uint16_t        w16_1;
    uint16_t        w16_2;
    uint16_t        m16;

    do {
	w16_1 = *buf16_1++;
	w16_2 = *buf16_2++;
	if (w16_1 != w16_2) {
	    m16    = *msk16;
	    w16_1 &= m16;
	    w16_2 &= m16;
	    if (w16_1 != w16_2) {
		return 1;
	    }
	}
	msk16++;
	sz -= SIZE_16;
    } while (sz);

    return 0;
}

static int pattern_match_fixed (prog_t* prog, pattern_t* pattern,
				size_t eoffset)
{
    unsigned char* buf;
    int            diag;

    if (prog->size < eoffset + pattern->count) {
	return 1;
    }

    buf = prog->text + eoffset;

    if (pattern->mask == NULL) {
	diag = pattern_cmp(buf, pattern->buf, pattern->count);
    } else {
	diag = pattern_cmp_mask(buf, pattern->buf, pattern->mask,
				pattern->count);
    }

    if (diag == 0) {
	pattern->eoffset = eoffset;
	pattern->ecount  = pattern->count;
    }

    return diag;
}

static int pattern_match_delta (prog_t* prog, pattern_t* pattern,
				size_t eoffset)
{
    size_t          size;
    size_t          count;
    size_t          limit;
    const uint16_t* buf16;
    uint16_t        p16;

    ASSERT((pattern->mask == NULL) || (read16(pattern->mask) == 0xffff));

    size   = prog->size;
    count  = pattern->count;

    limit  = eoffset + count;
    if (limit > size) {
	return 1;
    }
    limit += pattern->delta;
    limit  = limit < size ? limit : size;
    limit -= count;

    buf16  = (const uint16_t*) (prog->text + eoffset);
    p16    = *((const uint16_t*) pattern->buf);

    do {
	if ((p16 == *buf16) &&
	    (pattern_match_fixed(prog, pattern, eoffset) == 0)) {
	    return 0;
	}
	buf16++;
	eoffset += SIZE_16;
    } while (limit >= eoffset);

    return 1;
}

static int pattern_match (prog_t* prog, pattern_t* pattern,
			  pattern_t* pattern_prev)
{
    size_t offset;

    ASSERT(!((pattern->offset | pattern->count) & 0x1) &&
	   (pattern->count || (pattern == &pattern_none)));

    pattern->eoffset = 0;
    pattern->ecount  = 0;

    if (!(pattern->type & (prog->hsize ? PATTERN_PROG : PATTERN_BIN))) {
	if (pattern_prev) {
	    pattern->eoffset = pattern_prev->eoffset +  pattern_prev->ecount;
	}
	return 0;
    }

    offset = pattern->offset;
    if (offset == PATTERN_NEXT) {
	if (pattern_prev) {
	    offset = pattern_prev->eoffset + pattern_prev->ecount;
	} else {
	    offset = 0;
	}
    }

    if (pattern->delta == 0) {
	return pattern_match_fixed(prog, pattern, offset);
    }

    return pattern_match_delta(prog, pattern, offset);
}

/*
 * Find the protection used by a given program.
 */

#define ENCODED_MSG	"Program '%s' is enc0ded with " PP_LINEBRK "%s"

static prot_t* get_prot (prog_t* prog)
{
    prot_t*      prot;
    pattern_t*   pattern;
    pattern_t*   pattern_prev;
    unsigned int i;
    unsigned int j;

    for (i = 0; (prot = prots[i]) != NULL; i++) {
	ASSERT(!(prot->doffset & 0x1));
	if (prot->doffset &&
	    (prog->size < prot->doffset + sizeof(prog_hdr_t))) {
	    continue;
	}
	for (pattern_prev = NULL, j = 0;
	     (pattern = prot->patterns[j]) != NULL;
	     pattern_prev = pattern, j++) {
	    if (pattern_match(prog, pattern, pattern_prev) != 0) {
		break;
	    }
	}
	if (pattern == NULL) {
	    break;
	}
    }

    if (prot) {
	if (!prot->varnum) {
	    ASSERT(!prot->parent);
	    LOG_INFO(ENCODED_MSG "\n", prog->name, prot->name);
	} else {
	    ASSERT(prot->parent);
	    LOG_INFO(ENCODED_MSG " (variant %c)\n",
		     prog->name, prot->parent->name, prot->varnum);
	}
    } else {
	LOG_ERROR("Unrecognized protection for program '%s'\n", prog->name);
    }

    return prot;
}

/*
 * Load a program, find the corresponding protection, print its name
 * and release allocated resources.
 */
static void print_prot (const char* sname)
{
    prog_t* prog;

    prog = load_prog(sname);
    if (prog) {
	(void) get_prot(prog);
	release_prog(prog);
    }
}

/*
 * Decode a loaded program (without saving it).
 */
static int decode_prog (prog_t* prog)
{
    prot_t*       prot;
    decode_func_t prot_decode;
    int           diag = 1;

    prot = get_prot(prog);

    if (prot) {
	PP_NEWLINE();
	prog->prot = prot;
	prot_decode = PROT_DECODE(prot);
	ASSERT(prot_decode);
	diag = prot_decode(prog, prog->text + prot->doffset,
			   prog->size - prot->doffset);
	if (diag == 0) {
	    diag = fixup_prog(prog);
	}
    }

    return diag;
}

/*
 * Load, decode and save a program.
 */
static int decode (const char* sname, const char* dname)
{
    prog_t* prog;
    int     diag = 1;

    prog = load_prog(sname);
    if (prog) {
	diag = decode_prog(prog);
	if ((diag == 0) && dname) {
	    LOG_INFO("Saving dec0ded program as '%s'\n", dname);
	    diag = save_prog(prog, dname);
	}
	release_prog(prog);
    }

    return diag;
}

/*
 * List supported protections.
 */
static void list_prots (void)
{
    prot_t*      prot;
    unsigned int i;

    LOG_INFO("Supported protections are:\n");
    PP_NEWLINE();

    for (i = 0; (prot = prots[i]) != NULL; i++) {
	if (!prot->parent || (prot->parent == prot)) {
	    LOG_INFO("  %s\n", prot->name);
	}
    }
}

/*****************************************************************************
 * Help & information
 *****************************************************************************/

#define DEC0DE_INFO							\
    DEC0DE_NAME " sources are available at " DEC0DE_REPO "\n"		\
    "Report bugs or unsupported protections to " DEC0DE_EMAIL "\n"

static void usage (char** argv)
{
    LOG_INFO(
    "Usage: %s <command> [<source_file>] [<destination_file>]\n"
    "Remove encryption systems used to protect Atari ST programs.\n"
    "\n"
    "Possible commands are:\n"
    "  -d ... dec0de <source_file> into <destination_file>\n"
    "  -t ... test dec0ding of <source_file>\n"
    "  -p ... display protection name of <source_file>\n"
    "  -l ... list supported protections\n"
    "  -h ... display this help\n"
    "  -i ... provide detailed information\n"
    "  -v ... output version information\n"
    "  -c ... credits\n"
    "\n"
    "This tool has been developed by " DEC0DE_AUTHOR ".\n"
    DEC0DE_INFO,
    PROG_NAME(argv)
    );
}

static void info (void)
{
    LOG_INFO_MORE(
    DEC0DE_VERSION_FULL "\nBy " DEC0DE_TEAM ".\n"
    "\n"
    "Remove encryption systems used to protect Atari ST programs.\n"
    "\n"
    "On Atari ST, encryption systems were often used to protect programs\n"
    "against hacking, reverse-engineering or ripping: the original program\n"
    "was encrypted and transformed into a self-decrypting program.\n"
    "\n"
    "These protections were developed by the game industry or by the sceners\n"
    "themselves. Most popular protections are Copylock by Rob Northen,\n"
    "Anti-bitos by Illegal, Cooper by Cameo...\n"
    "\n"
    DEC0DE_NAME " merely removes such protections, thus enabling to restore\n"
    "the original unprotected programs.\n"
    "\n"
    "If a protected program crashes under your emulator or on your machine,\n"
    "if it contains a music, a picture or a scrolltext you want to rip,\n"
    "or if it is a software you want to hack, then " DEC0DE_NAME
    " is made for you.\n"
    );
    LOG_INFO_MORE(
    DEC0DE_NAME " expects the protected program to be provided as a regular\n"
    "file. Therefore it is up to you to extract the program from the disk if\n"
    "there is no filesystem on it.\n"
    "\n"
    "A protected program can be provided to " DEC0DE_NAME " as a GEMDOS or a\n"
    "raw binary program file. " DEC0DE_NAME " will automatically recognize\n"
    "the protection, will extract the original unprotected program and will\n"
    "save it in its original format (GEMDOS or raw binary program file).\n"
    "\n"
    "If the resulting unprotected program is packed, then you can use the\n"
    "well known depackers (New Depack, Naughty Unpacker...) to obtain the\n"
    "original uncompressed file.\n"
    "\n"
    "Depackers links:\n"
    "- New Depack                https://demozoo.org/productions/96097/\n"
    "- The Naughty Unpacker      https://demozoo.org/productions/75456/\n"
    "- The UPX packer/unpacker   https://upx.github.io/\n"
    );
    LOG_INFO_MORE(
    "Note about the Rob Northen Copylock Systems:\n"
    "\n"
#if !defined (TARGET_ST)
    "To determine the serial number and to extract the original unprotected\n"
    "program, " DEC0DE_NAME " must be run on a real or emulated Atari ST.\n"
    "\n"
#endif
    "Besides decrypting the program, " DEC0DE_NAME " also provides useful\n"
    "details about the Copylock protection: the serial number and the\n"
    "memory address it is saved to, the use of extra tricks in the\n"
    "protection (extra magic value, special serial key usage).\n"
    "Such details may be needed to properly crack the protected software.\n"
    "\n"
#if !defined (TARGET_ST)
    "When run on Linux, Mac OS or Windows, " DEC0DE_NAME " provides these\n"
    "details as much as possible, while skipping the decryption process.\n"
    "\n"
#endif
    "In addition to the Copylock 'wrapper' type (self-decrypting program)\n"
    DEC0DE_NAME" also supports the Copylock 'internal' type (self-decrypting\n"
    "routine inside a host program).\n"
    "You just need to extract the encrypted routine from the host program\n"
    "and to provide it as a file to " DEC0DE_NAME ".\n"
    DEC0DE_NAME " will analyze the encrypted routine and give the details\n"
    "needed to crack the protection (such as the serial number and how\n"
    "it is used).\n"
    "\n"
    "Original copy-locked floppy disks are available as image files that can\n"
    "be used on most Atari ST emulators. Such images can be found at:\n"
    "- Atari Mania    http://www.atarimania.com\n"
    "- Atari Legend   http://www.atarilegend.com\n"
    );
    LOG_INFO(
    "Greetings to all Atari ST sceners, past and present.\n"
    "\n"
    "Thanks to all Atari ST enthusiasts who contribute to keep the Atari ST\n"
    "scene and spirit alive.\n"
    "\n"
    "Special thanks to the following people:\n"
    "- Mr Nours ^ MJJ Prod for his essential Fuzion Shrine website\n"
    "  http://fuzionshrine.omiquel.lautre.net\n"
    "- Jace ^ ST Knights for his support to The Replicants\n"
    "  http://replicants.free.fr/index.php\n"
    "- Brume ^ Atari Legend for his amazing archiving effort\n"
    "  http://www.atarilegend.com & http://www.stonish.net/Fuzion-61\n"
    "- Lotek Style ^ tSCc for his great work on Demozoo\n"
    "  https://demozoo.org\n"
    "\n"
    "A big hi to Marcer ^ Elite, Mug UK ^ AL, Zorro2 ^ NoExtra, St Cooper,\n"
    "Mara ^ Flush, Marco Breddin.\n"
    "\n"
    "A warm hello to all Replicants and Fuzion members, especially Ellfire,\n"
    "Cameo, Kasar, Squat, JackTBS, Docno, Illegal, Snake, Excalibur, Fury...\n"
    "\n"
    DEC0DE_INFO
    );
}

static void version (void)
{
    LOG_INFO(DEC0DE_VERSION_FULL "\n");
}

static void credits (void)
{
    LOG_INFO("Credits:\n");
    PP_NEWLINE();
    LOG_INFO(
    "  Code & reverse engineering ... Orion ^ The Replicants ^ Fuzion\n"
    "  Reverse engineering .......... Maartau ^ Atari Legend ^ Elite\n"
#if defined (TARGET_ST)
    "  ASCII logo ................... Senser ^ Effect ^ Vectronix\n"
#endif
    "\n"
    DEC0DE_INFO
    );
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
 * Using interactive mode?
 */
static int       ia_mode_usage;

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
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	%0,%%sp@-			\n\t"
	    "move.w	#9,%%sp@-			\n\t"
	    "trap	#1				\n\t"
	    "addq.l	#6,%%sp				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    :
	    : "g" (txt)
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);
}

#define PRINT(_t)							\
    do {								\
	print(_t);							\
	log_count++;							\
    } while (0)

/*
 * Key wait (Crawcin).
 */
static int key_wait (void)
{
    register uint32_t key;

    __asm__ __volatile__
	(
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	#7,%%sp@-			\n\t"
	    "trap	#1				\n\t"
	    "addq.l	#2,%%sp				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
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
    register uint16_t drv;

    __asm__ __volatile__
	(
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	#25,%%sp@-			\n\t"
	    "trap	#1				\n\t"
	    "addq.l	#2,%%sp				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
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
    register int32_t diag;

    __asm__ __volatile__
	(
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	%1,%%sp@-			\n\t"
	    "move.l	%2,%%sp@-			\n\t"
	    "move.w	#71,%%sp@-			\n\t"
	    "trap	#1				\n\t"
	    "addq.l	#8,%%sp				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
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
    register int32_t diag;

    __asm__ __volatile__
	(
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	%1,%%sp@-			\n\t"
	    "move.w	#38,%%sp@-			\n\t"
	    "trap	#14				\n\t"
	    "addq.l	#6,%%sp				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
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
    register uint16_t rez;

    __asm__ __volatile__
	(
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	#4,%%sp@-			\n\t"
	    "trap	#14				\n\t"
	    "addq.l	#2,%%sp				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
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
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	%0,%%sp@-			\n\t"
	    "move.l	#-1,%%sp@-			\n\t"
	    "move.l	#-1,%%sp@-			\n\t"
	    "move.w	#5,%%sp@-			\n\t"
	    "trap	#14				\n\t"
	    "add.l	#12,%%sp			\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
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
    register int16_t oldcolor;

    __asm__ __volatile__
	(
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.w	%1,%%sp@-			\n\t"
	    "move.w	%2,%%sp@-			\n\t"
	    "move.w	#7,%%sp@-			\n\t"
	    "trap	#14				\n\t"
	    "addq.l	#6,%%sp				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
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
    register void* linea_addr;

    __asm__ __volatile__
	(
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	#0, %%a0			\n\t"
	    "dc.w	0xa000				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
	    "						\n\t"
	    "movea.l	%%a0, %0			\n\t"
	    : "=a" (linea_addr)
	    :
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

      if (!linea_addr || !(*(void**)((uint8_t*)linea_addr + 8))) {
	  PRINT("Line-A initialization failed\n\r");
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
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	%0,%%a0				\n\t"
	    "move.l	%%a0@(8),%%a1			\n\t"
	    "move.w	#0,%%a1@ 			\n\t"
	    "dc.w	0xa009				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
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
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	%0,%%a0				\n\t"
	    "move.l	%%a0@(8),%%a1			\n\t"
	    "move.w	#0,%%a1@ 			\n\t"
	    "dc.w	0xa00a				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
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
    register int32_t diag;

    __asm__ __volatile__
	(
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-	\n\t"
	    "						\n\t"
	    "move.l	#200,%%d0			\n\t"
	    "move.l	%1,%%d1				\n\t"
	    "trap	#2				\n\t"
	    "						\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5	\n\t"
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
	PRINT("AES initialization (aes_appl_init) failed\n\r");
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
	PRINT("AES cleanup (aes_appl_exit) failed\n\r");
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
	PRINT("AES file selector (fsel_input) failed\n\r");
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
 * Prints a new line only if the last printed line is not empty.
 */

static void pp_newline (void)
{
    static int log_count_nl;

    if (log_count_nl != log_count) {
	print("\n\r");
	log_count_nl = log_count;
    }
}

/*
 * Interactive (IA) mode services.
 */

static int ia_mode_avail (void)
{
    ASSERT(mouse_hid_count_p);
    return !mouse_is_hidden;
}

#define DEC0DE_LOGO1												\
"      _  _______  _  _______  _  _______  _  _______  _  _______  _  _______    \n\r"				\
"    ____\\\\__   / ___\\\\__   / ___\\\\__   / ___\\\\__   /____\\\\__   / ___\\\\__   /    \n\r"		\
" __/   __     /_/    __   /_/  _      /_/  _      /    __     /_/    __   /     \n\r"				\
" \\     \\|    /_\\     /___/_\\_  \\_____/_\\_  \\     /___  \\|    /_\\     /___/___ s \n\r"			\
"  \\     \\      _\\_   __/   _/   \\      _/   \\      _/   \\      _\\_   __/   _/ n \n\r"			\
"   \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\  s \n\r"		\
"    \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\   \n\r"		\
"  $  \\_______ D  \\_______ E  \\_______ C  \\_______ 0  \\_______ D  \\_______ E  \\  \n\r"			\
"            \\_____\\     \\_____\\     \\_____\\     \\_____\\     \\_____\\     \\_____\\ \n\r"

#define DEC0DE_LOGO2												\
"     _  _______  _  _______  _  _______  _  _______  _  _______  _  _______     \n\r"				\
"   ____\\\\__   /\\___\\\\__   /\\___\\\\__   /\\___\\\\__   /\\___\\\\__   /\\___\\\\__   /\\    \n\r"	\
"__/   __     /_/    __   /_/  _      /_/  _      /_/  __     /_/    __   / /    \n\r"				\
"\\     \\|    /_\\     /___/_\\_  \\_____/_\\_  \\     /___  \\|    /_\\     /___/_/___  \n\r"			\
" \\     \\      _\\_   __/   _/   \\      _/   \\      _/   \\      _\\_   __/   _/_/  \n\r"			\
"  \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\ \\   \n\r"		\
"   \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\ \\  \n\r"		\
" $  \\_______ D  \\_______ E  \\_______ C  \\_______ 0  \\_______ D  \\_______ E  \\ \\ \n\r"			\
"      sns  \\_____\\/    \\_____\\/    \\_____\\/    \\_____\\/    \\_____\\/    \\_____\\/ \n\r"

#define DEC0DE_LOGO3												\
"        ________    ________    ________    ________    ________    ________    \n\r"				\
"    ____\\\\__   / ___\\\\__   / ___\\\\__   / ___\\\\__   /____\\\\__   / ___\\\\__   /    \n\r"		\
" __/          /_/         /_/         /_/         /           /_/         /     \n\r"				\
" \\      __   /_\\    _____/_\\_  ______/_\\_  ___   /___   __   /_\\    _____/___ s \n\r"			\
"  \\     \\      _\\__  __/   _/   \\      _/   \\      _/   \\      _\\__  __/   _/ n \n\r"			\
"   \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\  s \n\r"		\
"    \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\   \n\r"		\
"  $  \\_______ D  \\_______ E  \\_______ C  \\_______ 0  \\_______ D  \\_______ E  \\  \n\r"			\
"            \\_____\\     \\_____\\     \\_____\\     \\_____\\     \\_____\\     \\_____\\ \n\r"

#define DEC0DE_LOGO4												\
"         _______     _______     _______     _______     _______     _______    \n\r"				\
"    ____\\\\__   / ___\\\\__   / ___\\\\__   / ___\\\\__   /____\\\\__   / ___\\\\__   /    \n\r"		\
" __/          /_/         /_/         /_/         /           /_/         /     \n\r"				\
" \\      __   /_\\    _____/_\\_  ______/_\\_  ___   /___   __   /_\\    _____/___ s \n\r"			\
"  \\     \\|     _\\__  __/   _/   \\|     _/   \\|     _/   \\|     _\\__  __/   _/ n \n\r"			\
"   \\     \\     \\     \\|    \\     \\     \\     \\     \\     \\     \\     \\|    \\  s \n\r"		\
"    \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\     \\   \n\r"		\
"  $  \\_______ D  \\_______ E  \\_______ C  \\_______ 0  \\_______ D  \\_______ E  \\  \n\r"			\
"            \\_____\\     \\_____\\     \\_____\\     \\_____\\     \\_____\\     \\_____\\ \n\r"

#define DEC0DE_LOGO5												\
"             _____                                           _____              \n\r"				\
"            _\\\\   \\                          $ d e c 0 d e  _\\\\   \\             \n\r"			\
"     ______/     _/\\_______  _/\\_______  _/\\_______  ______/     _/\\_______     \n\r"			\
"   \\\\\\_ __     \\\\\\_ __     \\\\\\_ __     \\\\\\_ __     \\\\\\_ __     \\\\\\_ __     \\\\   \n\r"	\
"    /    /      /    /      /    /      /    /      /    /      /    /      /\\  \n\r"				\
"   /    /      /    /      /    /      /    /      /    /      /    /      / /  \n\r"				\
"  /    /      /    /      /    /______/    /      /    /      /    /      / /   \n\r"				\
"  \\   /      /\\   _______/\\   /      /\\   /      /\\   /      /\\   _______/ /    \n\r"			\
"   \\____    / /\\____    /\\/\\____    / /\\____    / /\\____    / /\\____    /\\/     \n\r"			\
"   \\\\__\\___/ / \\\\__\\___/ / \\\\__\\___/ / \\\\__\\___/ / \\\\__\\___/ / \\\\__\\___/ //     \n\r"	\
"        \\__\\/       \\__\\/       \\__\\/       \\__\\/       \\__\\/       \\__\\/  sns  \n\r"

#define DEC0DE_LOGO_FAVORITE	5

#define DEC0DE_LOGO_NR		5

#define LINE_FILL		"\t\t\t\t\t\t\t\t\t\t"

static unsigned int rand_seed = 0;
static unsigned int logo_idx;

static int32_t rand_seed_set (void)
{
    unsigned char cnt;

    do {
	cnt        = *(volatile unsigned char*) 0xffff8207;
	rand_seed  = ((unsigned int) cnt) << 8;
	cnt        = *(volatile unsigned char*) 0xffff8209;
	rand_seed |= ((unsigned int) cnt) << 0;
    } while (rand_seed == 0);

    return 0;
}

static inline const char* menu_text_get (void)
{
    static char        buf[82*25+1];
    static const char* logos[DEC0DE_LOGO_NR] = {
	DEC0DE_LOGO1,
	DEC0DE_LOGO2,
	DEC0DE_LOGO3,
	DEC0DE_LOGO4,
	DEC0DE_LOGO5,
    };
    unsigned int rand_nr;

    if (rand_seed == 0) {
	(void) supexec(rand_seed_set);
	srand(rand_seed);
	rand_nr = (unsigned int) rand();
	/* Randomly choose a logo */
	if (rand_nr & (1 << 8)) {
	    logo_idx = DEC0DE_LOGO_FAVORITE - 1;
	} else {
	    logo_idx = rand_nr % DEC0DE_LOGO_NR;
	}
    } else {
	logo_idx = (logo_idx + 1) % DEC0DE_LOGO_NR;
    }

    strcpy(buf,
	   CLEAR_HOME
	   WRAP_OFF
	   REV_ON
	   "\r" LINE_FILL "\n\r");

    strcat(buf, logos[logo_idx]);

    strcat(buf,
	   LINE_FILL "\n\r"
	   LINE_FILL "\r"
	   "  " DEC0DE_VERSION_FULL " By " DEC0DE_TEAM ".\n\r"
	   LINE_FILL "\n\r"
	   REV_OFF
	   "\n\r"
	   REV_ON " 1 " REV_OFF "   Dec0de a protected program\n\r"
	   REV_ON " 2 " REV_OFF "   List supported protections\n\r"
	   REV_ON " 3 " REV_OFF "   Detailed Information\n\r"
	   REV_ON " 4 " REV_OFF "   Credits\n\r"
	   REV_ON " 5 " REV_OFF "   Exit\n\r"
	   WRAP_ON);

    return buf;
}

static int ia_mode_enter (void)
{
    char    path[256];
    prog_t* prog;
    int     key;
    int     wait_return;
    int     diag;

    ia_mode_usage = 1;
    prog          = NULL;
    wait_return   = 0;

    do {

	print(menu_text_get());

	key = key_wait();
	if ((key >= 'a') && (key <= 'z')) {
	    key = key + 'A' - 'a';
	}

	print(CLEAR_HOME);

	switch(key)
	{
	case '1':
	{
	    print("Select a program file");

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

	    diag = decode_prog(prog);
	    if (diag) {
		wait_return = 1;
		break;
	    }

	    PP_NEWLINE();
	    print("Save dec0ded program? " REV_ON " (Y/N) " REV_OFF);

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

	case '4':
	    credits();
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
	    PP_NEWLINE();
	    print(REV_ON "Press any key to return to the menu" REV_OFF);
	    key_wait();
	    wait_return = 0;
	}

    } while (key != '5');

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

    print(CLEAR_HOME CUR_OFF WRAP_ON "\r");

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
	PRINT("Insufficient screen resolution\n\r"
	      "Try medium or higher resolution\n\r");
	return 1;
    }

    return aes_appl_init();
}

static void prog_atexit (void)
{
    unsigned int i;

    if (!ia_mode_usage) {
	PP_NEWLINE();
	print(REV_ON "Press any key to quit" REV_OFF);
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

/*****************************************************************************
 * Native (Atari ST) protection code execution helpers
 *****************************************************************************/

/*
 * Vectors and system variables are described at:
 * http://dev-docs.atariforge.org/files/The_Atari_Compendium.pdf
 */

#define HW_VECTORS_COUNT		(128 - 2)
#define VBL_QUEUE_MAX			32

#define READ16_VECTOR(_a)		\
    (*((uint16_t*) (_a)))

#define READ32_VECTOR(_a)		\
    (*((uint32_t*) (_a)))

#define SAVE_VECTOR(_d, _s)		\
    do {				\
	*(_d) = *(_s);			\
    } while (0)

#define SWAP_VECTOR(_d, _s)		\
    do {				\
	uint32_t _t = *(_s);		\
	*(_s) = *(_d);			\
	*(_d) = _t;			\
    } while (0)

/*
 * For saving/restoring vectors before/after running a native protection code.
 */
static struct {
    uint32_t hw[HW_VECTORS_COUNT];	/* $8-$200 */
    uint32_t vlbq[VBL_QUEUE_MAX];	/*  [$456] */
    uint32_t prv_lst;			/*   $50a  */
    uint32_t prv_aux;			/*   $512  */
    uint32_t resvalid;			/*   $426  */
    uint32_t resvector;			/*   $42a  */
} vectors;

/*
 * Save Atari ST vectors.
 */
static int32_t save_vectors (void)
{
    uint32_t*    v;
    unsigned int n;
    unsigned int i;

    v = (uint32_t*) 0x8;			/* first vector, bus error */

    for (i = 0; i < HW_VECTORS_COUNT; i++) {
	SAVE_VECTOR(&vectors.hw[i], &v[i]);
    }

    n = (unsigned int) READ16_VECTOR(0x454);	/* nvbls */
    v = (uint32_t*)    READ32_VECTOR(0x456);	/* _vblqueue */

    ASSERT(n <= VBL_QUEUE_MAX);

    for (i = 0; i < n; i++) {
	SAVE_VECTOR(&vectors.vlbq[i], &v[i]);
    }

    SAVE_VECTOR(&vectors.prv_lst,   (uint32_t*) 0x50a);
    SAVE_VECTOR(&vectors.prv_aux,   (uint32_t*) 0x512);

    SAVE_VECTOR(&vectors.resvalid,  (uint32_t*) 0x426);
    SAVE_VECTOR(&vectors.resvector, (uint32_t*) 0x42a);

    return 0;
}

/*
 * Restore Atari ST vectors.
 */
static int32_t restore_vectors (void)
{
    uint32_t*    v;
    unsigned int n;
    unsigned int i;

    v = (uint32_t*) 0x8;			/* first vector, bus error */

    for (i = 0; i < HW_VECTORS_COUNT; i++) {
	SWAP_VECTOR(&vectors.hw[i], &v[i]);
    }

    n = (unsigned int) READ16_VECTOR(0x454);	/* nvbls */
    v = (uint32_t*)    READ32_VECTOR(0x456);	/* _vblqueue */

    for (i = 0; i < n; i++) {
	SWAP_VECTOR(&vectors.vlbq[i], &v[i]);
    }

    SWAP_VECTOR(&vectors.prv_lst,   (uint32_t*) 0x50a);
    SWAP_VECTOR(&vectors.prv_aux,   (uint32_t*) 0x512);

    SWAP_VECTOR(&vectors.resvalid,  (uint32_t*) 0x426);
    SWAP_VECTOR(&vectors.resvector, (uint32_t*) 0x42a);

    return 0;
}

/*
 * For disabling/restoring cache before/after running a native protection code.
 */
static uint32_t cache_flag;

/*
 * Disable cache, to allow self-modifying code.
 */
static int32_t disable_cache (void)
{
    register uint32_t cf;

    __asm__ __volatile__
	(
	    "move.l	0x10.l,%%sp@-					\n\t"
	    "movea.l	%%sp,%%a0					\n\t"
	    "lea	1f(pc),%%a1					\n\t"
	    "move.l	%%a1,0x10.l					\n\t"
	    "								\n\t"
	    "moveq.l	#0,%0						\n\t"
	    "dc.w	0x4e7a,0x0002		;# MOVEC CACR,%%d0	\n\t"
	    "move.l	%%d0,%0						\n\t"
	    "bclr	#0,%%d0						\n\t"
	    "dc.w	0x4e7b,0x0002		;# MOVEC %%d0,CACR	\n\t"
	    "1:								\n\t"
	    "movea.l	%%a0,%%sp					\n\t"
	    "move.l	%%sp@+,0x10.l					\n\t"
	    : "=d" (cf)
	    :
	    : "cc", "%%d0", "%%a0", "%%a1", "memory"
	);

    cache_flag = cf;

    return 0;
}

/*
 * Restore cache.
 */
static int32_t restore_cache (void)
{
    __asm__ __volatile__
	(
	    "move.l	0x10.l,%%sp@-					\n\t"
	    "movea.l	%%sp,%%a0					\n\t"
	    "lea	1f(pc),%%a1					\n\t"
	    "move.l	%%a1,0x10.l					\n\t"
	    "								\n\t"
	    "move.l	%0,%%d0						\n\t"
	    "dc.w	0x4e7b,0x0002		;# MOVEC %%d0,CACR	\n\t"
	    "1:								\n\t"
	    "movea.l	%%a0,%%sp					\n\t"
	    "move.l	%%sp@+,0x10.l					\n\t"
	    :
	    : "g" (cache_flag)
	    : "cc", "%%d0", "%%a0", "%%a1", "memory"
	    );

    return 0;
}

#define IDX_D0_REG			0
#define IDX_D1_REG			1
#define IDX_D2_REG			2
#define IDX_D3_REG			3
#define IDX_D4_REG			4
#define IDX_D5_REG			5
#define IDX_D6_REG			6
#define IDX_D7_REG			7
#define IDX_A0_REG			8
#define IDX_A1_REG			9
#define IDX_A2_REG			10
#define IDX_A3_REG			11
#define IDX_A4_REG			12
#define IDX_A5_REG			13
#define IDX_A6_REG			14
#define IDX_A7_REG			15

static uint32_t registers[16];

#define IDX_PROT_ENTRY_RUNPROT		0
#define IDX_TRAMPOLINE_ADDR_RUNPROT	1
#define IDX_NEW_SSP_RUNPROT		2
#define IDX_SUP_MODE_RUNPROT		3
#define IDX_RESTORE_VECS_RUNPROT	4
#define IDX_REGS_RUNPROT		5
#define IDX_SR_RUNPROT			6
#define IDX_SSP_RUNPROT			7
#define IDX_A6_RUNPROT			8
#define IDX_A7_RUNPROT			9
#define IDX_RET_ADDR_RUNPROT		10
#define IDX_MAX_RUNPROT			11

#define ASM_IDX_RUNPROT(_n)		__ASM_STR(4 * IDX_##_n##_RUNPROT)

#define SET_PARAM_RUNPROT(_n, _v)	\
    params.val[IDX_##_n##_RUNPROT] = (uint32_t) (_v)

/*
 * Execute a protection code, natively on the Atari ST.
 *
 * The following parameters are passed:
 * - The entry point address of the protection code.
 * - The address where the "resuming trampoline" should be installed.
 *   The "resuming trampoline" is a routine that should be called from the
 *   native protection code to resume the normal execution of dec0de.
 * - The address of the supervisor stack pointer (optional, NULL can be passed
 *   to use the default SSP).
 * - A boolean to indicate if the protection code should be executed in the
 *   supervisor mode or not.
 *
 * Prior to jumping into the protection code, the vectors are saved, the
 * cache is disabled and the registers are initialized with the content of
 * the global 'registers' array.
 *
 * On return from the protection code, The "resuming trampoline" saves the
 * registers (as left by the protection code) into the global 'registers'
 * array and restores their initial values, it also restores the vectors and
 * resumes the execution of the 'run_prot' function.
 * That function restores the cache and returns to the caller.
 */
static void run_prot (void* prot_entry, void* trampoline_addr,
		      void* new_ssp, unsigned int sup_mode)
{
    static struct {
	uint32_t val[IDX_MAX_RUNPROT];
    } params asm("runprot_params") USED;

    SET_PARAM_RUNPROT(PROT_ENTRY,      prot_entry);
    SET_PARAM_RUNPROT(TRAMPOLINE_ADDR, trampoline_addr);
    SET_PARAM_RUNPROT(NEW_SSP,         new_ssp);
    SET_PARAM_RUNPROT(SUP_MODE,        sup_mode);
    SET_PARAM_RUNPROT(RESTORE_VECS,    restore_vectors);
    SET_PARAM_RUNPROT(REGS,            registers);

    (void) supexec(save_vectors);
    (void) supexec(disable_cache);

    __asm__ __volatile__
	(
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-			\n\t"
	    "								\n\t"
	    "lea	runprot_params,%%a2				\n\t"
	    "								\n\t"
	    "move	%%sr,%%d0					\n\t"
	    "move.w	%%d0,%%a2@(" ASM_IDX_RUNPROT(SR) ")		\n\t"
	    "move.l	%%a6,%%a2@(" ASM_IDX_RUNPROT(A6) ")		\n\t"
	    "move.l	%%sp,%%a2@(" ASM_IDX_RUNPROT(A7) ")		\n\t"
	    "lea	8f(pc),%%a0					\n\t"
	    "move.l	%%a0,%%a2@(" ASM_IDX_RUNPROT(RET_ADDR) ")	\n\t"
	    "								\n\t"
	    "clr.l	%%sp@-						\n\t"
	    "move.w	#32,%%sp@-					\n\t"
	    "trap	#1						\n\t"
	    "								\n\t"
	    "move.l	%%d0,%%a2@(" ASM_IDX_RUNPROT(SSP) ")		\n\t"
	    "move.l	%%a2@(" ASM_IDX_RUNPROT(NEW_SSP) "),%%d2	\n\t"
	    "beq.s	2f						\n\t"
	    "move.l	%%d2,%%d0					\n\t"
	    "2: movea.l	%%d0,%%sp					\n\t"
	    "								\n\t"
	    "lea	5f(pc),%%a0					\n\t"
	    "movea.l	%%a2@(" ASM_IDX_RUNPROT(TRAMPOLINE_ADDR) "),%%a1\n\t"
	    "moveq.l	#(8f-5f+3)/4-1,%%d0				\n\t"
	    "3: move.l	%%a0@+,%%a1@+					\n\t"
	    "dbf	%%d0,3b						\n\t"
	    "								\n\t"
	    "move.w	%%a2@(" ASM_IDX_RUNPROT(SR) "),%%d0		\n\t"
	    "tst.l	%%a2@(" ASM_IDX_RUNPROT(SUP_MODE) ")		\n\t"
	    "beq.s	4f						\n\t"
	    "or.w	#0x2000,%%d0					\n\t"
	    "4: move.l	%%a2@(" ASM_IDX_RUNPROT(PROT_ENTRY) "),%%sp@-	\n\t"
	    "move.w	%%d0,%%sp@-					\n\t"
	    "								\n\t"
	    "movea.l	%%a2@(" ASM_IDX_RUNPROT(REGS) "),%%a0		\n\t"
	    "movem.l	%%a0@,%%d0-%%d7/%%a0-%%a5			\n\t"
	    "								\n\t"
	    "rte							\n\t"
	    "								\n\t"
	    "5:								\n\t"
	    "move.l	%%a2,%%sp@-					\n\t"
	    "lea	runprot_params,%%a2				\n\t"
	    "movea.l	%%a2@(" ASM_IDX_RUNPROT(REGS) "),%%a2		\n\t"
	    "movem.l	%%d0-%%d7/%%a0-%%a6,%%a2@			\n\t"
	    "move.l	%%sp@+,%%a2@(10*4)				\n\t"
	    "								\n\t"
	    "lea	runprot_params,%%a2				\n\t"
	    "movea.l	%%a2@(" ASM_IDX_RUNPROT(SSP) "),%%sp		\n\t"
	    "move	%%sr,%%d0					\n\t"
	    "and.w	#0x3fff,%%d0					\n\t"
	    "or.w	#0x0700,%%d0					\n\t"
	    "move	%%d0,%%sr	;# IPL7, trace off		\n\t"
	    "								\n\t"
	    "movea.l	%%a2@(" ASM_IDX_RUNPROT(RESTORE_VECS) "),%%a0	\n\t"
	    "jsr	%%a0@						\n\t"
	    "								\n\t"
	    "move.l	%%a2@(" ASM_IDX_RUNPROT(RET_ADDR) "),%%sp@-	\n\t"
	    "move.w	%%a2@(" ASM_IDX_RUNPROT(SR) "),%%sp@-		\n\t"
	    "rte							\n\t"
	    "								\n\t"
	    "8:				;# return address		\n\t"
	    "movea.l	%%a2@(" ASM_IDX_RUNPROT(A6) "),%%a6		\n\t"
	    "movea.l	%%a2@(" ASM_IDX_RUNPROT(A7) "),%%sp		\n\t"
	    "								\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5			\n\t"
	    :
	    :
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

    (void) supexec(restore_cache);
}

/*****************************************************************************
 * Copylock Protection System by Rob Northen - Atari ST helper routines
 *****************************************************************************/

/*
 * Print a message and wait for the original disk to be inserted in the
 * floppy drive.
 */

static int wait_prot (int keydisk)
{
    int lc;
    int key;

    lc = log_count;
    print(SAVE_POS);

    PP_NEWLINE();

    if (keydisk) {
	print(REV_ON
	      "Insert original disk and press any key, or press 'C' to cancel"
	      REV_OFF);

	key = key_wait();
	if ((key == 'c') || (key == 'C')) {
	    print(CLEAR_SOL "\r"
		  "Dec0ding canceled!\n\r");
	    log_count++;
	    return 1;
	}
    }

    print(CLEAR_SOL "\r"
	  "Please wait while running the native protection code...");

    print(LOAD_POS);
    log_count = lc;

    return 0;
}

static void end_wait_prot (void)
{
    print(CLEAR_DOWN);
}

/*****************************************************************************
 *
 * Copylock Protection System series 1 (1988) by Rob Northen
 * Atari ST specific code
 *
 * Dynamic (run-time) analysis of the protection.
 *
 * Since the static analysis cannot be performed systematically (it is not
 * possible for the wrapper type), a complex dynamic analysis is performed
 * instead, in order to obtain all the required static and dynamic information:
 * the location and behavior of the different parts of the protection,
 * the value of the serial key, the decrypted program and its execution
 * context.
 * Such complex dynamic analysis is performed for both the internal and the
 * wrapper type (although some information is already available for the
 * internal type, as result of the static analysis).
 *
 * The run-time analysis works as follows: the series 1 uses a single and
 * static (in place) TVD routine. Dec0de replaces this TVD routine with
 * a new one which behaves in the same way but which performs additional
 * on-the-fly checks.
 * Each instruction of the protection (which triggers the TVD routine) is
 * checked in order to:
 * - avoid the trace vector to be modified.
 * - avoid vectors to be checked.
 * - avoid an invalid disk buffer to be used.
 * - determine if a key disk is read.
 * - determine the value of the serial key.
 * - determine the memory location where the serial key is saved to.
 * - determine if an extra magic value is computed from the serial key.
 * - determine the memory location where the extra magic value is saved to.
 * - decrypt the wrapped program if any.
 * - determine if the wrapped program is a GEMDOS or a binary program.
 * - determine the execution context of the program (destination address).
 *
 *****************************************************************************/

#define TRAMPOLINE_ADDR_ROBN88		0x200

#define FLAG_VECS_SETUP_ROBN88		0
#define FLAG_VECS_CHECK_ROBN88		1
#define FLAG_KEY_DISK_ROBN88		2
#define FLAG_SERIAL_ROBN88		3
#define FLAG_MAGIC_ROBN88		4
#define FLAG_PROG_RESUME_ROBN88		5
#define FLAG_NR_ROBN88			6

#define ASM_FLAG_ROBN88(_n)		__ASM_STR(FLAG_##_n##_ROBN88)

#define IDX_ILLVEC_CONT_ROBN88		0
#define IDX_TVD_PINSTR_ROBN88		1
#define IDX_TVD_TYPE_ROBN88		2
#define IDX_TRAMPOLINE_ROBN88		3
#define IDX_DISK_BUFFER_ROBN88		4
#define IDX_PROG_START_ROBN88		5
#define IDX_SERIAL_PTR_ROBN88		6
#define IDX_SERIAL_DST_PTR_ROBN88	7
#define IDX_SERIAL_ONLY_ROBN88		8
#define IDX_MAGIC_PTR_ROBN88		9
#define IDX_MAGIC_DST_PTR_ROBN88	10
#define IDX_PROG_RESUME_ROBN88		11
#define IDX_FLAGS_ROBN88		12
#define IDX_MAX_ROBN88			16

#define ASM_IDX_ROBN88(_n)		__ASM_STR(4 * IDX_##_n##_ROBN88)

#define SET_PARAM_ROBN88(_n, _v)	\
    params.val[IDX_##_n##_ROBN88] = (uint32_t) (_v)

static uint32_t       serial_robn88;
static uint32_t*      serial_dst_robn88;
static uint32_t       magic_robn88;
static uint32_t*      magic_dst_robn88;
static unsigned char* prog_resume_robn88;
static unsigned char* prog_start_robn88;
static uint8_t        flags_robn88[FLAG_NR_ROBN88];

/*
 * Provides the TVD routine used during dynamic analysis and returns
 * the address of the code snippet which is in charge of installing
 * dec0de's illegal handler (which, in turn, installs the TVD routine).
 *
 * Each instruction of the protection code triggers the following TVD routine
 * (instead of the protection one) which performs on-the-fly checks.
 *
 * The protection code of the series 1 has evolved slightly over time.
 * A particular code logic may have been implemented in different ways
 * (typically the vectors checking). The following TVD routine takes
 * all variants of the same code logic into account.
 *
 * In order to replace the TVD routine of the protection with dec0de's
 * TVD routine, the protection code prolog is patched as follows:
 * the instruction which installs the illegal handler of the protection is
 * replaced with a 'Jump to SubRoutine/JSR' to 'label 1' (see below).
 * When 'label 1' is called by the protection prolog, dec0de's illegal
 * handler is installed (replacing that of the protection), the original
 * protection code prolog is restored and the execution of the protection
 * prolog is resumed.
 * When dec0de's illegal handler is invoked, it mimics the behavior of the
 * original illegal handler: it pushes the expected registers onto the stack,
 * it installs the trace handler (and thus dec0de's TVD routine) and it ends
 * with a jump to the original illegal handler to complete the handling of
 * the illegal exception.
 *
 * When dec0de's trace handler is invoked, it mimics the behavior of the
 * original TVD routine: it re-encodes the previously decrypted instruction
 * and decodes the next one. Then it performs on-the-fly checks for each
 * decoded instruction.
 *
 * illvec_cont: where to jump on exit from dec0de's illegal handler in order
 *              to complete the handling of the illegal exception.
 *
 * tvd_pinstr: address used by the protection code to save the address of
 *             the currently decoded instruction and its original encrypted
 *             value. This address is also used by dec0de's TVD routine for
 *             the same purpose.
 *
 * tvd_type: 2 different encryption schemes can be used by the series 1.
 *           This parameter indicates which one is used by the current
 *           protection code.
 *
 * disk_buf: buffer where the key disk sectors should be read to.
 *
 * serial_only: this flag is set if the current protection is an internal type.
 */
static uint32_t tvd_robn88 (void* illvec_cont, void* tvd_pinstr, int tvd_type,
			    void* disk_buf, int serial_only)
{
    register uint32_t entry;

    static struct {
	uint32_t val[IDX_MAX_ROBN88];
    } params asm("tvd_params_robn88") USED;

    SET_PARAM_ROBN88(ILLVEC_CONT,    illvec_cont);
    SET_PARAM_ROBN88(TVD_PINSTR,     tvd_pinstr);
    SET_PARAM_ROBN88(TVD_TYPE,       tvd_type);
    SET_PARAM_ROBN88(TRAMPOLINE,     TRAMPOLINE_ADDR_ROBN88);
    SET_PARAM_ROBN88(DISK_BUFFER,    disk_buf);
    SET_PARAM_ROBN88(PROG_START,     &prog_start_robn88);
    SET_PARAM_ROBN88(SERIAL_PTR,     &serial_robn88);
    SET_PARAM_ROBN88(SERIAL_DST_PTR, &serial_dst_robn88);
    SET_PARAM_ROBN88(SERIAL_ONLY,    serial_only);
    SET_PARAM_ROBN88(MAGIC_PTR,      &magic_robn88);
    SET_PARAM_ROBN88(MAGIC_DST_PTR,  &magic_dst_robn88);
    SET_PARAM_ROBN88(PROG_RESUME,    &prog_resume_robn88);
    SET_PARAM_ROBN88(FLAGS,          flags_robn88);

    __asm__ __volatile__
	(
	    "lea	1f(pc),%0					\n\t"
	    "bra	2f						\n\t"
	    "1:	;# Installs dec0de's illegal handler, restores the	\n\t"
	    "   ;# protection code prolog and returns to the caller	\n\t"
	    "move.l	%%a0,%%sp@-					\n\t"
	    "lea	3f(pc),%%a0					\n\t"
	    "move.l	%%a0,0x10.w					\n\t"
	    "movea.l	%%sp@(4),%%a0					\n\t"
	    "move.w	#0x23c8,%%a0@(-6)				\n\t"
	    "move.l	#0x10,%%a0@(-4)					\n\t"
	    "movea.l	%%sp@+,%%a0					\n\t"
	    "rts							\n\t"
	    "								\n\t"
	    "3:	;# illegal handler - installs the TVD routine		\n\t"
	    "movem.l	%%d0/%%a0-%%a1,%%sp@-				\n\t"
	    "lea	4f(pc),%%a0					\n\t"
	    "move.l	%%a0,0x24.w					\n\t"
	    "lea	tvd_params_robn88,%%a0				\n\t"
	    "move.l	%%a0@(" ASM_IDX_ROBN88(ILLVEC_CONT) "),%%sp@-	\n\t"
	    "rts							\n\t"
	    "								\n\t"
	    "4:	;# trace handler (TVD routine)				\n\t"
	    "andi.w	#0xf8ff,%%sr					\n\t"
	    "movem.l	%%d0/%%a0-%%a1,%%sp@-				\n\t"
	    "lea	tvd_params_robn88,%%a0				\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(TVD_PINSTR) "),%%a1	\n\t"
	    "move.l	%%a0@(" ASM_IDX_ROBN88(TVD_TYPE) "),%%d0	\n\t"
	    "movea.l	%%a1@,%%a0					\n\t"
	    "cmpi.w	#"__ASM_STR(PROT_TVD_FSHARK_ROBN88)",%%d0	\n\t"
	    "bne	50f		;# tvd_common			\n\t"
	    "								\n\t"
	    ";# tvd_fshark - 'Flying Shark'-like encryption logic	\n\t"
	    "move.l	%%a0@(-4),%%d0					\n\t"
	    "sub.l	%%d3,%%d0					\n\t"
	    "not.l	%%d0						\n\t"
	    "swap	%%d0						\n\t"
	    "eor.l	%%d0,%%a0@					\n\t"
	    "movea.l	%%sp@(14),%%a0					\n\t"
	    "move.l	%%a0@(-4),%%d0					\n\t"
	    "sub.l	%%d3,%%d0					\n\t"
	    "not.l	%%d0						\n\t"
	    "swap	%%d0						\n\t"
	    "eor.l	%%d0,%%a0@					\n\t"
	    "move.l	%%a0,%%a1@					\n\t"
	    "bra	60f		;# intercept_instrs		\n\t"
	    "								\n\t"
	    "50: ;# tvd_common - Most commonly used encryption logic	\n\t"
	    "move.l	%%a1@(4),%%a0@					\n\t"
	    "movea.l	%%sp@(14),%%a0					\n\t"
	    "move.l	%%a0,%%a1@					\n\t"
	    "move.l	%%a0@,%%a1@(4)					\n\t"
	    "move.l	%%a0@(-4),%%d0					\n\t"
	    "not.l	%%d0						\n\t"
	    "swap	%%d0						\n\t"
	    "eor.l	%%d0,%%a0@					\n\t"
	    "								\n\t"
	    "60: ;# intercept_instrs - Intercept decoded instructions	\n\t"
	    "move.w	%%a0@,%%d0					\n\t"
	    "								\n\t"
	    ";# Intercept prot vectors setup				\n\t"
	    "cmpi.w	#0x22c1,%%d0	;# move.l d1,(a1)+		\n\t"
	    "bne	110f		;# chk_vecs			\n\t"
	    "100: ;# chk_ill - Intercept illegal vector setup		\n\t"
	    "cmpi.l	#0x10,%%sp@(8)	;# (a1 = 8(sp)) == $10	?	\n\t"
	    "bne	105f		;# chk_trace			\n\t"
	    "move.l	0x10.w,%%d1	;# d1 = illegal handler		\n\t"
	    "bra	9999f		;# tvd_cont			\n\t"
	    "105: ;# chk_trace - Intercept trace vector setup		\n\t"
	    "cmpi.l	#0x24,%%sp@(8)	;# (a1 = 8(sp)) == $24	?	\n\t"
	    "bne	9999f		;# tvd_cont			\n\t"
	    "move.l	0x24.w,%%d1	;# d1 = trace handler		\n\t"
	    "lea	tvd_params_robn88,%%a1				\n\t"
	    "movea.l	%%a1@(" ASM_IDX_ROBN88(FLAGS) "),%%a1		\n\t"
	    "st.b	%%a1@(" ASM_FLAG_ROBN88(VECS_SETUP) ")		\n\t"
	    "bra	9999f		;# tvd_cont			\n\t"
	    "								\n\t"
	    "110: ;# chk_vecs - Intercept vectors checking		\n\t"
	    "     ;# Two variants are supported:			\n\t"
	    "     ;#   - cmpi.l <vec_base>,d[0|1]			\n\t"
	    "     ;#   - cmpi.l <vec_base>,<off>(a[0|1])		\n\t"
	    "cmpi.l	#0xfc0000,%%a0@(2)				\n\t"
	    "bne	120f		;# chk_diskbuf			\n\t"
	    "cmpi.w	#0xb0bc,%%d0	;# cmpi.l #$fc0000,d0		\n\t"
	    "bne	111f		;# chk_vecs_d1			\n\t"
	    "move.l	#0xfc0000,%%sp@	;# (sp) = d0 = #$fc0000		\n\t"
	    "bra	117f		;# chk_vecs_end			\n\t"
	    "111: ;# chk_vecs_d1					\n\t"
	    "cmpi.w	#0xb2bc,%%d0	;# cmpi.l #$fc0000,d1		\n\t"
	    "bne	112f		;# chk_vecs_a1			\n\t"
	    "move.l	#0xfc0000,%%d1	;# d1 = #$fc0000		\n\t"
	    "bra	117f		;# chk_vecs_end			\n\t"
	    "112: ;# chk_vecs_a1					\n\t"
	    "cmpi.w	#0x0c91,%%d0	;# cmpi.l #$fc0000,(a1)		\n\t"
	    "bne	113f		;# chk_vecs_a0			\n\t"
	    "lea	500f(pc),%%a1	;# vecs_fake			\n\t"
	    "move.l	%%a1,%%sp@(8)	;# 8(sp) = a1 = vecs_fake	\n\t"
	    "bra	117f		;# chk_vecs_end			\n\t"
	    "113: ;# chk_vecs_a0					\n\t"
	    "cmpi.w	#0x0ca8,%%d0	;# cmpi.l #$fc0000,-4(a0)	\n\t"
	    "bne	120f		;# chk_diskbuf			\n\t"
	    "lea	500f(pc),%%a1	;# vecs_fake			\n\t"
	    "move.l	%%a1,%%sp@(4)	;# 4(sp) = a0 = vecs_fake	\n\t"
	    "bra	117f		;# chk_vecs_end			\n\t"
	    "nop							\n\t"
	    "117: ;# chk_vecs_end					\n\t"
	    "lea	tvd_params_robn88,%%a1				\n\t"
	    "movea.l	%%a1@(" ASM_IDX_ROBN88(FLAGS) "),%%a1		\n\t"
	    "st.b	%%a1@(" ASM_FLAG_ROBN88(VECS_CHECK) ")		\n\t"
	    "bra	9999f		;# tvd_cont			\n\t"
	    "								\n\t"
	    "120: ;# chk_diskbuf - Intercept disk buffer setup		\n\t"
	    "cmpi.w	#0x0880,%%d0	;# bclr #0,d0			\n\t"
	    "bne	130f		;# chk_keydisk			\n\t"
	    "movea.l	%%sp@,%%a1	;# d0 = (sp) = prot disk buffer	\n\t"
	    "cmpa.l	%%a0,%%a1					\n\t"
	    "blo	9999f		;# tvd_cont			\n\t"
	    "suba.l	%%a0,%%a1					\n\t"
	    "cmpa.l	#0x100000,%%a1					\n\t"
	    "bhs	9999f		;# tvd_cont			\n\t"
	    "lea	tvd_params_robn88,%%a1				\n\t"
	    "movea.l	%%a1@(" ASM_IDX_ROBN88(DISK_BUFFER) "),%%a1	\n\t"
	    "move.l	%%a1,%%sp@	;# (sp) = d0 = new disk buffer	\n\t"
	    "bra	9999f		;# tvd_cont			\n\t"
	    "								\n\t"
	    "130: ;# chk_keydisk - Intercept key disk usage		\n\t"
	    "cmpi.l	#0x0000043e,%%a0@(2)				\n\t"
	    "bne	140f		;# chk_serial			\n\t"
	    "cmpi.w	#0x50f9,%%d0	;# st $43e			\n\t"
	    "bne	140f		;# chk_serial			\n\t"
	    "lea	tvd_params_robn88,%%a1				\n\t"
	    "movea.l	%%a1@(" ASM_IDX_ROBN88(FLAGS) "),%%a1		\n\t"
	    "st.b	%%a1@(" ASM_FLAG_ROBN88(KEY_DISK) ")		\n\t"
	    "bra	9999f		;# tvd_cont			\n\t"
	    "								\n\t"
	    "140: ;# chk_serial - Intercept serial saving		\n\t"
	    "cmpi.w	#0x2140,%%d0					\n\t"
	    "bne	150f		;# chk_badserial		\n\t"
	    "cmpi.w	#0x1c,%%a0@(2)	;# move.l d0,$1c(a0)		\n\t"
	    "bne	9999f		;# tvd_cont			\n\t"
	    "move.l	%%sp@,%%d0	;# d0 = (sp) = serial number	\n\t"
	    "lea	tvd_params_robn88,%%a0				\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(FLAGS) "),%%a1		\n\t"
	    "st.b	%%a1@(" ASM_FLAG_ROBN88(SERIAL) ")		\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(SERIAL_DST_PTR) "),%%a1	\n\t"
	    "move.l	#0x1c+8,%%a1@					\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(SERIAL_PTR) "),%%a1	\n\t"
	    "move.l	%%d0,%%a1@					\n\t"
	    "tst.l	%%a0@(" ASM_IDX_ROBN88(SERIAL_ONLY) ")		\n\t"
	    "bne	8888f		;# tvd_stop			\n\t"
	    "tst.l	%%d0						\n\t"
	    "beq	8888f		;# tvd_stop			\n\t"
	    "bra	9999f		;# tvd_cont			\n\t"
	    "								\n\t"
	    "150: ;# chk_badserial - Intercept bad serial		\n\t"
	    "cmpi.w	#0xd880,%%d0	;# add.l d0,d4			\n\t"
	    "bne	160f		;# chk_magic			\n\t"
	    "lea	tvd_params_robn88,%%a0				\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(FLAGS) "),%%a1		\n\t"
	    "tst.b	%%a1@(" ASM_FLAG_ROBN88(KEY_DISK) ")		\n\t"
	    "beq	9999f		;# tvd_cont			\n\t"
	    "tst.b	%%a1@(" ASM_FLAG_ROBN88(SERIAL) ")		\n\t"
	    "bne	9999f		;# tvd_cont			\n\t"
	    "move.l	%%sp@,%%d0	;# d0 = (sp) = serial number	\n\t"
	    "tst.l	%%d0		;# bad serial if 0		\n\t"
	    "bne	9999f		;# tvd_cont			\n\t"
	    "st.b	%%a1@(" ASM_FLAG_ROBN88(SERIAL) ")		\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(SERIAL_PTR) "),%%a0	\n\t"
	    "move.l	%%d0,%%a0@					\n\t"
	    "bra	8888f		;# tvd_stop			\n\t"
	    "								\n\t"
	    "160: ;# chk_magic - Intercept magic saving			\n\t"
	    "cmpi.w	#0x23c7,%%d0	;# move.l d7,$addr		\n\t"
	    "bne	200f		;# chk_decode			\n\t"
	    "move.l	%%a0@(2),%%d0	;# d0 = magic dest. address	\n\t"
	    "lea	tvd_params_robn88,%%a0				\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(FLAGS) "),%%a1		\n\t"
	    "st.b	%%a1@(" ASM_FLAG_ROBN88(MAGIC) ")		\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(MAGIC_DST_PTR) "),%%a1	\n\t"
	    "move.l	%%d0,%%a1@					\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(MAGIC_PTR) "),%%a0	\n\t"
	    "move.l	%%d7,%%a0@	;# d7 = magic number		\n\t"
	    "bra	9999f		;# tvd_cont			\n\t"
	    "								\n\t"
	    "200: ;# chk_decode - Intercept end of prog decoding	\n\t"
	    "cmpi.w	#0x601a,%%a0@(2)				\n\t"
	    "bne	300f		;# chk_end			\n\t"
	    "cmpi.w	#0x0c50,%%d0	;# cmpi.w #$601a,(a0)		\n\t"
	    "bne	300f		;# chk_end			\n\t"
	    "lea	tvd_params_robn88,%%a0				\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(PROG_START) "),%%a1	\n\t"
	    "cmpi.l	#0,%%a1@					\n\t"
	    "beq	210f		;# chk_decode_hdr		\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(FLAGS) "),%%a1		\n\t"
	    "st.b	%%a1@(" ASM_FLAG_ROBN88(PROG_RESUME) ")		\n\t"
	    "bra	9999f		;# tvd_cont			\n\t"
	    "210: ;# chk_decode_hdr					\n\t"
	    "movea.l	%%sp@(4),%%a0	;# a0 = 4(sp) = start of prog	\n\t"
	    "move.l	%%a0,%%a1@					\n\t"
	    "cmpi.w	#0x601a,%%a0@					\n\t"
	    "beq	8888f		;# tvd_stop			\n\t"
	    "bra	9999f		;# tvd_cont			\n\t"
	    "								\n\t"
	    "300: ;# chk_end - Intercept end of protection		\n\t"
	    "     ;# Three variants of the end of the trampoline code 	\n\t"
	    "     ;# (resume to normal code) are supported:		\n\t"
	    "     ;#   - rte						\n\t"
	    "     ;#   - rts (using usp or ssp)				\n\t"
	    "     ;#   - jmp						\n\t"
	    "cmpi.w	#0x4afc,%%d0	;# illegal			\n\t"
	    "bne	400f		;# chk_end_internal		\n\t"
	    "lea	tvd_params_robn88,%%a0				\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(FLAGS) "),%%a1		\n\t"
	    "cmpi.b	#0,%%a1@(" ASM_FLAG_ROBN88(PROG_RESUME) ")	\n\t"
	    "beq	9999f		;# tvd_cont			\n\t"
	    "movea.l	%%sp@(3*4+6),%%a1 ;# trampoline start addr	\n\t"
	    "310: ;# chk_end_lp1					\n\t"
	    "cmpi.w	#0x4e73,%%a1@	;# rte				\n\t"
	    "bne	320f		;# chk_end_lp2			\n\t"
	    "move.l	%%sp@(3*4+6+4+4*15+2),%%d0			\n\t"
	    "bra	360f		;# chk_end_lp6			\n\t"
	    "320: ;# chk_end_lp2					\n\t"
	    "cmpi.w	#0x4e75,%%a1@	;# rts				\n\t"
	    "bne	340f		;# chk_end_lp4			\n\t"
	    "lea	%%sp@(3*4+6+4),%%a1				\n\t"
	    "move.w	%%a1@+,%%d0					\n\t"
	    "btst	#13,%%d0					\n\t"
	    "bne	330f		;# chk_end_lp3			\n\t"
	    "move.l	%%usp,%%a1					\n\t"
	    "330: ;# chk_end_lp3					\n\t"
	    "move.l	%%a1@(4*15),%%d0				\n\t"
	    "bra	360f		;# chk_end_lp6			\n\t"
	    "340: ;# chk_end_lp4					\n\t"
	    "cmpi.w	#0x4ef9,%%a1@	;# jmp				\n\t"
	    "bne	350f		;# chk_end_lp5			\n\t"
	    "move.l	%%a1@(2),%%d0					\n\t"
	    "bra	360f		;# chk_end_lp6			\n\t"
	    "350: ;# chk_end_lp5					\n\t"
	    "lea	%%a1@(2),%%a1					\n\t"
	    "bra	310b		;# chk_end_lp1			\n\t"
	    "360: ;# chk_end_lp6					\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(PROG_RESUME) "),%%a0	\n\t"
	    "move.l	%%d0,%%a0@	;# resume address		\n\t"
	    "bra	8888f		;# tvd_stop			\n\t"
	    "								\n\t"
	    "400: ;# chk_end_internal - Intercept end of internal prot	\n\t"
	    "cmpi.w	#0x2f48,%%d0					\n\t"
	    "bne	9999f		;# tvd_cont			\n\t"
	    "cmpi.w	#2,%%a0@(2)	;# move.l a0,2(a7)		\n\t"
	    "bne	9999f		;# tvd_cont			\n\t"
	    "lea	tvd_params_robn88,%%a0				\n\t"
	    "tst.l	%%a0@(" ASM_IDX_ROBN88(SERIAL_ONLY) ")		\n\t"
	    "beq	9999f		;# tvd_cont			\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN88(FLAGS) "),%%a1		\n\t"
	    "tst.b	%%a1@(" ASM_FLAG_ROBN88(KEY_DISK) ")		\n\t"
	    "beq	9999f		;# tvd_cont			\n\t"
	    "st.b	%%a1@(" ASM_FLAG_ROBN88(SERIAL) ")		\n\t"
	    ";# Fall through						\n\t"
	    "								\n\t"
	    "8888: ;# tvd_stop						\n\t"
	    "lea	tvd_params_robn88,%%a0				\n\t"
	    "move.l	%%a0@(" ASM_IDX_ROBN88(TRAMPOLINE) "),%%sp@(14)	\n\t"
	    "and.w	#0x3fff,%%sp@(12)				\n\t"
	    ";# Fall through						\n\t"
	    "								\n\t"
	    "9999: ;# tvd_cont						\n\t"
	    "movem.l	%%sp@+,%%d0/%%a0-%%a1				\n\t"
	    "rte							\n\t"
	    "nop							\n\t"
	    "nop							\n\t"
	    "nop							\n\t"
	    "dc.l	0xfc0000					\n\t"
	    "500: #; vecs_fake						\n\t"
	    "dc.l	0xfc0000					\n\t"
	    "nop							\n\t"
	    "2:								\n\t"
	    : "=a" (entry)
	    :
	    : "cc", "memory"
	);

    /*
     * Returns the address of the code snippet which installs dec0de's
     * illegal handler.
     */
    return entry;
}

/*
 * Dynamic analysis providing both the static and dynamic information
 * about the protection.
 *
 * The dynamic analysis relies on the above TVD routine.
 */
static int decode_native_robn88 (prog_t* prog, info_robn_t* info)
{
    prot_t*        prot = prog->prot;
    unsigned char* illtrig;
    unsigned char* illvec_cont;
    unsigned char* tvd_pinstr_off;
    unsigned char* tvd_pinstr;
    void*          disk_buf;
    uint32_t       entry;
    unsigned int   i;

    ASSERT((info->decode_off >= 0) || (info->serial_off >= 0));

    /*
     * Get the address of the protection code prolog which will be patched
     * for the installation of dec0de's illegal handler.
     */
    illtrig = prog->text + prot->patterns[2]->eoffset + (SIZE_16*2);
    ASSERT(read32(illtrig + SIZE_16) == 0x10);

    /*
     * Get the address where to jump on exit from dec0de's illegal handler
     * in order to complete the handling of the illegal exception.
     */
    illvec_cont  = prog->text + prot->patterns[3]->eoffset;
    illvec_cont += (4 + 4 + 6);
    ASSERT(read16(illvec_cont) == 0x41fa);

    /*
     * Get the address used by the protection code to save the information
     * about the currently traced instruction (address and encrypted opcode).
     */

    tvd_pinstr_off  = prog->text + prot->patterns[4]->eoffset;
    tvd_pinstr_off += (4 + 4 + 2);
    ASSERT(read16(tvd_pinstr_off - SIZE_16) == 0x43fa);

    tvd_pinstr = tvd_pinstr_off + (ssize_t) (int16_t) read16(tvd_pinstr_off);

    /* Allocate a buffer for the key disk reading */
    disk_buf = malloc(8192);
    if (!disk_buf) {
	LOG_ERROR("Cannot allocate a disk buffer of 8192 bytes\n");
	return 1;
    }

    /*
     * Get the address of the code snippet which installs dec0de's
     * illegal handler.
     */
    entry = tvd_robn88(illvec_cont,
		       tvd_pinstr,
		       PROT_FLAGS_ROBN88(prot) & PROT_TVD_MASK_ROBN88,
		       disk_buf,
		       (info->serial_off >= 0));

    /*
     * Patch the protection code prolog so that the above code snippet
     * will be called during the execution of the protection code.
     */
    write16(0x4eb9, illtrig);
    write32(entry,  illtrig + SIZE_16);

    serial_robn88      = 0;
    serial_dst_robn88  = NULL;
    magic_robn88       = 0;
    magic_dst_robn88   = NULL;
    prog_resume_robn88 = NULL;
    prog_start_robn88  = NULL;

    for (i = 0; i < FLAG_NR_ROBN88; i++) {
	flags_robn88[i] = 0;
    }

    /*
     * Registers values at protection startup time.
     * The address of the key disk buffer is passed in a0.
     */
    memset(registers, 0, sizeof(uint32_t) * 16);
    registers[IDX_A0_REG] = (uint32_t) (size_t) disk_buf;

    /* Ask for the original disk to be inserted */
    if (wait_prot(1)) {
	free(disk_buf);
	return 1;
    }

    /*
     * Execute the protection code.
     *
     * As a consequence of the patch applied to the protection code prolog
     * (described above), dec0de's illegal and trace handlers will replace
     * those of the protection.
     */
    run_prot(prog->text, (void*) TRAMPOLINE_ADDR_ROBN88, NULL,
	     (PROT_FLAGS_ROBN88(prot) & PROT_FORCE_SUP_ROBN88));

    free(disk_buf);

    end_wait_prot();

    /*
     * If an invalid serial is detected, the execution of the protection
     * is aborted and prog_start_robn88 remains NULL.
     */
    if (prog_start_robn88) {
	ASSERT(!flags_robn88[FLAG_SERIAL_ROBN88] || serial_robn88);
	/* Start of the wrapped program if any */
	prog->doffset = (size_t) (prog_start_robn88 - prog->text);
	if (prog_resume_robn88) {
	    /* Wrapped program is a binary type */
	    prog->binary = 1;
	    prog->dsize  = (size_t) (registers[IDX_A2_REG] -
				     registers[IDX_A1_REG]);
	}
    }

    /*
     * Fill the info_robn_t structure with the information obtained
     * from the native execution of the protection.
     *
     * The offsets fields of the info_robn_t structure are supposed to give
     * the locations of the different parts/features of the protection
     * (in bytes, relative to the beginning of the file).
     * These offsets are actually used by the dump routine (print_info_robn)
     * to only describe the behavior of the protection (if a feature is
     * present or not). The actual offsets of the features are not dumped.
     * Therefore, when a protection feature is found/localized by the TVD
     * routine, the corresponding offset in the info_robn_t structure is
     * set to zero on purpose (to indicate the feature is present).
     * Otherwise the offset is left unchanged (initialized to -1 to indicate
     * the feature is missing).
     */

    /* Start of the wrapped program if any */
    if (prog->doffset) {
	info->prog_off            = (ssize_t) prog->doffset;
    }

    /* Wrapped program type (GEMDOS/binary) */
    if (prog->doffset && !prog->binary) {
	info->reloc_off           = 0;
    }

    /* Vectors checked by the protection? */
    if (flags_robn88[FLAG_VECS_CHECK_ROBN88]) {
	info->vecs_off            = 0;
    }

    /* Key disk accessed by the protection? */
    if (flags_robn88[FLAG_KEY_DISK_ROBN88]) {
	info->keydisk_off         = 0;
	info->keydisk_hit         = 1;
    }

    /* Serial usage */
    if (flags_robn88[FLAG_SERIAL_ROBN88]) {
	info->serial_off          = 0;
	if (info->decode_off >= 0) {
	    /* Keydisk is used by a wrapper type protection */
	    info->serial_usage    = SERIAL_USAGE_DECODE_PROG_ROBN;
	}
	/* Serial is saved into memory */
	info->serial_usage       |= SERIAL_USAGE_SAVE_MEM_ROBN;
	info->serial              = serial_robn88;
	if (serial_dst_robn88) {
	    info->serial_dst_addr = serial_dst_robn88;
	}
	info->serial_valid        = 1;
    }

    /* Extra magic value computed from the serial key? */
    if (flags_robn88[FLAG_MAGIC_ROBN88]) {
	info->serial_usage       |= SERIAL_USAGE_MAGIC_MEM_ROBN;
	info->magic               = magic_robn88;
	/* Destination address where the magic value is saved to */
	if (magic_dst_robn88) {
	    info->magic_dst_addr  = magic_dst_robn88;
	}
	info->magic_valid         = 1;
    }

    /* Execution context of the program (binary type only) */
    if (prog->dsize) {
	info->dst_addr            = (void*) registers[IDX_A1_REG];
	if (info->dst_addr == prog->text) {
	    info->dst_addr        = NULL;
	}
	info->entry_off           = ((size_t) prog_resume_robn88 -
				     (size_t) registers[IDX_A1_REG]);
	info->prog_len            = prog->dsize;
	info->zeroes_len          = (size_t) registers[IDX_A3_REG];
	info->dstexec_valid       = 1;
    }

    info->prot_run = 1;

    if (check_size_robn(prog, info)) {
	return 1;
    }

    /* Dump the collected information */
    return print_info_robn(info, prog_start_robn88);
}

/*****************************************************************************
 *
 * Copylock Protection System series 2 (1989) by Rob Northen
 * Atari ST specific code
 *
 * Dynamic (run-time) analysis of the protection.
 *
 * A rich static analysis can be performed for both types (wrapper and
 * internal) of the series 2.
 * Therefore, the dynamic analysis is only needed for the following:
 * - to determine the value of the serial key
 * - to decrypt the wrapped program if any
 * - to determine the execution context of the wrapped program (if binary type)
 *
 * The run-time analysis works as follows: the encryption scheme of the
 * series 2 enables to modify the encrypted protection code in order to
 * replace original (decoded) instructions with new ones.
 * Therefore, it is possible to patch the encrypted protection code in some
 * special places in order to:
 * - modify the behavior of the protection
 * - temporarily interrupt the execution of the protection and call
 *   a subroutine aimed at performing some additional operations
 * - terminate the execution of the protection prematurely
 * Unlike the series 1, the series 2 does not require to replace the original
 * TVD routine and to analyze each decoded instruction on-the-fly.
 *
 *****************************************************************************/

#define TRAMPOLINE_ADDR_ROBN89		0x200
#define SERIAL_HANDLER_ADDR_ROBN89	0x2a0

#define IDX_SERIAL_HDL_ROBN89		0
#define IDX_SERIAL_INSTRS_ROBN89	1
#define IDX_SERIAL_PTR_ROBN89		2
#define IDX_SERIAL_ONLY_ROBN89		3
#define IDX_SERIAL_TRAMP_ROBN89		4
#define IDX_MAX_ROBN89			5

#define ASM_IDX_ROBN89(_n)		__ASM_STR(4 * IDX_##_n##_ROBN89)

#define SET_PARAM_ROBN89(_n, _v)	\
    params.val[IDX_##_n##_ROBN89] = (uint32_t) (_v)

static uint32_t serial_instrs_robn89[4];
static uint32_t serial_robn89;
static uint32_t serial_only_robn89;

/*
 * Prepare the routine which will be called during the execution of the
 * protection in order to catch the serial key value.
 *
 * The static analysis localizes, in the protection code, the instruction
 * of which the register will contain the serial key value at run-time.
 *
 * Dec0de patches the protection code at this location so that the following
 * routine will be called to catch the serial key value.
 * Once the serial key value is catched and saved, the routine restores
 * the original protection code and resumes its execution.
 *
 * When an invalid serial key is detected (value is null), the routine
 * immediately terminates the execution of the protection and jumps to the
 * trampoline routine in order to resume the normal execution of dec0de.
 *
 * The execution of the protection is also terminated right after the
 * catching of the serial key value if the protection is an internal type
 * (serial_only flag is set).
 */
static int32_t setup_serial_handler_robn89 (void)
{
    static struct {
	uint32_t val[IDX_MAX_ROBN89];
    } params asm("serial_hdl_params_robn89") USED;

    SET_PARAM_ROBN89(SERIAL_HDL,    SERIAL_HANDLER_ADDR_ROBN89);
    SET_PARAM_ROBN89(SERIAL_INSTRS, serial_instrs_robn89);
    SET_PARAM_ROBN89(SERIAL_PTR,    &serial_robn89);
    SET_PARAM_ROBN89(SERIAL_ONLY,   serial_only_robn89);
    SET_PARAM_ROBN89(SERIAL_TRAMP,  TRAMPOLINE_ADDR_ROBN89);

    __asm__ __volatile__
	(
	    ";# installs the serial handler routine at the desired	\n\t"
	    ";# location in memory, and returns.			\n\t"
	    "movem.l	%%d2-%%d7/%%a2-%%a5,%%sp@-			\n\t"
	    "								\n\t"
	    "lea	serial_hdl_params_robn89,%%a2			\n\t"
	    "								\n\t"
	    "lea	2f(pc),%%a0					\n\t"
	    "movea.l	%%a2@(" ASM_IDX_ROBN89(SERIAL_HDL) "),%%a1	\n\t"
	    "moveq.l	#(7f-2f+3)/4-1,%%d0				\n\t"
	    "1: move.l	%%a0@+,%%a1@+					\n\t"
	    "dbf	%%d0,1b						\n\t"
	    "								\n\t"
	    "bra	7f						\n\t"
	    "								\n\t"
	    "2:								\n\t"
	    ";# serial handler routine:					\n\t"
	    ";# catches the serial key value (in d0) and saves it,	\n\t"
	    ";# then restores the original protection code and resumes	\n\t"
	    ";# its execution.						\n\t"
	    "movem.l	%%a0-%%a1/%%d0-%%d1,%%sp@-			\n\t"
	    "								\n\t"
	    "lea	serial_hdl_params_robn89,%%a0			\n\t"
	    "								\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN89(SERIAL_PTR) "),%%a1	\n\t"
	    "move.l	%%d0,%%a1@		;# save serial		\n\t"
	    "tst.l	%%a0@(" ASM_IDX_ROBN89(SERIAL_ONLY) ")		\n\t"
	    "bne.s	3f						\n\t"
	    "tst.l	%%d0			;# invalid serial?	\n\t"
	    "bne.s	4f						\n\t"
	    "3:								\n\t"
	    ";# terminates the execution of the protection		\n\t"
	    "move.l	%%a0@(" ASM_IDX_ROBN89(SERIAL_TRAMP) "),%%sp@(18)\n\t"
	    "and.w	#0x3fff,%%sp@(16)				\n\t"
	    "bra	6f						\n\t"
	    "								\n\t"
	    "4:								\n\t"
	    ";# resumes the execution of the original protection code	\n\t"
	    "movea.l	%%a0@(" ASM_IDX_ROBN89(SERIAL_INSTRS) "),%%a0	\n\t"
	    "movea.l	%%sp@(2+(4*4)),%%a1				\n\t"
	    "subq.l	#8,%%a1						\n\t"
	    "move.l	%%a1,%%sp@(2+(4*4))				\n\t"
	    "move.l	%%a1,0xc.w					\n\t"
	    "moveq.l	#3,%%d0						\n\t"
	    "5: move.l	%%a0@+,%%a1@+					\n\t"
	    "dbf	%%d0,5b						\n\t"
	    "								\n\t"
	    "6:								\n\t"
	    "movem.l	%%sp@+,%%a0-%%a1/%%d0-%%d1			\n\t"
	    "								\n\t"
	    "rte							\n\t"
	    "								\n\t"
	    "7:								\n\t"
	    "movem.l	%%sp@+,%%d2-%%d7/%%a2-%%a5			\n\t"
	    :
	    :
	    : "cc", "%%d0", "%%d1", "%%a0", "%%a1", "memory"
	);

    return 0;
}

/*
 * Patch the encrypted protection code at a given location in order to
 * replace the original decoded instruction at this location with a new
 * 32-bit instruction.
 *
 * This helper routine encrypts a 32-bit instruction according to the
 * second TVD method and patches the encrypted protection code with it.
 * The 32-bit magic value which is used for the encryption (and passed
 * as parameter) is obtained during the static analysis.
 *
 * See static analysis for details about the two TVD methods used by the
 * series 2.
 */
static void encode_instr32_robn89 (unsigned char* buf,
				   uint32_t       magic32,
				   uint32_t       instr32)
{
    uint32_t key32;

    key32    = read32(buf - SIZE_32);
    key32   += magic32;

    instr32 ^= key32;
    write32(instr32, buf);
}

/*
 * Dynamic analysis of the protection.
 *
 * The encrypted protection code is patched at different places in order
 * to replace the original decoded instructions at these locations
 * with new ones.
 * The purpose is to modify the behavior of the original protection code
 * in order to obtain the desired information (serial key value,
 * decrypted program...).
 */
static int decode_native_robn89 (prog_t* prog, info_robn_t* info)
{
    unsigned char* buf;
    uint32_t       key32;
    uint16_t       w16;

    ASSERT(((info->decode_off >= 0) || (info->serial_off >= 0)) &&
	   (info->pushtramp_off >= 0));

    serial_robn89      = 0;
    serial_only_robn89 = 0;

    /*
     * If vectors are checked, deactivates this check: modifies the original
     * subroutine that checks a given vector. A 'rts' is written as the
     * first instruction of this routine, so the routine will be ineffective.
     * (see vecs_pattern1_robn89 for details about the code pattern of the
     * vectors checking subroutine).
     */
    if (info->vecs_off >= 0) {
	buf = prog->text + info->vecs_off;

	/* rts ; nop */
	encode_instr32_robn89(buf + SIZE_32, info->magic32, 0x4e754e71);
    }

    /*
     * If a serial key is used, patches the protection code, so a
     * subroutine aimed at saving the serial key value will be called
     * (see setup_serial_handler_robn89 for details).
     */
    if (info->serial_off >= 0) {
	buf = prog->text + info->serial_off;

	/*
	 * Save the encrypted code snippet before patching it.
	 * It will be restored after the serial key value has been
	 * saved and prior to resuming the execution of the protection.
	 * When this code snippet will be reached, the two first instructions
	 * (which are the next to be executed) should be decoded by
	 * the second TVD routine.
	 * Save that code snippet in such a state, so it can be restored
	 * and its execution can be resumed properly.
	 */

	key32 = get_decode_key32_robn89(buf, info->magic32);

	serial_instrs_robn89[0] = read32(buf + (SIZE_32*0)) ^ key32;
	serial_instrs_robn89[1] = read32(buf + (SIZE_32*1)) ^ key32;
	serial_instrs_robn89[2] = read32(buf + (SIZE_32*2));
	serial_instrs_robn89[3] = read32(buf + (SIZE_32*3));

	/*
	 * Encode and install the new instructions.
	 * These instructions will trigger an illegal exception whose
	 * handler is the routine aimed at saving the serial key value.
	 * That routine is installed (copied) into memory at a 16-bit address.
	 * Indeed, an instruction that loads a 16-bit address can be
	 * encoded in a 32-bit word.
	 */

	/* lea SERIAL_HANDLER_ADDR_ROBN89.w,a6 */
	encode_instr32_robn89(buf + 0*SIZE_32, info->magic32,
			      0x4df80000 + SERIAL_HANDLER_ADDR_ROBN89);
	/* move.l a6,$10.w (illegal vector) */
	encode_instr32_robn89(buf + 1*SIZE_32, info->magic32, 0x21ce0010);
	/* illegal ; nop */
	encode_instr32_robn89(buf + 2*SIZE_32, info->magic32, 0x4afc4e71);

	if (info->decode_off < 0) {
	    serial_only_robn89 = 1;
	}

	/*
	 * Install the routine aimed at saving the serial key value
	 * at the expected location in memory (at a 16-bit address).
	 */
	(void) supexec(setup_serial_handler_robn89);
    }

    if (info->reloc_off >= 0) {
	/*
	 * If the wrapped program is a GEMDOS program, patches the
	 * protection code so the execution of the protection will be
	 * terminated right after the program has been decrypted (before
         * it is relocated).
	 */

	buf = prog->text + info->reloc_off;

	/* lea TRAMPOLINE_ADDR_ROBN89.w,a6 */
	encode_instr32_robn89(buf + 0*SIZE_32, info->magic32,
			      0x4df80000 + TRAMPOLINE_ADDR_ROBN89);
	/* move.l a6,$10.w (illegal vector) */
	encode_instr32_robn89(buf + 1*SIZE_32, info->magic32, 0x21ce0010);
	/* illegal ; nop */
	encode_instr32_robn89(buf + 2*SIZE_32, info->magic32, 0x4afc4e71);

    } else if (info->decode_off >= 0) {
	/*
	 * Otherwise, patches the trampoline of the protection code,
	 * so the protection will be terminated right before the binary
	 * program is installed to its final location.
	 * The registers saved on exit from the protection provide the
	 * execution context of the binary program (destination address,
	 * program size, zeroes length...).
	 */

	buf = prog->text + info->pushtramp_off;

	/*
	 * Caution: the protection code which is modified here is encrypted
	 * with the first TVD method (see static analysis for details).
	 *
	 * Modify protection code (push trampoline into the stack) so that
	 * it does not affect 'sr' when the "move.l #$value,-(a7)" instruction
	 * is executed. 'sr' is indeed used in the TVD handler for decoding.
	 *
	 * Here, 'eor.l d6,4(a6)' will be replaced with
	 * 'jmp TRAMPOLINE_ADDR_ROBN89.w'.
	 */

	/* Patch 'move.l #$bd96bdae,-(a7)' */
	w16  = read16(buf + SIZE_16*2);
	/* eor.l d6,4(a6) (1st part) */
	w16 ^= (uint16_t) 0xbdae;
	/* jmp TRAMPOLINE_ADDR_ROBN89.w (1st part) */
	w16 ^= (uint16_t) 0x4ef8;
	write16(w16, buf + SIZE_16*2);

	/* Patch 'move.l #$0004487a,-(a7)' */
	w16  = read16(buf - SIZE_16*2);
	/* eor.l d6,4(a6) (2nd part) */
	w16 ^= (uint16_t) 0x0004;
	/* jmp TRAMPOLINE_ADDR_ROBN89.w (2nd part) */
	w16 ^= (uint16_t) TRAMPOLINE_ADDR_ROBN89;
	write16(w16, buf - SIZE_16*2);
    }

    /*
     * Registers values at protection startup time.
     */
    memset(registers, 0, sizeof(uint32_t) * 16);

    /* Ask for the original disk to be inserted */
    if (wait_prot(info->keydisk_off >= 0)) {
	return 1;
    }

    /*
     * Execute the protection code.
     *
     * The behavior of the protection code will be modified according
     * to the patches applied above.
     */
    run_prot(prog->text, (void*) TRAMPOLINE_ADDR_ROBN89, NULL,
	     (PROT_FLAGS_ROBN89(prog->prot) & PROT_FORCE_SUP_ROBN89));

    end_wait_prot();

    /* Start of the wrapped program if any */
    if (info->decode_off >= 0) {
	prog->doffset = (size_t) info->prog_off;
	prog->binary  = (unsigned int) (info->reloc_off < 0);
    }

    /* Size of the binary program if any */
    if (prog->binary && ((info->serial_off < 0) || serial_robn89)) {
	prog->dsize = (size_t) registers[IDX_A2_REG];
    }

    /*
     * Fill the info_robn_t structure with the information obtained
     * from the native execution of the protection.
     * Only the dynamic information is filled here as the static information
     * has already been provided during the static analysis.
     */

    /* Key disk usage and serial key value */
    if (info->serial_off >= 0) {
	info->keydisk_hit     = 1;
	info->serial          = serial_robn89;
	info->serial_valid    = 1;
    }

    /* Execution context of the program (binary type only) */
    if (prog->dsize) {
	info->dst_addr        = (void*) registers[IDX_A1_REG];
	if (info->dst_addr == prog->text) {
	    info->dst_addr    = NULL;
	}
	info->entry_off       = (size_t) (registers[IDX_A4_REG] -
					  registers[IDX_A1_REG]);
	info->prog_len        = prog->dsize;
	info->zeroes_len      = (size_t) registers[IDX_A3_REG];
	info->dstexec_valid   = 1;
    }

    info->prot_run = 1;

    buf = (info->decode_off >= 0) ? prog->text + prog->doffset : NULL;

    /* Dump the collected information */
    return print_info_robn(info, buf);
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

    case 'p':
	if (argc == 3) {
	    src = argv[2];
	    print_prot(src);
	    return 0;
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

    case 'c':
	if (argc == 2) {
	    credits();
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

    return decode(src, dst);
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
