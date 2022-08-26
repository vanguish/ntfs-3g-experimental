/*
 * dedup.c - NTFS-3G deduplication plugin
 *
 * Copyright (C) 2016-2018 Jean-Pierre Andre
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 *			History
 *
 *		Version 1.0.0, Aug 2016
 *	- first version, for a Windows 10 deduplicated partition
 *
 *		Version 1.1.0, Nov 2016
 *	- added support for a shorter reparse data format
 *
 *		Version 1.1.1, Jan 2017
 *	- added a search for a stream name matching the expected pattern
 *
 *		Version 1.2.0, Feb 2017
 *	- added an indexed search for a stream record when needed
 *
 *		Version 1.2.1, Feb 2017
 *	- fixed a bug in indexed search
 *	- based indexed search on assuming not four zeroes in stream name
 *
 *		Version 1.2.2, Feb 2017
 *	- fixed a bug in the beginning of index
 *	- protected against bad index
 *
 *		Version 1.2.3, Apr 2017
 *	- always tried direct access before indexed search
 *
 *		Version 1.2.4, Apr 2017
 *	- taken the number of index entries from "Rrtl" instead of "Cthr"
 *
 *		Version 1.2.5, Aug 2018
 *	- in dedup_read_short(), loop until requested size is reached
 */

#define DEDUP_VERSION "1.2.5"

#include "config.h"

/*
 * Although fuse.h is only needed for 'struct fuse_file_info', we still need to
 * request a specific FUSE API version.  (It's required on FreeBSD, and it's
 * probably a good idea to request the same version used by NTFS-3G anyway.)
 */
#define FUSE_USE_VERSION 26
#include <fuse.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include <ntfs-3g/inode.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/index.h>
#include <ntfs-3g/unistr.h>
#include <ntfs-3g/volume.h>
#include <ntfs-3g/security.h>
#include <ntfs-3g/plugin.h>
#include <ntfs-3g/misc.h>

#define CKHR_MAGIC const_cpu_to_le32(0x72686b43) /* "Ckhr" */
#define SMAP_MAGIC const_cpu_to_le32(0x70616d53) /* "Smap" */
#define CTHR_MAGIC const_cpu_to_le32(0x72687443) /* "Cthr" */
#define RRTL_MAGIC const_cpu_to_le32(0x6c747252) /* "Rrtl" */

#define MAXMEM 0x20000 /* Max buffer size */
#define MAXSMAP 512 /* Max smap chunk cnt (MAXSMAP*64 + 0x68 < MAXMEM) */
#define MAXPATHSTORE 256 /* The real limit is less than 120 */
#define MAXFILESTORE 32 /* The real limit is 21 */

/* For badly aligned le64 fields */
#define mergele64(p,q) ((((u64)le32_to_cpu(p)) << 32) + le32_to_cpu(q))

struct DEDUP_REPARSE_ENTRY { /* size 0x40 */
	le32 num;		/* Sequence number of ckhr in stream */
	le32 id;
	le32 offset;          /* a4 */
	le32 unknown31[3];
	le32 size_smap;       /* b4 */
	le32 unknown32;
	le32 digest[4];
	le32 part_end_low;       /* cc, le64 badly aligned */
	le32 part_end_high;
	le32 part_begin_low;     /* d4, le64 badly aligned */
	le32 part_begin_high;
} ;

struct DEDUP_REPARSE {
	le32 reparse_tag;		/* Reparse point type (inc. flags). */
	le16 reparse_data_length;	/* Byte size of reparse data. */
	le16 reserved;			/* Align to 8-byte boundary. */
	le16 format;			/* Probably major+minor version */
	le16 length;

	le32 unknown11[16];
	le16 size_data1;       /* 4c */
	le16 offs_data1;
	le32 unknown12;
	le16 size_data2;       /* 54 */
	le16 offs_data2;
	le32 unknown13[9];

	GUID guid;             /* 7c */
	le32 unknown2[4];
		/* Array of DEDUP_REPARSE_ENTRY usually begins here */
	le32 data[1];
} ;

struct DEDUP_REPARSE_SHORT {
	le32 reparse_tag;		/* Reparse point type (inc. flags). */
	le16 reparse_data_length;	/* Byte size of reparse data. */
	le16 reserved;			/* Align to 8-byte boundary. */
	le16 format;			/* Probably major+minor version */
	le16 length;

	le32 unknown11;
	le32 part_end_low;
	le32 part_end_high;
	le32 unknown12[2];
	GUID guid;             /* 20 */
	le32 unknown2[4];
		/* Array of DEDUP_REPARSE_ENTRY usually begins here */
	le32 data[1];
} ;

struct DEDUP_CKHR_DATA {  /* Ckhr in Data, size 88 */
	le32 magic;
	le32 unknown1;
	le32 num;
	le32 payload_size;
	le16 unknown21;
	le16 some_size;		/* 0x28, related to struct size ? */
	le32 unknown22[5];
	char digest[32];
	le32 unknown3[4];
} ;

struct DEDUP_CKHR_STREAM {  /* Ckhr in Stream, size 104 */
	le32 magic;
	le32 unknown1;
	le32 num;
	le32 payload_size;
	le16 unknown21;
	le16 some_size;		/* 0x38, related to struct size ? */
	le32 unknown2[9];
	char digest[16];
	le32 unknown3[8];
} ;

struct DEDUP_SMAP_ENTRY {  /* size 64 */
	le32 num;
	le32 id1;
	le32 offset;
	le32 id2;
	le64 data_end; /* uncompressed end */
	char digest[32];
	le32 data_size; /* compressed size */
	le32 unknown;
} ;

struct DEDUP_SMAP {
	le32 magic;
	le32 unknown1;
	struct DEDUP_SMAP_ENTRY entry[1];
} ;

struct STREAM_INDEX_ENTRY {
	le32 num;
	le32 offset;
} ;


/*
 *		Table for fast computing a crc32
 *
 *	This table can be computed by running :
 *
 *	static const unsigned int polynomial = 0xedb88320;
 *	int i,j;
 *	unsigned int c;
 *
 *	for (i=0; i<256; i++) {
 *		c = i;
 *		for (j=0; j<8; j++)
 *			if (c & 1)
 *				c = polynomial ^ (c >> 1);
 *			else
 *				c = (c >> 1);
 *		printf("0x%lx\n",(long)c);
 *	}
 */

static const u32 crcvals[256] = {
	0x00000000,  0x77073096,  0xee0e612c,  0x990951ba,
	0x076dc419,  0x706af48f,  0xe963a535,  0x9e6495a3,
	0x0edb8832,  0x79dcb8a4,  0xe0d5e91e,  0x97d2d988,
	0x09b64c2b,  0x7eb17cbd,  0xe7b82d07,  0x90bf1d91,
	0x1db71064,  0x6ab020f2,  0xf3b97148,  0x84be41de,
	0x1adad47d,  0x6ddde4eb,  0xf4d4b551,  0x83d385c7,
	0x136c9856,  0x646ba8c0,  0xfd62f97a,  0x8a65c9ec,
	0x14015c4f,  0x63066cd9,  0xfa0f3d63,  0x8d080df5,
	0x3b6e20c8,  0x4c69105e,  0xd56041e4,  0xa2677172,
	0x3c03e4d1,  0x4b04d447,  0xd20d85fd,  0xa50ab56b,
	0x35b5a8fa,  0x42b2986c,  0xdbbbc9d6,  0xacbcf940,
	0x32d86ce3,  0x45df5c75,  0xdcd60dcf,  0xabd13d59,
	0x26d930ac,  0x51de003a,  0xc8d75180,  0xbfd06116,
	0x21b4f4b5,  0x56b3c423,  0xcfba9599,  0xb8bda50f,
	0x2802b89e,  0x5f058808,  0xc60cd9b2,  0xb10be924,
	0x2f6f7c87,  0x58684c11,  0xc1611dab,  0xb6662d3d,
	0x76dc4190,  0x01db7106,  0x98d220bc,  0xefd5102a,
	0x71b18589,  0x06b6b51f,  0x9fbfe4a5,  0xe8b8d433,
	0x7807c9a2,  0x0f00f934,  0x9609a88e,  0xe10e9818,
	0x7f6a0dbb,  0x086d3d2d,  0x91646c97,  0xe6635c01,
	0x6b6b51f4,  0x1c6c6162,  0x856530d8,  0xf262004e,
	0x6c0695ed,  0x1b01a57b,  0x8208f4c1,  0xf50fc457,
	0x65b0d9c6,  0x12b7e950,  0x8bbeb8ea,  0xfcb9887c,
	0x62dd1ddf,  0x15da2d49,  0x8cd37cf3,  0xfbd44c65,
	0x4db26158,  0x3ab551ce,  0xa3bc0074,  0xd4bb30e2,
	0x4adfa541,  0x3dd895d7,  0xa4d1c46d,  0xd3d6f4fb,
	0x4369e96a,  0x346ed9fc,  0xad678846,  0xda60b8d0,
	0x44042d73,  0x33031de5,  0xaa0a4c5f,  0xdd0d7cc9,
	0x5005713c,  0x270241aa,  0xbe0b1010,  0xc90c2086,
	0x5768b525,  0x206f85b3,  0xb966d409,  0xce61e49f,
	0x5edef90e,  0x29d9c998,  0xb0d09822,  0xc7d7a8b4,
	0x59b33d17,  0x2eb40d81,  0xb7bd5c3b,  0xc0ba6cad,
	0xedb88320,  0x9abfb3b6,  0x03b6e20c,  0x74b1d29a,
	0xead54739,  0x9dd277af,  0x04db2615,  0x73dc1683,
	0xe3630b12,  0x94643b84,  0x0d6d6a3e,  0x7a6a5aa8,
	0xe40ecf0b,  0x9309ff9d,  0x0a00ae27,  0x7d079eb1,
	0xf00f9344,  0x8708a3d2,  0x1e01f268,  0x6906c2fe,
	0xf762575d,  0x806567cb,  0x196c3671,  0x6e6b06e7,
	0xfed41b76,  0x89d32be0,  0x10da7a5a,  0x67dd4acc,
	0xf9b9df6f,  0x8ebeeff9,  0x17b7be43,  0x60b08ed5,
	0xd6d6a3e8,  0xa1d1937e,  0x38d8c2c4,  0x4fdff252,
	0xd1bb67f1,  0xa6bc5767,  0x3fb506dd,  0x48b2364b,
	0xd80d2bda,  0xaf0a1b4c,  0x36034af6,  0x41047a60,
	0xdf60efc3,  0xa867df55,  0x316e8eef,  0x4669be79,
	0xcb61b38c,  0xbc66831a,  0x256fd2a0,  0x5268e236,
	0xcc0c7795,  0xbb0b4703,  0x220216b9,  0x5505262f,
	0xc5ba3bbe,  0xb2bd0b28,  0x2bb45a92,  0x5cb36a04,
	0xc2d7ffa7,  0xb5d0cf31,  0x2cd99e8b,  0x5bdeae1d,
	0x9b64c2b0,  0xec63f226,  0x756aa39c,  0x026d930a,
	0x9c0906a9,  0xeb0e363f,  0x72076785,  0x05005713,
	0x95bf4a82,  0xe2b87a14,  0x7bb12bae,  0x0cb61b38,
	0x92d28e9b,  0xe5d5be0d,  0x7cdcefb7,  0x0bdbdf21,
	0x86d3d2d4,  0xf1d4e242,  0x68ddb3f8,  0x1fda836e,
	0x81be16cd,  0xf6b9265b,  0x6fb077e1,  0x18b74777,
	0x88085ae6,  0xff0f6a70,  0x66063bca,  0x11010b5c,
	0x8f659eff,  0xf862ae69,  0x616bffd3,  0x166ccf45,
	0xa00ae278,  0xd70dd2ee,  0x4e048354,  0x3903b3c2,
	0xa7672661,  0xd06016f7,  0x4969474d,  0x3e6e77db,
	0xaed16a4a,  0xd9d65adc,  0x40df0b66,  0x37d83bf0,
	0xa9bcae53,  0xdebb9ec5,  0x47b2cf7f,  0x30b5ffe9,
	0xbdbdf21c,  0xcabac28a,  0x53b39330,  0x24b4a3a6,
	0xbad03605,  0xcdd70693,  0x54de5729,  0x23d967bf,
	0xb3667a2e,  0xc4614ab8,  0x5d681b02,  0x2a6f2b94,
	0xb40bbe37,  0xc30c8ea1,  0x5a05df1b,  0x2d02ef8d
} ;

/*
 *	Decompressing big runs potentially requires huge buffers, but
 *	the compressor apparently takes care of never requiring more
 *	than 131K.
 *	For safety, make sure never to allocate more than 131K.
 */

static void *malloc_maxed(size_t size, int line)
{
	void *p;

	if (size > MAXMEM) {
		ntfs_log_error("Allocation %lld bytes"
			" is not allowed at line %d\n",(long long)size,line);
		p = (void*)NULL;
	} else {
		p = ntfs_malloc(size);
	}
	return (p);
}

/*
 *		Compute a crc32
 */

static le32 crc32(const u8 *b, int n)
{
	u32 crc;
	int k;

	crc = -1;
	for (k=0; k<n; k++)
		crc = (crc >> 8) ^ crcvals[(b[k] ^ crc) & 255];
	crc = ~crc;
	return (cpu_to_le32(crc));
}

/*
 *		Fetch a smap when it is not in the initial list.
 *
 *	Owing to the limit set on buffer allocation, we may have to
 *	split big arrays of smaps. This function reuses the buffer
 *	while looking for the needed smap.
 */

static int dedup_fetch_further(ntfs_attr *na_stream, char *buf_stream,
				u32 offset_stream, off_t offset, int smap_cnt)
{
	struct DEDUP_CKHR_STREAM *ckhr_stream;
	struct DEDUP_SMAP *smap_stream;
	struct DEDUP_SMAP_ENTRY *smap_entry;
	int offset_entries;
	int first_smap;
	int more_smaps;
	int r;
	BOOL ok;

	ckhr_stream = (struct DEDUP_CKHR_STREAM*)buf_stream;
	smap_stream = (struct DEDUP_SMAP*)&buf_stream[0x68];
	smap_entry = &smap_stream->entry[MAXSMAP - 1];
	first_smap = 0;
	if (offset >= (off_t)le64_to_cpu(smap_entry->data_end)) {
		do {
			/*
			 * entry[MAXSMAP - 1] is read again as entry[0],
			 * so that the needed entry is not the first one
			 */
			first_smap += MAXSMAP - 1;
			more_smaps = smap_cnt - first_smap;
			if (more_smaps > MAXSMAP)
				more_smaps = MAXSMAP;
			offset_entries = sizeof(struct DEDUP_CKHR_STREAM)
					+ offsetof(struct DEDUP_SMAP, entry);
			r = ntfs_attr_pread(na_stream,
				first_smap*sizeof(struct DEDUP_SMAP_ENTRY)
					+ offset_stream + offset_entries,
				more_smaps*sizeof(struct DEDUP_SMAP_ENTRY),
				buf_stream + offset_entries);
			ok = ((first_smap + more_smaps) >= smap_cnt)
				|| (more_smaps < MAXSMAP)
				|| ((off_t)le64_to_cpu(smap_entry->data_end)
					> offset);
		} while (!ok);
	} else
		ok = TRUE;
	return (ok);
}

/*
 *		Lookup a stream file in Stream directory
 *
 *	The full name of the stream is not known, a part of it is an
 *	hexadecimal number, which is probably incremented when the
 *	stream is updated.
 *	Make a directory search for the expected pattern and use the
 *	first file whose name matches the pattern.
 *
 *	Returns an opened inode and the file name (with null terminator)
 *		or NULL if not found (failure left to be logged by caller)
 */
static ntfs_inode *dedup_lookup_name(ntfs_inode *dirni_stream,
		u32 id, ntfschar *name_stream)
{
	static ntfschar I30[] = {
		const_cpu_to_le16('$'), const_cpu_to_le16('I'),
		const_cpu_to_le16('3'), const_cpu_to_le16('0')
	};
	char streamname[MAXFILESTORE];
	ntfschar *pkey;
	struct {
		FILE_NAME_ATTR nameattr;
		ntfschar morechars[MAXFILESTORE];
	} fullkey;
	ntfs_inode *ni_stream;
	INDEX_ENTRY *entry;
	ntfs_index_context *xctx;
	MFT_REF mref;
	int res;
	int len;

	ni_stream = (ntfs_inode*)NULL;
			/*
			 * Build the search pattern. This is the last name
			 * which collates before a possible name.
			 */
	snprintf(streamname, MAXFILESTORE, "%08lx.00000000.ccc", (long)id);
	pkey = (ntfschar*)NULL;
	len = ntfs_mbstoucs(streamname, &pkey);
	if (len && (len <= MAXFILESTORE) && pkey) {
		memcpy(fullkey.nameattr.file_name, pkey, 2*len);
		fullkey.nameattr.file_name_length = len;
			/* Search for the pattern */
		xctx = ntfs_index_ctx_get(dirni_stream, I30, 4);
		if (xctx) {
			res = ntfs_index_lookup(&fullkey, len, xctx);
			entry = xctx->entry;
			/* If we reached an end of block, get next entry */
			if (res
			    && entry
			    && (entry->ie_flags & INDEX_ENTRY_END)) {
				entry = ntfs_index_next(entry,xctx);
			}
			/*
			 * Loop while we get a valid entry and a file name
			 * whose first 9 chars match, though the length
			 * or the last 4 chars do not match.
			 */
			while (entry
			    && !(entry->ie_flags & INDEX_ENTRY_END)
			    && !memcmp(entry->key.file_name.file_name,
							pkey, 18)
			    && ((entry->key.file_name.file_name_length != len)
				|| memcmp(&entry->key.file_name.file_name[17],
							&pkey[17], 8))) {
				entry = ntfs_index_next(entry,xctx);
			}
			/*
			 * Check whether we got a full match (the length,
			 * the first 9 chars and the last 4 ones must match)
			 */
			if (entry
			    && !(entry->ie_flags & INDEX_ENTRY_END)
			    && (entry->key.file_name.file_name_length == len)
			    && !memcmp(entry->key.file_name.file_name,
							pkey, 18)
			    && !memcmp(&entry->key.file_name.file_name[17],
							&pkey[17], 8)) {
				/* Open the file */
				mref = le64_to_cpu(entry->indexed_file);
				memcpy(name_stream,
					&entry->key.file_name.file_name, 2*len);
				name_stream[len] = const_cpu_to_le16(0);
				ni_stream = ntfs_inode_open(dirni_stream->vol,
						mref);
			}
			ntfs_index_ctx_put(xctx);
		}
		free(pkey);
	}
	return (ni_stream);
}

/*
 *		Examine the index of a Stream file to locate a record
 *
 *	Returns the offset in the file, or 0 if not found
 *
 *	Note : the logic for locating the index is unclear
 */

static u32 search_index_stream(ntfs_attr *na, const le32 num)
{
	enum {
		INDEX_HEAD = 0x3000,	/* to be properly computed */
		INDEX_BASE = 0x3020
	};
	le32 rrtl[8];
	char *buf;
	struct STREAM_INDEX_ENTRY *p;
	const int ENTRY_SIZE = sizeof(struct STREAM_INDEX_ENTRY);
	u32 count;
	u32 knum;
	u32 offset;
	u32 cluster_size;
	u32 cluster_bits;
	u32 current_cluster;
	u32 cluster;
	u32 upper,lower,middle;
	int offs;

	offset = 0; /* default return */
	cluster_size = na->ni->vol->cluster_size;
	cluster_bits = na->ni->vol->cluster_size_bits;
	buf = (char*)NULL;
			/* Read head of first Rrtl record and check its magic */
	if ((ntfs_attr_pread(na, INDEX_HEAD, 32, rrtl) == 32)
	    && (rrtl[0] == RRTL_MAGIC)
	    && ((buf = (char*)malloc_maxed(cluster_size, __LINE__)))) {
		count = le32_to_cpu(rrtl[2]);
		if (count) {
				/* Do a dichotomical index search */
			lower = 0;
			upper = count - 1;
			current_cluster = -1;
			knum = le32_to_cpu(num);
			do {
				middle = (lower + upper) >> 1;
				cluster = (INDEX_BASE + middle*ENTRY_SIZE)
							>> cluster_bits;
				if ((cluster != current_cluster)
				    && (ntfs_attr_pread(na,
						cluster << cluster_bits,
						cluster_size,
						buf) == cluster_size)) {
					current_cluster = cluster;
				}
				offs = INDEX_BASE + middle*ENTRY_SIZE
					- (cluster << cluster_bits);
				p = (struct STREAM_INDEX_ENTRY*)&buf[offs];
				if (le32_to_cpu(p->num) < knum)
					lower = middle + 1;
				else {
					if (le32_to_cpu(p->num) == knum)
						upper = middle;
					else
						upper = middle - 1;
				}
			} while (((lower < upper) || (middle != upper))
					&& (upper < count));
			if (p && (p->num == num)) {
				offset = le32_to_cpu(p->offset);
			}
		 } else
			ntfs_log_error("No record available\n");
		free(buf);
	} else
		ntfs_log_error("Bad Cthr magic\n");
	return (offset);
}

/*
 *		Fetch the ckhr and smap which describe the needed chunk.
 *
 *	First try direct access to offset recorded in the reparse entry.
 *	If it fails, try indexed search.
 *	Apparently when a file is created, its reparse entry points at
 *	the correct offset and the offset is not recorded in the index.
 *	When the file is updated, a new index entry is inserted, but
 *	the reparse entry is not, so an index search is required.
 *
 *	Returns TRUE is the smap is found.
 */
static BOOL dedup_fetch_ckhr(ntfs_inode *ni_stream,
			const struct DEDUP_REPARSE_ENTRY *reparse_entry,
			char *buf_stream, u32 size_stream,
			off_t offset)
{
	ntfs_attr *na_stream;
	u32 offset_stream;
	struct DEDUP_CKHR_STREAM *ckhr_stream;
	struct DEDUP_SMAP *smap_stream;
	int smap_cnt;
	int r;
	BOOL ok;

	na_stream = ntfs_attr_open(ni_stream, AT_DATA, (ntfschar*)NULL, 0);
	if (na_stream) {
		ok = FALSE;
		ckhr_stream = (struct DEDUP_CKHR_STREAM*)buf_stream;
		smap_stream = (struct DEDUP_SMAP*)&buf_stream[0x68];
		offset_stream = le32_to_cpu(reparse_entry->offset);
		r = ntfs_attr_pread(na_stream, offset_stream,
						size_stream, buf_stream);
		if ((r == (int)size_stream)
		    && (ckhr_stream->magic == CKHR_MAGIC)
		    && (ckhr_stream->payload_size == reparse_entry->size_smap)
		    && !memcmp(ckhr_stream->digest, reparse_entry->digest,16)
		    && (smap_stream->magic == SMAP_MAGIC))
			ok = TRUE;
		else {
			offset_stream = search_index_stream(na_stream,
						reparse_entry->num);
			r = ntfs_attr_pread(na_stream,
						offset_stream,
						size_stream, buf_stream);
			if ((r == (int)size_stream)
			    && (ckhr_stream->magic == CKHR_MAGIC)
			    && (ckhr_stream->payload_size
					== reparse_entry->size_smap)
			    && !memcmp(ckhr_stream->digest,
					reparse_entry->digest,16)
			    && (smap_stream->magic == SMAP_MAGIC)) {
				ok = TRUE;
			}
		}
		if (ok) {
			smap_cnt = le32_to_cpu(reparse_entry->size_smap)
				/sizeof(struct DEDUP_SMAP_ENTRY);
			if (smap_cnt > MAXSMAP) {
				ok = dedup_fetch_further(na_stream, buf_stream,
							offset_stream,
							offset, smap_cnt);
			}
		} else {
			ntfs_log_error("Bad stream"
				" for offset 0x%llx"
				" in Stream %lld\n",
				(long long)offset,
				(long long)ni_stream->mft_no);
		}
		ntfs_attr_close(na_stream);
	}
	return (ok);
}


/*
 *		Fetch a Stream and the smap which describes the needed chunk.
 *
 *	Returns a buffer containing the Stream header (Ckhr) and a set of
 *	smaps (at least the one starting at the requested offset).
 *	Returns NULL if the needed smap could not be found.
 */

static char *dedup_fetch_stream(ntfs_volume *vol, const char *guid,
			const struct DEDUP_REPARSE_ENTRY *reparse_entry,
			off_t offset)
{
	char path[MAXPATHSTORE];
	ntfschar name_stream[MAXFILESTORE];
	char *buf_stream;
	ntfs_inode *dirni_stream;
	ntfs_inode *ni_stream;
	u32 size_stream;
	int smap_cnt;
	BOOL ok;

	ok = FALSE;

	if ((le32_to_cpu(reparse_entry->size_smap) - 8)
			% sizeof(struct DEDUP_SMAP_ENTRY)) {
		ntfs_log_error("Not an integral count of Smap entries"
				" (size %ld)\n",
				(long)le32_to_cpu(reparse_entry->size_smap));
	}
	smap_cnt = le32_to_cpu(reparse_entry->size_smap)
			/sizeof(struct DEDUP_SMAP_ENTRY);
	if (smap_cnt <= MAXSMAP) {
		size_stream = le32_to_cpu(reparse_entry->size_smap)
				+ sizeof(struct DEDUP_CKHR_STREAM);
	} else {
		size_stream = MAXSMAP*sizeof(struct DEDUP_SMAP_ENTRY)
				+ sizeof(struct DEDUP_CKHR_STREAM)
				+ offsetof(struct DEDUP_SMAP, entry);
	}
	buf_stream = (char*)malloc_maxed(size_stream,__LINE__);
	if (buf_stream) {
		snprintf(path,MAXPATHSTORE,
				"%s/%s/%s/{%s}.ddp/%s",
				"System Volume Information",
				"Dedup",
				"ChunkStore",
				guid,
				"Stream");
		dirni_stream = ntfs_pathname_to_inode(vol,
				(ntfs_inode*)NULL,path);
		ni_stream = (ntfs_inode*)NULL;
		if (dirni_stream) {
			ni_stream = dedup_lookup_name(dirni_stream,
				le32_to_cpu(reparse_entry->id),
				name_stream);
			ntfs_inode_close(dirni_stream);
		}
		if (ni_stream) {
			ok = dedup_fetch_ckhr(ni_stream, reparse_entry,
				buf_stream, size_stream, offset);
			ntfs_inode_close(ni_stream);
		} else {
			ntfs_log_error("Failed to open a dedup stream"
				" %08lx.*.ccc in directory %s\n",
				(long)le32_to_cpu(reparse_entry->id), path);
		}
	}
	if (!ok) {
		free(buf_stream);
		buf_stream = (char*)NULL;
	}
	return (buf_stream);
}

/*
 *		Read an uncompressed chunk of data
 *
 *	Reading is interrupted at the end of the initial chunk. A new
 *	request has to be made to get the end (which may be located in
 *	a different file or compressed).
 *
 *	Returns a non-negative count of bytes read,
 *		or a negative error code.
 */

static int dedup_pread_data(ntfs_attr *na_data, off_t offset, u32 data_offset,
			const struct DEDUP_SMAP_ENTRY *smap_entry,
			size_t size, char *buf)
{
	struct DEDUP_CKHR_DATA ckhr_data;
	size_t read_size;
	s32 available_size;
	int r;
	int res;

	res = -1;
	r = ntfs_attr_pread(na_data, data_offset,
				sizeof(struct DEDUP_CKHR_DATA), &ckhr_data);
	if ((r == sizeof(struct DEDUP_CKHR_DATA))
	    && (ckhr_data.magic == CKHR_MAGIC)
	    && (ckhr_data.payload_size == smap_entry->data_size)
	    && !memcmp(ckhr_data.digest, smap_entry->digest, 32)) {
		available_size = le32_to_cpu(ckhr_data.payload_size) - offset;
		if (available_size > 0) {
			read_size = available_size;
			if (read_size > size)
				read_size = size;
			r = ntfs_attr_pread(na_data,
				data_offset + sizeof(struct DEDUP_CKHR_DATA)
					+ offset, read_size, buf);
			if (r == (int)read_size)
				res = read_size;
		} else {
			ntfs_log_error("Data at offset 0x%llx"
					" is not within chunk at 0x%llx"
					" in file %lld\n",
					(long long)offset,
					(long long)data_offset,
					(long long)na_data->ni->mft_no);
			res = -EIO;
		}
	} else {
		ntfs_log_error("Bad Ckhr data header at 0x%llx"
				" for offset 0x%llx"
				" in file %lld\n",
				(long long)data_offset,
				(long long)offset,
				(long long)na_data->ni->mft_no);
		res = -EIO;
	}
	return (res);
}

/*
 *		Get an extra repeat count in a compressed file.
 *
 *	When the base repeat count is 7, get a nibble from a source byte.
 *	If this nibble is 0xf, get a full byte from source.
 *      if this is not 0xff the count is 3 + the sum of values collected so far.
 *      otherwise
 *		Get the value of the next couple of source bytes
 *		if this is not zero, the count is 3 + this value
 *		otherwise
 *			Get the value of the next four source bytes
 *			The count is 3 + this value
 *	Danger : the last case may require a huge buffer if the compressor
 *	did not set a safe limit. Windows has apparently set a limit to
 *	131K bytes.
 */

static u32 dedup_get_extra(int extra, BOOL moreextra,
			const char *buf, u32 *xbuf)
{
	u32 extra2;
	u32 cnt;

	if (moreextra) {
						/* add nibble */
		cnt = (extra >> 4) + 10;
	} else {
						/* add nibble */
		cnt = (extra & 15) + 10;
		(*xbuf)++;
	}
	if (cnt == 25) {
						/* add next byte */
		extra2 = buf[*xbuf + 2] & 255;
		cnt += extra2;
		if (extra2 == 255) {
						/* replace by next pair */
			extra2 = (buf[*xbuf + 3] & 255)
				+ ((buf[*xbuf + 4] & 255) << 8);
			if (extra2) {
				cnt += extra2 - 277;
				(*xbuf) += 2;
			} else {
						/* replace by next quad */
				extra2 = ((((((buf[*xbuf + 8] & 255L) << 8)
					+ (buf[*xbuf + 7] & 255)) << 8)
					+ (buf[*xbuf + 6] & 255)) << 8)
					+ (buf[*xbuf + 5] & 255);
				cnt += extra2 - 277;
				(*xbuf) += 6;
			}
		}
		(*xbuf)++;
	}
	return (cnt);
}

/*
 *		Decompress a buffer.
 *
 *	Must always decompress from the beginning of a chunk, and store
 *	the uncompressed part before what is requested in order to copy
 *	repeated sequences.
 *
 *	Both compressed buffer and uncompressed buffer are limited to
 *	131K.
 *
 *	Returns the non-negative count of decompressed bytes,
 *		or a negative error code.
 */

static int dedup_decompress(char *target, u32 target_size, u32 skip_size,
		const char *buf, u32 buf_size, char *buf_decomp)
{
	u32 pattern;
	s32 credit;
	u32 xbuf;
	u32 xtgt;
	u32 xseq;
	u32 pos;
	u32 cnt;
	u32 mix;
	u32 space;
	int extra;
	BOOL moreextra;
	BOOL err;

	xbuf = 0;
	xtgt = 0;
	pattern = 0;
	credit = -4;
	moreextra = FALSE;
	err = FALSE;
	do {
		if (credit < 0) {
			pattern += (buf[xbuf] & 255L) << ((credit + 4) << 3);
			if (!++credit)
				credit = 32;
		} else
			if ((1L << --credit) & pattern) {
				if (!credit) {
					credit = -4;
					pattern = 0;
				}
				mix = ((buf[xbuf + 1] & 255L) << 8)
						+ (buf[xbuf] & 255);
				cnt = (mix & 7) + 3;
				pos = (mix >> 3) + 1;
				if (cnt == 10) {
					if (!moreextra)
						extra = buf[xbuf + 2] & 255;
					cnt = dedup_get_extra(extra,
						moreextra, buf, &xbuf);
					moreextra = !moreextra;
				}
				if (pos > xtgt) {
					ntfs_log_error("Invalid reference,"
						" pos 0x%x xtgt 0x%x\n",
						(int)pos,(int)xtgt);
					err = TRUE;
				} else {
			 /* truncate sequence to fit into the target buffer */
					space = target_size + skip_size - xtgt;
					if (cnt > space)
						cnt = space;
					for (xseq=0; xseq<cnt; xseq++)
						buf_decomp[xtgt + xseq]
							= buf_decomp[xtgt
								- pos + xseq];
					xtgt += cnt;
				}
				xbuf++;
			} else {
				if (!credit) {
					credit = -4;
					pattern = 0;
				}
				buf_decomp[xtgt++] = buf[xbuf];
			}
		xbuf++;
	} while ((xbuf < buf_size)
	    && (xtgt < (target_size + skip_size))
	    && !err);
	if (xtgt > skip_size)
		memcpy(target, &buf_decomp[skip_size], xtgt - skip_size);
	else {
		ntfs_log_error("No uncompressed data,"
				" xbuf 0x%x xtgt 0x%x skip_size 0x%x\n",
				(int)xbuf,(int)xtgt,(int)skip_size);
		err = TRUE;
	}
	return (err ? -1 : xtgt - skip_size);
}

/*
 *		Read a compressed chunk of data
 *
 *	Reading is interrupted at the end of the initial chunk. A new
 *	request has to be made to get the end (which may be located in
 *	a different file or not compressed).
 *
 *	Returns a non-negative count of bytes read,
 *		or a negative error code.
 */

static s32 dedup_pread_compressed(ntfs_attr *na_data, off_t offset,
			u32 data_offset,
			const struct DEDUP_SMAP_ENTRY *smap_entry,
			u64 previous_end, size_t size, char *buf)
{
	struct DEDUP_CKHR_DATA ckhr_data;
	char *buf_compressed;
	char *buf_decomp;
	size_t read_size;
	s32 compressed_size;
	u32 decomp_size;
	u32 want_size;
	s32 r;
	s32 res;

	res = -1;
	r = ntfs_attr_pread(na_data, data_offset,
			sizeof(struct DEDUP_CKHR_DATA), &ckhr_data);
	if ((r == sizeof(struct DEDUP_CKHR_DATA))
	    && (ckhr_data.magic == CKHR_MAGIC)
	    && (ckhr_data.payload_size == smap_entry->data_size)
	    && !memcmp(ckhr_data.digest, smap_entry->digest, 32)) {
		compressed_size = le32_to_cpu(ckhr_data.payload_size);
			/* read the full compressed data */
		buf_compressed = (char*)malloc_maxed(compressed_size,__LINE__);
		if (buf_compressed) {
			/*
			 * Make sure the temporary buffer is never bigger
			 * than the uncompressed block, by truncating the
			 * requested size to the end of current block.
			 */
			decomp_size = size + offset;
			want_size = size;
			if ((decomp_size + previous_end)
					> le64_to_cpu(smap_entry->data_end)) {
				decomp_size = le64_to_cpu(smap_entry->data_end)
					- previous_end;
				want_size = decomp_size - offset;
			}
			buf_decomp = (char*)malloc_maxed(decomp_size,__LINE__);
			if (buf_decomp) {
				read_size = compressed_size;
				r = ntfs_attr_pread(na_data,
					sizeof(struct DEDUP_CKHR_DATA)
						+ data_offset,
					read_size, buf_compressed);
				if (r == (s32)read_size) {
					res = dedup_decompress(buf, want_size,
						offset, buf_compressed,
						compressed_size, buf_decomp);
				}
				free(buf_decomp);
			}
			free(buf_compressed);
		} else {
			res = -ENOMEM;
		}
	} else {
		ntfs_log_error("Bad Ckhr data header at 0x%llx"
				" for offset 0x%llx"
				" in file %lld\n",
				(long long)data_offset,
				(long long)offset,
				(long long)na_data->ni->mft_no);
		res = -EIO;
	}
	return (res);
}

/*
 *		Get data from a single chunk
 *
 *	Reading is interrupted at the end of the initial chunk. A new
 *	request has to be made to get the end (which may be located in
 *	a different file).
 *
 *	Returns a non-negative count of bytes read,
 *		or a negative error code.
 */

static int dedup_get_data(ntfs_inode *ni, char *buf, off_t offset, size_t size,
			const char *guid, u64 part_begin,
			struct DEDUP_SMAP *smap_stream, int smap_cnt)
{
	char path[MAXPATHSTORE];
	struct DEDUP_SMAP_ENTRY *smap_entry;
	ntfs_inode *ni_data;
	ntfs_attr *na_data;
	u64 data_end;
	u64 previous_end;
	size_t total;
	u32 data_offset;
	s32 got;
	BOOL compressed;
	int smaps_available;
	int k;

	total = 0;
	got = 0;
	/*
	 * Locate the first entry whose data_end is
	 * greater than wanted offset.
	 */
	k = 0;
	got = 0;
	previous_end = part_begin;
	smap_entry = smap_stream->entry;
	if (smap_cnt <= MAXSMAP)
		smaps_available = smap_cnt;
	else
		smaps_available = MAXSMAP;
	while ((k < smaps_available)
	    && (le64_to_cpu(smap_entry->data_end)
			 <= (u64)(offset + total))) {
		previous_end = le64_to_cpu(smap_entry->data_end);
		smap_entry++;
		k++;
		}
	if (k < smaps_available) {
		data_offset = le32_to_cpu(smap_entry->offset);
		data_end = le64_to_cpu(smap_entry->data_end);
		compressed = (data_end - previous_end)
					!= le32_to_cpu(smap_entry->data_size);
		snprintf(path,MAXPATHSTORE,
				"%s/%s/%s/{%s}.ddp/%s/%08lx.%08lx.ccc",
				"System Volume Information",
				"Dedup",
				"ChunkStore",
				guid,
				"Data",
				(long)le32_to_cpu(smap_entry->id1),
				(long)le32_to_cpu(smap_entry->id2));
		ni_data = ntfs_pathname_to_inode(ni->vol, (ntfs_inode*)NULL,
				path);
		if (ni_data) {
			na_data = ntfs_attr_open(ni_data, AT_DATA,
						(ntfschar*)NULL, 0);
			if (na_data) {
				if (compressed)
					got = dedup_pread_compressed(na_data,
						offset - previous_end + total,
						data_offset,
						smap_entry,
						previous_end,
						size - total,
						buf + total);
				else
					got = dedup_pread_data(na_data,
						offset - previous_end + total,
						data_offset,
						smap_entry,
						size - total,
						buf + total);
				ntfs_attr_close(na_data);
			}
			ntfs_inode_close(ni_data);
		}
	} else {
		got = 0; /* Is this an error case ? */
	}
	return (got);
}

/*
 *		Get data from the chunks designated in a reparse entry.
 *
 *	Returns a non-negative count of bytes read,
 *		or a negative error code.
 */

static s32 dedup_read_from_entry(ntfs_inode *ni, const char *guid,
			const struct DEDUP_REPARSE_ENTRY *reparse_entry,
			char *buf, size_t size, off_t offset)
{
	char *buf_stream;
	struct DEDUP_SMAP *smap_stream;
	u64 part_begin;
	size_t total;
	s32 got;
	s32 res;
	int smap_cnt;

	res = 0;
	total = 0;
	part_begin = ((u64)le32_to_cpu(reparse_entry->part_begin_high)
					<< 32)
			+ le32_to_cpu(reparse_entry->part_begin_low);
	buf_stream = dedup_fetch_stream(ni->vol, guid,
					reparse_entry, offset + total);
	if (buf_stream) {
		smap_stream = (struct DEDUP_SMAP*)&buf_stream[0x68];
		smap_cnt = (le32_to_cpu(reparse_entry->size_smap) - 8)
					/sizeof(struct DEDUP_SMAP_ENTRY);
		do {
			got = dedup_get_data(ni, buf + total,
				offset + total, size - total,
				guid, part_begin,
					smap_stream, smap_cnt);
			if (got > 0) {
				total += got;
				res = total;
			} else
				if (!total)
					res = got;
		} while ((got > 0) && (total < size));
		free(buf_stream);
	}
	return (res);
}

/*
 *		Get the size and mode of a deduplicated file
 */

static int dedup_getattr(ntfs_inode *ni, const REPARSE_POINT *reparse,
			      struct stat *stbuf)
{
	int res;

	res = -EOPNOTSUPP;
	if (reparse->reparse_tag == IO_REPARSE_TAG_DEDUP) {
		/* deduplicated file */
		stbuf->st_size = ni->data_size;
		stbuf->st_blocks = (ni->data_size + 511) >> 9;
		stbuf->st_mode = S_IFREG | 0555;
		res = 0;
	}
	/* Not a system dedup file, or another error occurred */
	return (res);
}

/*
 *		Open a deduplicated file for reading
 *
 *	Currently no reading context is created.
 */

static int dedup_open(ntfs_inode *ni __attribute__((unused)),
			   const REPARSE_POINT *reparse,
			   struct fuse_file_info *fi)
{
	int length;
	int res;

	res = -EOPNOTSUPP;
	length = le16_to_cpu(reparse->reparse_data_length);
	if ((reparse->reparse_tag == IO_REPARSE_TAG_DEDUP)
	    && (length >= 4)
	    && !(length & 3)
	    && (crc32(reparse->reparse_data, length - 4)
			== *(le32*)&reparse->reparse_data[length - 4])
	    && ((fi->flags & O_ACCMODE) == O_RDONLY))
		res = 0;
	return (res);
}

/*
 *		Release a deduplicated file
 *
 *	Should never be called, as we did not define a reading context
 */

static int dedup_release(ntfs_inode *ni __attribute__((unused)),
			   const REPARSE_POINT *reparse __attribute__((unused)),
			   struct fuse_file_info *fi __attribute__((unused)))
{
	return 0;
}

/*
 *		Read from a deduplicated file with extended reparse data
 *	Returns the count of bytes read or a negative error code.
 */

static int dedup_read_long(ntfs_inode *ni, const REPARSE_POINT *reparse,
			   char *buf, size_t size, off_t offset)
{
	char guid[37];
	const struct DEDUP_REPARSE *dedup_reparse;
	const struct DEDUP_REPARSE_ENTRY *reparse_entry;
	u64 previous_end;
	u64 part_begin;
	u64 part_end;
	s64 got;
	size_t total;
	int entry_offset;
	int more_entries;
	int res;
	int i;

	res = -EOPNOTSUPP;
	dedup_reparse = (struct DEDUP_REPARSE*)reparse;
	if (ntfs_guid_to_mbs(&dedup_reparse->guid, guid)) {
		for (i=0; guid[i]; i++)
			guid[i] = toupper(guid[i]);
		total = 0;
		do {
			entry_offset = le16_to_cpu(dedup_reparse->offs_data2);
			reparse_entry = (const struct DEDUP_REPARSE_ENTRY*)
					((const char*)dedup_reparse
						+ entry_offset + 8);
			previous_end = 0;
			part_end = mergele64(
					reparse_entry->part_end_high,
					reparse_entry->part_end_low);
			more_entries = le16_to_cpu(dedup_reparse->size_data2)
					- sizeof(struct DEDUP_REPARSE_ENTRY);
			while ((more_entries > 0)
			    && ((u64)(offset + total) >= part_end)) {
				previous_end = part_end;
				reparse_entry++;
				part_end = mergele64(
					reparse_entry->part_end_high,
					reparse_entry->part_end_low);
				more_entries
					-= sizeof(struct DEDUP_REPARSE_ENTRY);
			}
			if ((u64)(offset + total) >= part_end) {
				got = 0;	/* reading beyond the end */
			} else {
				part_begin = mergele64(
					reparse_entry->part_begin_high,
					reparse_entry->part_begin_low);
				if (part_begin != previous_end) {
					ntfs_log_error("There is a gap between"
						" 0x%llx and 0x%llx"
						" in file %lld\n",
						(long long)previous_end,
						(long long)part_begin,
						(long long)ni->mft_no);
					got = -EOPNOTSUPP;
				} else {
					got = dedup_read_from_entry(ni, guid,
						reparse_entry,
						buf + total, size - total,
						offset + total);
				}
			}
			if (got > 0) {
				total += got;
				res = total;
			} else
				if (!total)
					res = got;
		} while ((got > 0) && (total < size));
	} else {
		res = -EINVAL;
	}
	return res;
}

/*
 *		Read from a deduplicated file with minimal reparse data
 *	This format is probably not suitable for big files.
 *	Returns the count of bytes read or a negative error code.
 */

static int dedup_read_short(ntfs_inode *ni, const REPARSE_POINT *reparse,
			   char *buf, size_t size, off_t offset)
{
	char guid[37];
	const struct DEDUP_REPARSE_SHORT *dedup_reparse;
	struct DEDUP_REPARSE_ENTRY reparse_entry_copy;
	u64 previous_end;
	u64 part_begin;
	u64 part_end;
	s64 got;
	size_t total;
	int more_entries;
	int res;
	int i;

	res = -EOPNOTSUPP;
	dedup_reparse = (struct DEDUP_REPARSE_SHORT*)reparse;
	if (ntfs_guid_to_mbs(&dedup_reparse->guid, guid)) {
		for (i=0; guid[i]; i++)
			guid[i] = toupper(guid[i]);
		total = 0;
			/*
			 * Apparently, there is a 32-byte digest.
			 * Keep only 16 bytes and overwrite the end
			 * to match the DEDUP_REPARSE_ENTRY format.
			 * This will have to be changed if there can
			 * be an array of DEDUP_REPARSE_ENTRY.
			 * Need somebody to exhibit such an array
			 * for redesigning this properly.
			 */
		memcpy(&reparse_entry_copy, dedup_reparse->data,
					sizeof(struct DEDUP_REPARSE_ENTRY));
		part_end = mergele64(dedup_reparse->part_end_high,
					dedup_reparse->part_end_low);
		reparse_entry_copy.part_end_low
					= dedup_reparse->part_end_low;
		reparse_entry_copy.part_end_high
					= dedup_reparse->part_end_high;
		reparse_entry_copy.part_begin_low = const_cpu_to_le32(0);
		reparse_entry_copy.part_begin_high = const_cpu_to_le32(0);
		previous_end = 0;
		more_entries = 0;
		do {
			if ((u64)(offset + total) >= part_end) {
				got = 0;	/* reading beyond the end */
			} else {
					/* Assume a single entry for now */
				part_begin = 0;
				if (part_begin != previous_end) {
					ntfs_log_error("There is a gap between"
							" 0x%llx and 0x%llx"
							" in file %lld\n",
							(long long)previous_end,
							(long long)part_begin,
							(long long)ni->mft_no);
					got = -EOPNOTSUPP;
				} else {
					got = dedup_read_from_entry(ni, guid,
							&reparse_entry_copy,
							buf + total,
							size - total,
							offset + total);
				}
			}
			if (got > 0) {
				total += got;
				res = total;
			} else
				if (!total)
					res = got;
		} while ((got > 0) && (total < size));
	} else {
		res = -EINVAL;
	}
	return res;
}

/*
 *		Read entry point
 *	Check input and start processing according to reparse data format.
 *	Returns the count of bytes read or a negative error code.
 */

static int dedup_read(ntfs_inode *ni, const REPARSE_POINT *reparse,
			   char *buf, size_t size, off_t offset,
			   struct fuse_file_info *fi __attribute__((unused)))
{
	const struct DEDUP_REPARSE *dedup_reparse;
	int res;

	res = -EOPNOTSUPP;
	dedup_reparse = (struct DEDUP_REPARSE*)reparse;
		/* The crc32 was checked while opening, do not check again */
	if (ni && reparse && buf
	    && (dedup_reparse->reparse_tag == IO_REPARSE_TAG_DEDUP)
	    && (dedup_reparse->length == dedup_reparse->reparse_data_length)) {
		/* Assume the format defines a minor.major type version */
		switch (le16_to_cpu(dedup_reparse->format)) {
		case 0x0201 :
			res = dedup_read_short(ni, reparse,
						buf, size, offset);
			break;
		case 0x0102 :
			res = dedup_read_long(ni, reparse,
						buf, size, offset);
			break;
		default :
			ntfs_log_error("Unexpected dedup format code 0x%x\n",
				(int)le16_to_cpu(dedup_reparse->format));
			break;
		}
	} else {
		res = -EINVAL;
	}
	return (res);
}

static const struct plugin_operations ops = {
	.getattr = dedup_getattr,
	.open = dedup_open,
	.release = dedup_release,
	.read = dedup_read,
};

/*
 *		Initialize the plugin and return its methods.
 */

const struct plugin_operations *init(le32 tag)
{
	const struct plugin_operations *pops;

	pops = (const struct plugin_operations*)NULL;
	/* Check needed structs for safety (done at compile-time) */
	if ((sizeof(struct DEDUP_REPARSE_ENTRY) == 64)
	    && (sizeof(struct DEDUP_CKHR_DATA) == 88)
	    && (sizeof(struct DEDUP_CKHR_STREAM) == 104)
	    && (sizeof(struct DEDUP_SMAP_ENTRY) == 64)
	    && (offsetof(struct DEDUP_SMAP, entry) == 8)
	    && (offsetof(struct DEDUP_REPARSE, data) == 156)
	    && (offsetof(struct DEDUP_REPARSE_SHORT, data) == 64)) {
		if (tag == IO_REPARSE_TAG_DEDUP)
			pops = &ops;
	} else {
		ntfs_log_error("Error in deduplication struct layout\n");
	}
	if (pops)
		ntfs_log_info("Deduplication plugin %s for ntfs-3g\n",
					DEDUP_VERSION);
	else
		errno = EINVAL;
	return (pops);
}
