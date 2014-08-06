#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <stdint.h>
#include <stropts.h>
#include <CuTest.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>

/* [TODO]
 * Test if OpenVSL b0rked non-4k granularity modes or if LNVM code is
 *    still having issues.
 *
 * Fix erase test, it's still not complete.
 *
 * Fix erase async test.
 *
 * Expand LNVM code to err out when attempting to erase something
 *    which isn't a perfect multiple of the erase granularity
 *
 * Fix Read/Write interface to utilize correct R,W granularity instead
 *   of guessing.
 */

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#include <linux/byteorder/little_endian.h>
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#include <linux/byteorder/big_endian.h>
#endif

//Constants
#define LVER		1
#define LNVME_TYPE	0
#define LNVME_CHNL	16
#define QUEUE_SIZE	64
#define GRAN_READ	4096
#define GRAN_WRITE	4096
#define GRAN_ERASE	4096
#define OOB_SIZE	0
#define T_R		10000
#define T_SQR		10000
#define T_W		10000
#define T_SQW		10000
#define T_E		100000
#define IOSCHED_CHNL	0

#define TEST_FILE_SIZE	130000
#define BITS_TO_BYTES(x) ((x) >> 3)
#define LNVME_DEV "/dev/nvme0n1"

#define PACKED __attribute__((packed))

struct PACKED lnvme_id {
  	uint16_t	ver_id;
  	uint8_t	nvm_type;
  	uint16_t	nchannels;
  	uint8_t	unused[4091];
};

struct PACKED lnvme_id_chnl {
	uint64_t	queue_size;
	uint64_t	gran_read;
	uint64_t	gran_write;
	uint64_t	gran_erase;
	uint64_t	oob_size;
	uint32_t	t_r;
	uint32_t	t_sqr;
	uint32_t	t_w;
	uint32_t	t_sqw;
	uint32_t	t_e;
	uint8_t	io_sched;
	uint64_t	laddr_begin;
	uint64_t	laddr_end;
	uint8_t	unused[4019];
};

struct PACKED nvme_admin_cmd {
	uint8_t	opcode;
	uint8_t	flags;
	uint16_t	rsvd1;
	uint32_t	nsid;
	uint32_t	cdw2;
	uint32_t	cdw3;
	uint64_t	metadata;
	uint64_t	addr;
	uint32_t	metadata_len;
	uint32_t	data_len;
	uint32_t	cdw10;
	uint32_t	cdw11;
	uint32_t	cdw12;
	uint32_t	cdw13;
	uint32_t	cwd14;
	uint32_t	cdw15;
	uint32_t	timeout_ms;
	uint32_t	result;
};

struct nvme_user_io {
	uint8_t	opcode;
	uint8_t	flags;
	uint16_t	control;
	uint16_t	nblocks;
	uint16_t	rsvd;
	uint64_t	metadata;
	uint64_t	addr;
	uint64_t	slba;
	uint32_t	dsmgmt;
	uint32_t	reftag;
	uint16_t	apptag;
	uint16_t	appmask;
	uint32_t	host_lba;
};

enum nvme_admin_opcode {
	nvme_admin_format		= 0x80,
};

enum lnvme_admin_opcode {
	lnvme_admin_identify		= 0xc0,
	lnvme_admin_identify_channel	= 0xc1,
	lnvme_admin_get_features	= 0xc2,
	lnvme_admin_set_responsibility	= 0xc3,
	lnvme_admin_get_l2p_tbl	= 0xc4,
	lnvme_admin_get_p2l_tbl	= 0xc5,
	lnvme_admin_flush_tbls		= 0xc6,
};

enum nvme_opcode {
	nvme_cmd_flush		= 0x00,
	nvme_cmd_write		= 0x01,
	nvme_cmd_read		= 0x02,
	nvme_cmd_write_uncor	= 0x04,
	nvme_cmd_compare	= 0x05,
	nvme_cmd_dsm		= 0x09,
};

enum lnvme_opcode {
	lnvme_cmd_erase_sync	= 0x80,
	lnvme_cmd_erase_async	= 0x81,
};

enum LnvmeFeatures {
    R_L2P_MAPPING	= 0U,
    R_P2L_MAPPING	= 1U,
    R_GC		= 2U,
    R_ECC		= 3U,
    E_BLK_MOVE		= 256U,
    E_NVM_COPY_BACK	= 257U,
    E_SAFE_SHUTDOWN	= 258U,
};

#define NVME_IOCTL_ADMIN_CMD _IOWR('N', 0x41, struct nvme_admin_cmd)
#define NVME_IOCTL_SUBMIT_IO _IOW('N', 0x42, struct nvme_user_io)

#define TEST(n) void test_##n(CuTest *self)
#define err(msg,...) fprintf(stderr, "ERR<%s>%d: " msg, __FUNCTION__, __LINE__, __VA_ARGS__)

void *alloc_ioctl_structure(size_t cmd_len, size_t data_len, uint64_t *data_addr)
{
	uint8_t *base;
	uint8_t do_pad = (cmd_len % 8);
	size_t alloc_siz = do_pad ?
		(cmd_len + data_len + sizeof(void*)) : cmd_len + data_len;

	base = calloc(1, alloc_siz);
	if (!base)
		goto out;

	*data_addr = (uint64_t)base + cmd_len;
	if (do_pad) {
		*data_addr = (*data_addr + sizeof(void*)) && ~3;
	}

out:
	return (void *)base;
}

struct nvme_admin_cmd *alloc_ioctl_cmd(size_t data_len)
{
	struct nvme_admin_cmd *cmd = NULL;
	uint64_t data_addr;

	cmd = alloc_ioctl_structure(
		sizeof(struct nvme_admin_cmd),
		data_len, &data_addr);
	if (!cmd)
		goto out;
	cmd->addr = data_addr;
	cmd->data_len = data_len;
out:
	return cmd;
}

struct nvme_user_io *alloc_ioctl_uio(size_t len, uint64_t gran)
{
	struct nvme_user_io *uio = NULL;
	uint64_t data_addr;
	uio = alloc_ioctl_structure(
		sizeof(struct nvme_user_io),
		len, &data_addr);
	if (!uio)
		goto out;
	uio->addr = data_addr;
	if (len) {
		uio->nblocks = (len / gran) - 1;
	}
out:
	return uio;
}

void *uio_get_buf(struct nvme_user_io *uio)
{
	assert(uio != NULL);
	assert(uio->addr != 0);
	return (void *)uio->addr;
}

int memdiff(void *m1, void *m2, size_t off, size_t len)
{
	uint8_t *b1, *b2;
	size_t i;
	b1 = (uint8_t*) (((uintptr_t)m1)+off);
	b2 = (uint8_t*) (((uintptr_t)m2)+off);
	for(i = off; i < off+len; i++) {
		if (*b1 != *b2) {
			err("values differ at offset '%zu'\n", i);
			return -i;
		}
		b1++; b2++;
	}
	return 0;
}

void memdump(void *mem, size_t off, size_t len)
{
	uint8_t *b;
	size_t i;
	b = (uint8_t*) (((uintptr_t)mem)+off);
	for(i = off; i < off+len; i++) {
		fprintf(stderr, "%"PRIx8, *b);
		b++;
	}
}

void free_cmd(struct nvme_admin_cmd *cmd)
{
	free(cmd);
}

int readfile(char *fpath, size_t off, uint8_t *buf, size_t len)
{
	FILE *f;
	int ret = -1;

	if (!buf)
		goto out;

	f = fopen(fpath, "rb");

	if (!f) {
		goto out;
	}

	fseek(f, off, SEEK_SET);
	ret = fread(buf, 1, len, f);
	fclose(f);
out:
	return ret;
}

uint8_t __get_feature(uint64_t *features, uint32_t ndx)
{
	return (uint8_t)(features[(ndx >> 6)] & (1 << (ndx & 63)));
}

typedef void (*cmd_cfg_cb)(struct nvme_admin_cmd *cmd, void *data);
struct admin_cmd_buf
{
	uint8_t *data;
	size_t len;
};

void ioctl_admin_cmd(CuTest *self, struct admin_cmd_buf *buf, int ioctl_cmd,
		cmd_cfg_cb usr_cb, void *data)
{
	int ret, fd;
	struct nvme_admin_cmd *cmd = NULL;

	CuAssertTrue(self, buf != NULL);
	CuAssertTrue(self, usr_cb != NULL);

	if (buf->len) {
		memset(buf->data, 0, buf->len);
	}
	fd = open(LNVME_DEV, O_RDONLY);
	CuAssertTrue(self, fd != -1);
	cmd = alloc_ioctl_cmd(buf->len);
	CuAssertTrue(self, cmd != NULL);
	usr_cb(cmd, data);

	ret = ioctl(fd, ioctl_cmd, cmd);
	close(fd);
	CuAssertTrue(self, ret >= 0);
	if (buf->len)
		memcpy(buf->data, (void const *)cmd->addr, buf->len);
	free(cmd);
}

void __identify_cb(struct nvme_admin_cmd *cmd, void *data)
{
	cmd->opcode = lnvme_admin_identify;
}

void identify_ctrl(CuTest *self, struct lnvme_id *id)
{
	struct admin_cmd_buf buf = {.data = (uint8_t *)id, .len = sizeof(*id)};
	CuAssertTrue(self, id != NULL);
	ioctl_admin_cmd(self, &buf, NVME_IOCTL_ADMIN_CMD, __identify_cb, NULL);
}

void __identify_chnl(struct nvme_admin_cmd *cmd, void *data)
{
	uint32_t *nsid = data;
	cmd->opcode = lnvme_admin_identify_channel;
	cmd->nsid = cmd->cdw10 = *nsid;
}

void identify_chnl(CuTest *self, struct lnvme_id_chnl *id_chnl, uint32_t nsid)
{
	struct admin_cmd_buf buf = {.data = (uint8_t *)id_chnl,
				  .len = sizeof(*id_chnl)};
	CuAssertTrue(self, id_chnl != NULL);
	ioctl_admin_cmd(self, &buf, NVME_IOCTL_ADMIN_CMD,
		__identify_chnl, &nsid);
}

void __features_get(struct nvme_admin_cmd *cmd, void *data)
{
	cmd->opcode = lnvme_admin_get_features;
}

void features_get(CuTest *self, uint8_t *buffer)
{
	struct admin_cmd_buf buf = {.data = buffer, .len = BITS_TO_BYTES(512)};
	CuAssertTrue(self, buffer != NULL);
	ioctl_admin_cmd(self, &buf, NVME_IOCTL_ADMIN_CMD,
		__features_get, NULL);
}

void __responsibility_set(struct nvme_admin_cmd *cmd, void *data)
{
	uint32_t *input = data;
	cmd->opcode = lnvme_admin_set_responsibility;
	cmd->cdw10 = input[0];
	cmd->cdw11 = input[1];
}

void responsibility_set(CuTest *self, uint32_t resp, uint32_t val)
{
	struct admin_cmd_buf buf = {.data = NULL, .len = 0};
	uint32_t input[2] = {resp, val};
	ioctl_admin_cmd(self, &buf, NVME_IOCTL_ADMIN_CMD,
		__responsibility_set, input);
}

void __flush_tbl_cb(struct nvme_admin_cmd *cmd, void *data)
{
	uint32_t *nsid = data;
	cmd->opcode = lnvme_admin_flush_tbls;
	cmd->nsid = *nsid;
}

void flush_tbl(CuTest *self, uint32_t nsid)
{
	struct admin_cmd_buf buf = {.data = NULL, .len = 0};
	ioctl_admin_cmd(self, &buf, NVME_IOCTL_ADMIN_CMD,
		__flush_tbl_cb, &nsid);
}

#define FORMAT_GET_LBAF(x) ((x) & 15)
#define FORMAT_GET_MS(x) ( (x)>>4 & 1)
#define FORMAT_GET_PI(x) ( (x)>>5 & 7 )
#define FORMAT_GET_PIL(x) ( (x)>>8 & 1 )
#define FORMAT_GET_SES(x) ( (x)>>9 & 7 )

uint32_t set_bit_seq(uint32_t v, uint32_t input, uint8_t nbits, uint8_t off)
{
	/*extracts nbits lowest bits from 'input' and applies that
	 bit pattern at offset 'off' within value 'v'*/
	uint32_t o = (1 << (nbits+1)) - 1;
	return (v  & ~(o << off)) | (input & o)<<off;
}

uint32_t FORMAT_SET_LBAF(uint32_t x, uint32_t v)
{
	return set_bit_seq(x, v, 4, 0);
}

uint32_t FORMAT_SET_MS(uint32_t x, uint32_t v)
{
	return set_bit_seq(x, v, 1, 4);
}

uint32_t FORMAT_SET_PI(uint32_t x, uint32_t v)
{
	return set_bit_seq(x, v, 3, 5);
}

uint32_t FORMAT_SET_PIL(uint32_t x, uint32_t v)
{
	return set_bit_seq(x, v, 1, 8);
}

uint32_t FORMAT_SET_SES(uint32_t x, uint32_t v)
{
	return set_bit_seq(x, v, 3, 9);
}

uint32_t format_default_settings()
{
	/*LBAF=0, MS is separate, no PI, PIL N/A no SES*/
	return 0;
}

void __format_ns(struct nvme_admin_cmd *cmd, void *data)
{
	uint32_t *values = data;
	cmd->opcode = nvme_admin_format;
	cmd->nsid = values[0];
	cmd->cdw10 = values[1];
}

void format_ns(CuTest *self, uint32_t nsid, uint32_t format_settings)
{
	uint32_t data[2] = { nsid, format_settings };
	struct admin_cmd_buf buf = {.data = NULL, .len = 0};
	CuAssertTrue(self, nsid != 0);
	ioctl_admin_cmd(self, &buf, NVME_IOCTL_ADMIN_CMD,
		__format_ns, data);
}

static void __lnvme_erase (CuTest *self, uint8_t cmd_code, uint32_t nsid,
			uint64_t slba, uint16_t nlb)
{
	int ret, fd;
	struct nvme_user_io *cmd;
	CuAssert(self, "nlb cannot be 0, must be 1 or more", nlb != 0);

	fd = open(LNVME_DEV, O_RDONLY);
	CuAssertTrue(self, fd != 0);

	cmd = alloc_ioctl_uio(0,0);
	CuAssertTrue(self, cmd != NULL);

	cmd->opcode = lnvme_cmd_erase_sync;
	cmd->slba = slba;
	cmd->nblocks = nlb - 1;

	ret = ioctl(fd, NVME_IOCTL_SUBMIT_IO, cmd);
	close(fd);
	free(cmd);
	CuAssertTrue(self, ret >= 0);
}

void erase_sync(CuTest *self, uint32_t nsid, uint64_t slba, uint16_t nlb)
{
	return __lnvme_erase(self, lnvme_cmd_erase_sync, nsid, slba, nlb);
}

void erase_async(CuTest *self, uint32_t nsid, uint64_t slba, uint16_t nlb)
{
	return __lnvme_erase(self, lnvme_cmd_erase_async, nsid, slba, nlb);
}

#define TBL_P2L 3ULL
#define TBL_L2P 4ULL
typedef uint64_t tbl_type_t;

struct tbl_req {
	tbl_type_t tbl;
	uint64_t slba;
	uint16_t nlb;
	uint32_t nsid;
};

void __get_tbl_cb(struct nvme_admin_cmd *cmd, void *data)
{
	struct tbl_req *req = data;
	if (req->tbl == TBL_P2L) {
		cmd->opcode = lnvme_admin_get_p2l_tbl;
	} else {
		err("unhandled test case -- asking for L2P table%d\n", 1);
	}
	cmd->nsid = req->nsid;
	cmd->cdw10 = (uint32_t)(req->slba & 0xffffffff);
	cmd->cdw11 = (uint32_t)((req->slba)>>32);
	cmd->cdw12 = (uint32_t)(req->nlb);
}

void get_tbl(CuTest *self, tbl_type_t tbl_type, uint32_t nsid,
	uint64_t slba, void *buffer, size_t len)
{
	struct admin_cmd_buf buf = {.data = buffer, .len = len};
	struct tbl_req req = {.tbl = tbl_type, .slba = slba,
			      .nlb = len/(1<<9), .nsid = nsid};
	CuAssertTrue(self, nsid !=  0);
	ioctl_admin_cmd(self, &buf, NVME_IOCTL_ADMIN_CMD,
			__get_tbl_cb, &req);
}

typedef enum {
	IOTYPE_READ	= 0ULL,
	IOTYPE_WRITE	= 1ULL,
	IOTYPE_ERASE	= 2ULL,
} IOType;

uint64_t get_granularity(CuTest *self, uint32_t nsid, IOType t)
{
	struct lnvme_id_chnl chnl;
	identify_chnl(self, &chnl, nsid);
	switch(t) {
	case IOTYPE_READ:
		return __le64_to_cpu(chnl.gran_read);
	case IOTYPE_WRITE:
		return __le64_to_cpu(chnl.gran_write);
	case IOTYPE_ERASE:
		return __le64_to_cpu(chnl.gran_erase);
	default:
		return 0;
	}
}

typedef void (*cmd_io_cb)(struct nvme_user_io *cmd, void *data);
struct uio_buf {
	uint8_t *data;
	size_t len;
	uint64_t gran;
};

void ioctl_io_cmd(CuTest *self, IOType iot,
		struct uio_buf *buf, cmd_io_cb usr_cb, void *data)
{
	static uint32_t const NVME_SUCCESS = 0x0;
	static uint32_t const NVME_NO_COMPLETE = 0xffff;
	int ret, fd;
	struct nvme_user_io *cmd = NULL;

	CuAssertTrue(self, buf != NULL);
	CuAssertTrue(self, buf->len != 0);
	CuAssertTrue(self, buf->gran != 0);
	CuAssertTrue(self, usr_cb != NULL);
	CuAssertTrue(self, iot == IOTYPE_READ
		|| iot == IOTYPE_WRITE);

	if (iot == IOTYPE_READ) {
		memset(buf->data, 0, buf->len);
	}

	fd = open(LNVME_DEV, O_RDONLY);
	CuAssertTrue(self, fd != -1);

	cmd = alloc_ioctl_uio(buf->len, buf->gran);
	CuAssertTrue(self, cmd != NULL);
	usr_cb(cmd, data);

	if (iot == IOTYPE_WRITE)
		memcpy((void *)cmd->addr, buf->data, buf->len);
	ret = ioctl(fd, NVME_IOCTL_SUBMIT_IO, cmd);
	close(fd);
	CuAssert(self,
		"Error processing I/O ioctl",
		(ret == NVME_SUCCESS) || (ret == NVME_NO_COMPLETE));
	if (iot == IOTYPE_READ)
		memcpy(buf->data, (void const *)cmd->addr, buf->len);
	free(cmd);
}

void __ioctl_iorw_cb(struct nvme_user_io *cmd, void *data)
{
	uint64_t *input = data;
	uint64_t iot, slba;
	uint32_t host_lba;
	iot = input[0];
	slba = input[1];
	host_lba = (uint32_t)input[2];

	if(iot == IOTYPE_WRITE)
		cmd->opcode = nvme_cmd_write;
	else if (iot == IOTYPE_READ)
		cmd->opcode = nvme_cmd_read;
	cmd->slba = slba;
	cmd->host_lba = host_lba;
}

void __ioctl_io(CuTest *self, IOType iot, uint32_t hlba,
		uint64_t slba, void *buffer, size_t len)
{
	uint64_t input[3] = {iot, slba, hlba};
	struct uio_buf buf = {
		.data = (uint8_t *)buffer,
		.len = len,
		.gran = 0
	};
	buf.gran = get_granularity(self, 1, iot);

	CuAssertTrue(self, buffer != NULL);
	CuAssertTrue(self, len != 0);
	CuAssert(self,
		"buffers must be an exact multiple of"
		"IO type granularity",
		buf.len % buf.gran == 0
	);

	ioctl_io_cmd(self, iot, &buf, __ioctl_iorw_cb, input);
}

void ioctl_io_write(CuTest *self, uint32_t hlba, uint64_t slba,
		void *buf, size_t len)
{
	__ioctl_io(self, IOTYPE_WRITE, hlba, slba, buf, len);
}

void ioctl_io_read(CuTest *self, uint64_t slba,
		void *buf, size_t len)
{
	__ioctl_io(self, IOTYPE_READ, 0, slba, buf, len);
}

/*    --[TEST CODE BEGIN]--    */
/*=============================*/
void test_setup(CuTest *self)
{
	uint32_t const nsid = 1;
	/*clear P2L tbl & sets r/w/e granularity to 4K*/
	format_ns(self, nsid,
		FORMAT_SET_LBAF(format_default_settings(), 3)
	);
}

void test_teardown(CuTest *self)
{
	/*do nothing*/
}

TEST(format_ns)
{
	struct lnvme_id id;
	struct lnvme_id_chnl id_chnl;
	identify_ctrl(self, &id);
	CuAssertTrue(self, id.nchannels == LNVME_CHNL);

	identify_chnl(self, &id_chnl, 1);
	CuAssertTrue(self, id_chnl.gran_read != 0);

	format_ns(self, 1, format_default_settings());
	identify_chnl(self, &id_chnl, 1);
	CuAssertTrue(self, id_chnl.gran_read == 512);

	format_ns(self, 1, FORMAT_SET_LBAF(format_default_settings(), 3));
	identify_chnl(self, &id_chnl, 1);
	CuAssertTrue(self, id_chnl.gran_read == 4096);
}

TEST(identify)
{
	struct lnvme_id id;
	identify_ctrl(self, &id);
	CuAssertTrue(self, __le16_to_cpu(id.ver_id) == LVER);
	CuAssertTrue(self, id.nvm_type == LNVME_TYPE);
	CuAssertTrue(self, __le16_to_cpu(id.nchannels) == LNVME_CHNL);
}

TEST(identify_channel)
{
	struct lnvme_id_chnl chnl;
	identify_chnl(self, &chnl, 1);

	CuAssertTrue(self, __le64_to_cpu(chnl.queue_size) == QUEUE_SIZE);
	CuAssertTrue(self, __le64_to_cpu(chnl.gran_read) == GRAN_READ);
	CuAssertTrue(self, __le64_to_cpu(chnl.gran_write) == GRAN_WRITE);
	CuAssertTrue(self, __le64_to_cpu(chnl.gran_erase) == GRAN_ERASE);
	CuAssertTrue(self, __le64_to_cpu(chnl.oob_size) == OOB_SIZE);
	CuAssertTrue(self, __le32_to_cpu(chnl.t_r) == T_R);
	CuAssertTrue(self, __le32_to_cpu(chnl.t_sqr) == T_SQR);
	CuAssertTrue(self, __le32_to_cpu(chnl.t_w) == T_W);
	CuAssertTrue(self, __le32_to_cpu(chnl.t_sqw) == T_SQW);
	CuAssertTrue(self, __le32_to_cpu(chnl.t_e) == T_E);
	CuAssertTrue(self, chnl.io_sched == IOSCHED_CHNL);
}

TEST(get_features)
{
	uint8_t buf[BITS_TO_BYTES(512)];
	uint64_t *resp = (uint64_t *)buf;
	features_get(self, buf);
	CuAssertTrue(self, !__get_feature(resp, R_L2P_MAPPING));
	CuAssertTrue(self,! __get_feature(resp, R_P2L_MAPPING));
	CuAssertTrue(self, __get_feature(resp, R_ECC));
	CuAssertTrue(self, __get_feature(resp, R_GC));
	CuAssertTrue(self, !__get_feature(resp, E_BLK_MOVE));
	CuAssertTrue(self, !__get_feature(resp, E_NVM_COPY_BACK));
	CuAssertTrue(self, !__get_feature(resp, E_SAFE_SHUTDOWN));
}

TEST(set_responsibility)
{
	uint8_t buf[BITS_TO_BYTES(512)];
	uint64_t *resp = (uint64_t *)buf;
	
	responsibility_set(self, R_ECC, 0);
	features_get(self, buf);
	CuAssertTrue(self, !__get_feature(resp, R_ECC));

	responsibility_set(self, R_ECC, 1);
	features_get(self, buf);
	CuAssertTrue(self, __get_feature(resp, R_ECC));
}

TEST(write_lba)
{
	long ret;
	size_t const data_size = 12288;
	uint64_t const slba = 1000;
	uint8_t *wbuf = NULL, *rbuf = NULL;

	wbuf = calloc(1, data_size);
	CuAssertTrue(self, wbuf != NULL);

	rbuf = calloc(1, data_size);
	CuAssertTrue(self, rbuf != NULL);

	ret = readfile("testdata", rand() % (TEST_FILE_SIZE-data_size),
		wbuf, data_size);
	CuAssertTrue(self, ret == data_size);

	ret = memcmp(wbuf, rbuf, data_size);
	CuAssertTrue(self, ret != 0);

	ioctl_io_write(self, 0, slba, wbuf, data_size);

	ioctl_io_read(self, slba, rbuf, data_size);

	ret = memcmp(wbuf, rbuf, data_size);
	if (ret != 0) {
		err("write ioctl failed.. ret(%ld)\n", ret);
		memdiff(wbuf, rbuf, 0, data_size);
	}
	free(wbuf);
	free(rbuf);
	CuAssertTrue(self, ret == 0);
}

int memcmp0(void const *buf, size_t off, size_t len)
{ /*return 0 if entire range is zero, +1/-1 otherwise*/
	uint8_t cmp_blk[len];
	uint8_t *c = (uint8_t *)buf;
	memset(cmp_blk, 0, sizeof(cmp_blk));
	return memcmp(cmp_blk, c + off , len);
}

void __erase_common_start(CuTest *self, uint64_t slba, uint32_t nsid,
		uint16_t nlb, size_t *data_size_out, uint8_t **buf_out)
{
	struct lnvme_id_chnl chnl;
	size_t data_size;
	uint8_t *buf = NULL;
	long ret;

	identify_chnl(self, &chnl, nsid);
	CuAssert(self,
		"Test not written to account for erase and write "
		"granularity being different!",
		chnl.gran_erase == chnl.gran_write
	);

	data_size = nlb * __le64_to_cpu(chnl.gran_write);
	buf = calloc(1, data_size);
	CuAssert(self, "Memory allocation for test failed!",
		buf != NULL);

	ret = readfile("testdata", rand() % (TEST_FILE_SIZE-data_size),
		buf, data_size);
	CuAssert(self, "error reading testdata into buffer",
		ret == data_size);
	ioctl_io_write(self, 0, slba, buf, data_size);

	/*Common path ends, return values*/
	*data_size_out = data_size;
	*buf_out = buf;
}

void __erase_common_end(CuTest *self, uint64_t slba,
			uint8_t *buf, size_t data_size)
{
	long ret;

	ioctl_io_read(self, slba, buf, data_size);

	ret = memcmp0(buf, 0, data_size);
	CuAssert(self, "xErase command didn't properly erase data!",
		ret == 0);
	free(buf);
}

TEST(erase_sync)
{
	uint64_t const slba = 1000;
	uint32_t const nsid = 1;
	uint16_t const nlb = 4;

	size_t data_size;
	uint8_t *buf;

	__erase_common_start(self, slba, nsid, nlb, &data_size, &buf);

	erase_sync(self, nsid, slba, nlb);
	__erase_common_end(self, slba, buf, data_size);
}

TEST(erase_async)
{
	uint64_t const slba = 1000;
	uint32_t const nsid = 1;
	uint16_t const nlb = 4;

	size_t data_size;
	uint8_t *buf;

	__erase_common_start(self, slba, nsid, nlb, &data_size, &buf);

	/*Admittedly dirty but I have no other recourse*/
	erase_async(self, nsid, slba, nlb);
	CuAssert(self,
		"sleep was interrupted, re-run tests!",
		sleep(1) == 0);

	__erase_common_end(self, slba, buf, data_size);
}

int validate_tbl_region(uint32_t start_hlba, void *tbl_buf, size_t off, size_t nlb)
{
	uint32_t *ptr = ((uint32_t *)tbl_buf)+off;
	uint32_t hlba;
	size_t i;
	for (i = 0; i < nlb; i++, ptr++) {
		hlba = __cpu_to_le32(start_hlba + 1);
		if ( *ptr != hlba ) {
		fprintf(stderr, "validate_tbl_region: (le32) value! expected (%"SCNx32") got (%"SCNx32")\n",
			hlba, *ptr);
			return i;
		}
	}
	return 0;
}

TEST(p2l_tbl)
{
	int ret;
	struct lnvme_id_chnl chnl;
	void *wbuf;
	uint32_t *tblbuf;
	uint32_t const nsid = 1;
	size_t const tbl_len = 7 * (1 << 9);
	size_t const wbuf_len = 12288;
	uint64_t const slba = 2;
	uint32_t const hlba = 0x89abcdef;

	wbuf = calloc(1, wbuf_len);
	CuAssertTrue(self, wbuf != NULL);
	tblbuf = calloc(1, tbl_len);
	CuAssertTrue(self, tblbuf != NULL);

	/*clear P2L tbl & sets r/w/e granularity to 4K*/
	format_ns(self, nsid,
		FORMAT_SET_LBAF(format_default_settings(), 3)
	);

	identify_chnl(self, &chnl, nsid);
	CuAssertTrue(self, chnl.gran_read == 4096);
	CuAssertTrue(self, chnl.gran_write == 4096);
	CuAssertTrue(self, chnl.gran_erase == 4096);

	get_tbl(self, TBL_P2L, nsid, slba-1, tblbuf, tbl_len);

	ret = readfile("testdata", rand() % (TEST_FILE_SIZE-wbuf_len),
		wbuf, wbuf_len);
	CuAssertTrue(self, ret == wbuf_len);

	ioctl_io_write(self, hlba, slba, wbuf, wbuf_len);

	flush_tbl(self, nsid);

	get_tbl(self, TBL_P2L, nsid, slba-1, tblbuf, tbl_len);

	/*Validate that X entries were written, ascending values from 'hlba'
	 and that surrounding entries are zero, still*/
	ret = validate_tbl_region(hlba, tblbuf, 1, wbuf_len % chnl.gran_write);
	CuAssert(self, "p2l tbl contents didn't match expected contents\n", ret == 0);

	CuAssert(self, "entry before expected entries has been written to!",
		tblbuf[0] == 0);
	CuAssert(self, "entry following expected entries has been written to!",
		tblbuf[1 + wbuf_len % chnl.gran_write] == 0);
}

typedef void (*suite_cfg_cb)(CuSuite *suite);

void IdentifySuite(CuSuite *suite)
{
	SUITE_ADD_TEST(suite, test_format_ns);
	SUITE_ADD_TEST(suite, test_identify);
	SUITE_ADD_TEST(suite, test_identify_channel);
	SUITE_ADD_TEST(suite, test_get_features);
	SUITE_ADD_TEST(suite, test_set_responsibility);
	SUITE_ADD_TEST(suite, test_write_lba);
	SUITE_ADD_TEST(suite, test_erase_sync);
	SUITE_ADD_TEST(suite, test_erase_async);
	SUITE_ADD_TEST(suite, test_p2l_tbl);

	suite->setup = test_setup;
	suite->teardown = test_teardown;
}

void run_all_tests(suite_cfg_cb suite_cfg)
{
	CuSuite *suite = CuSuiteNew();
	CuString *output = CuStringNew();
	suite_cfg(suite);

	CuSuiteRun(suite);
	CuSuiteSummary(suite, output);
	CuSuiteDetails(suite, output);
	fprintf(stderr, "%s\n", output->buffer);
	CuStringDelete(output);
	CuSuiteDelete(suite);
}

int main(int argc, char **argv)
{
	fprintf(stderr, "\n\n\nFailing tests CAN alter expected "
		"device state - run once per boot!\n");
	run_all_tests(IdentifySuite);
	return 0;
}
