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

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#include <linux/byteorder/little_endian.h>
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#include <linux/byteorder/big_endian.h>
#endif

//Constants
#define LVER		1
#define LNVME_TYPE	0
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
	uint8_t	unused[4034];
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

enum lnvme_admin_opcode {
	lnvme_admin_identify		= 0xc0,
	lnvme_admin_identify_channel	= 0xc1,
	lnvme_admin_get_features	= 0xc2,
	lnvme_admin_set_responsibility	= 0xc3,
	lnvme_admin_get_l2p_tbl	= 0xc4,
	lnvme_admin_get_p2l_tbl	= 0xc5,
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

#define BITS_TO_BYTES(x) ((x) >> 3)
#define NVME_IOCTL_ADMIN_CMD _IOWR('N', 0x41, struct nvme_admin_cmd)
#define LNVME_IOCTL_TST _IO('N', 0x43)
#define LNVME_DEV "/dev/nvme0n1"

#define TEST(n) void test_##n(CuTest *self)

struct nvme_admin_cmd *alloc_ioctl_cmd(size_t data_len)
{
	struct nvme_admin_cmd *cmd;
	cmd = calloc(1, sizeof(struct nvme_admin_cmd) + data_len);
	if (!cmd) {
		return NULL;
	}
	cmd->addr = (uint64_t)cmd + 1;
	cmd->data_len = data_len;
	return cmd;
}

uint8_t __get_feature(uint64_t *features, uint32_t ndx)
{
	return (uint8_t)(features[(ndx >> 6)] & (1 << (ndx & 63)));
}

TEST(identify_retval)
{
	long ret;
	int fd;
	printf("id retval\n");
	errno = 0;
	fd = open(LNVME_DEV, O_RDONLY);
	CuAssertTrue(self, fd != -1);
	ret = ioctl(fd, LNVME_IOCTL_TST, 0);
	close(fd);
	CuAssertTrue(self, ret >= 0);
}

TEST(identify)
{
	long ret;
	int fd;
	struct lnvme_id *id = NULL;
	struct nvme_admin_cmd *cmd = NULL;

	fd = open(LNVME_DEV, O_RDONLY);
	CuAssertTrue(self, fd != -1);

	cmd = alloc_ioctl_cmd(sizeof(struct lnvme_id));
	CuAssertTrue(self, cmd != NULL);
	id = (void*)cmd->addr;
	cmd->opcode = lnvme_admin_identify;
	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
	close(fd);

	CuAssertTrue(self, ret >= 0);
	CuAssertTrue(self, __le16_to_cpu(id->ver_id) == LVER);
	CuAssertTrue(self, id->nvm_type == LNVME_TYPE);

	free(cmd);
}

TEST(identify_channel)
{
	long ret;
	int fd;
	struct nvme_admin_cmd *cmd = NULL;
	struct lnvme_id_chnl *chnl = NULL;

	fd = open(LNVME_DEV, O_RDONLY);
	CuAssertTrue(self, fd != -1);

	cmd = alloc_ioctl_cmd(sizeof(struct lnvme_id_chnl));
	CuAssertTrue(self, cmd != NULL);
	chnl = (void*)cmd->addr;
	cmd->opcode = lnvme_admin_identify_channel;
	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
	close(fd);

	CuAssertTrue(self, ret >= 0);
	CuAssertTrue(self, __le64_to_cpu(chnl->queue_size) == QUEUE_SIZE);
	CuAssertTrue(self, __le64_to_cpu(chnl->gran_read) == GRAN_READ);
	CuAssertTrue(self, __le64_to_cpu(chnl->gran_write) == GRAN_WRITE);
	CuAssertTrue(self, __le64_to_cpu(chnl->gran_erase) == GRAN_ERASE);
	CuAssertTrue(self, __le64_to_cpu(chnl->oob_size) == OOB_SIZE);
	CuAssertTrue(self, __le32_to_cpu(chnl->t_r) == T_R);
	CuAssertTrue(self, __le32_to_cpu(chnl->t_sqr) == T_SQR);
	CuAssertTrue(self, __le32_to_cpu(chnl->t_w) == T_W);
	CuAssertTrue(self, __le32_to_cpu(chnl->t_sqw) == T_SQW);
	CuAssertTrue(self, __le32_to_cpu(chnl->t_e) == T_E);
	CuAssertTrue(self, chnl->io_sched == IOSCHED_CHNL);

	free(cmd);
}

TEST(get_features)
{
	long ret;
	int fd;
	struct nvme_admin_cmd *cmd = NULL;
	uint64_t *resp = NULL;

	fd = open(LNVME_DEV, O_RDONLY);
	CuAssertTrue(self, fd != -1);

	cmd = alloc_ioctl_cmd(BITS_TO_BYTES(512));
	CuAssertTrue(self, cmd != NULL);
	resp = (uint64_t*)cmd->addr;
	cmd->opcode = lnvme_admin_get_features;
	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
	close(fd);

	CuAssertTrue(self, ret >= 0);

	CuAssertTrue(self, !__get_feature(resp, R_L2P_MAPPING));
	CuAssertTrue(self,! __get_feature(resp, R_P2L_MAPPING));
	CuAssertTrue(self, __get_feature(resp, R_ECC));
	CuAssertTrue(self, __get_feature(resp, R_GC));
	CuAssertTrue(self, !__get_feature(resp, E_BLK_MOVE));
	CuAssertTrue(self, !__get_feature(resp, E_NVM_COPY_BACK));
	CuAssertTrue(self, !__get_feature(resp, E_SAFE_SHUTDOWN));
	
	free(cmd);
}

TEST(set_features)
{
	long ret;
	int fd;
	struct nvme_admin_cmd *cmd_w, *cmd_r = NULL;
	uint64_t *resp;
	
	fd = open(LNVME_DEV, O_RDONLY);
	CuAssertTrue(self, fd != -1);

	cmd_w = alloc_ioctl_cmd(0);
	CuAssertTrue(self, cmd_w != NULL);
	cmd_r = alloc_ioctl_cmd(BITS_TO_BYTES(512));
	CuAssertTrue(self, cmd_r != NULL);

	cmd_w->opcode = lnvme_admin_set_responsibility;
	cmd_w->cdw10 = R_ECC;
	cmd_w->cdw11 = 0;
	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd_w);
	CuAssertTrue(self, ret >= 0);
	free(cmd_w);

	cmd_r->opcode = lnvme_admin_get_features;
	resp = (uint64_t*)cmd_r->addr;
	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd_r);
	close(fd);
	CuAssertTrue(self, ret >= 0);
	CuAssertTrue(self, !__get_feature(resp, R_ECC));
	
	free(cmd_r);
}

TEST(WRITE_W_LBA)
{
	/*
	long ret;
	int fd;
	struct nvme_admin_cmd *cmd_w = NULL, *cmd_r = NULL;

	fd = open(LNVME_DEV, O_RDONLY);
	CuAssertTrue(self, fd != - 1);

	cmd_w = alloc_ioctl_cmd(12288);
	cmd_r = alloc_ioctl_cmd(12888);
	CuAssertTrue(self, cmd_w != NULL);
	CuAssertTrue(self, cmd_r != NULL);

	cmd_w->opcode = lnvme_
	*/
}

CuSuite *IdentifySuite()
{
	CuSuite *suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, test_identify_retval);
	SUITE_ADD_TEST(suite, test_identify);
	SUITE_ADD_TEST(suite, test_identify_channel);
	SUITE_ADD_TEST(suite, test_get_features);
	SUITE_ADD_TEST(suite, test_set_features);
	return suite;
}

typedef void (*suite_cb)(CuSuite *);

void add_suites(CuSuite *suite)
{
	CuSuiteAddSuite(suite, IdentifySuite());
}

void run_all_tests(suite_cb fn)
{
	CuSuite *suite = CuSuiteNew();
	CuString *output = CuStringNew();

	//CuSuiteAddSuite(suite, CuGetSuite());
	fn(suite);

	CuSuiteRun(suite);
	CuSuiteSummary(suite, output);
	CuSuiteDetails(suite, output);
	printf("-- %s\n", output->buffer);

	CuStringDelete(output);
	CuSuiteDelete(suite);
}


int main(int argc, char **argv)
{
	run_all_tests(add_suites);
	/*
	long ret;
	int fd;
	errno = 0;
	fprintf(stderr, "Opening (%s) for IOCTL.\n", LNVME_DEV);
	fd = open(LNVME_DEV, O_RDONLY);
	check_err(ret);
	ret = ioctl(fd, LNVME_IOCTL_TST, 0);
	check_err(ret);
	close(fd);
	*/
	return 0;
}
