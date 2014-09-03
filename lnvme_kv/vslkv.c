#include "vslkv.h"

#include <stdio.h>
#include <inttypes.h>

#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <errno.h>
#include <string.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#include <linux/byteorder/little_endian.h>
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#include <linux/byteorder/big_endian.h>
#endif

#define PTR_ALIGN 8

typedef struct vslkv_ctx {
	int fd;
	size_t blk_siz;
	char *dev;
} vslkv_ctx;

static inline uint64_t pad_n_round(uint64_t addr)
{
	return (addr + sizeof(void*)) >> 3 << 3;
}

/**
 *	alloc_kv_cmd	-	allocate & initialise new VSL KV cmd
 *	@klen: length of key
 *	@vlen: length of value
 *
 *	Allocate vsl kv structure, setting aside sufficient memory
 *	for the key and value, initialising addr fields to their offsets
 */
static struct vsl_cmd_kv *cmdkv_new(size_t klen, size_t vlen)
{
	uint8_t *base = NULL;
	uint8_t pad_key = (sizeof(struct vsl_cmd_kv) % PTR_ALIGN);
	uint8_t pad_val = (klen % PTR_ALIGN);
	size_t cmd_siz;
	struct vsl_cmd_kv *kvcmd;

	fprintf(stderr, "cmdkv_new 1\n");
	fprintf(stderr, "cmdkv_new {cmd:%zu, klen:%zu, vlen:%zu}\n", sizeof(struct vsl_cmd_kv), klen, vlen);
	fprintf(stderr, "cmdkv_new {pad_key: %"SCNu8", pad_val:%"SCNu8"}\n", pad_key, pad_val);
	cmd_siz = sizeof(struct vsl_cmd_kv)
		+ (pad_key ? sizeof(void*) : 0)
		+ klen
		+ (pad_val ? sizeof(void*) : 0)
		+ vlen;

	fprintf(stderr, "cmdkv_new 2\n");
	fprintf(stderr, "cmdkv_new -- final siz: %zu\n", cmd_siz);
	base = calloc(1, cmd_siz);
	if (!base)
		return NULL;

	fprintf(stderr, "cmdkv_new 3\n");
	kvcmd = (struct vsl_cmd_kv *)base;
	kvcmd->key_len = klen;
	kvcmd->val_len = vlen;

	fprintf(stderr, "base addr x(%"SCNx64")\n", (uint64_t)base);
	fprintf(stderr, "base addr u(%"SCNu64")\n", (uint64_t)base);
	fprintf(stderr, "cmdkv_new 4\n");
	kvcmd->key_addr = ((uint64_t)base) + sizeof(struct vsl_cmd_kv);
	if (pad_key) {
		fprintf(stderr, "PAD_KEY!!!\n");
		fprintf(stderr, "key pre-pad x(%"SCNx64")\n", kvcmd->key_addr);
		fprintf(stderr, "key pre-pad u(%"SCNu64")\n", kvcmd->key_addr);
		fprintf(stderr, "tr(%"SCNu64")\n",
			(kvcmd->key_addr + sizeof(void*))
		);
		
		//kvcmd->key_addr = (kvcmd->key_addr + sizeof(void*));
		//kvcmd->key_addr = kvcmd->key_addr >> 3 << 3;
		kvcmd->key_addr = pad_n_round(kvcmd->key_addr);
		
		fprintf(stderr, "key post-pad x(%"SCNx64")\n", kvcmd->key_addr);
		fprintf(stderr, "key post-pad u(%"SCNu64")\n", kvcmd->key_addr);
	}
	fprintf(stderr, "cmdkv_new, key_addr{%"SCNx64"}, key_off{%"SCNu64"}\n",
		kvcmd->key_addr, kvcmd->key_addr - (uint64_t)base);

	fprintf(stderr, "cmdkv_new 5\n");
	kvcmd->val_addr = kvcmd->key_addr + kvcmd->key_len;
	if (pad_val) {
		fprintf(stderr, "PAD_VAL!!!!\n");
		kvcmd->val_addr = pad_n_round(kvcmd->val_addr);
	}
	fprintf(stderr, "cmdkv_new, val_addr{%"SCNx64"}, val_off{%"SCNu64"}\n",
		kvcmd->val_addr, kvcmd->val_addr - (uint64_t)base);
	fprintf(stderr,
		"\tbase: %"SCNu64"\n\t"
		"key:%"SCNu64"\n\t"
		"val:%"SCNu64"\n\n", (uint64_t)base, kvcmd->key_addr, kvcmd->val_addr);
	return kvcmd;
}

void *vslkv_get(vslkv_ctx *ctx, void *key, size_t klen)
{
	struct vsl_cmd_kv *c = NULL;
	int ret;
	
	c = cmdkv_new(klen, 0);
	if (!c) {
		errno = -ENOMEM;
		return NULL;
	}

	c->opcode = VSL_KV_GET;
	memcpy((void*)c->key_addr, key, klen);

	ret = ioctl(ctx->fd, VSL_IOCTL_KV, c);
	if (ret) {
		errno = -VSLKV_ERR_IOCTL;
		goto err_ioctl;
	}
	
	return c; /*brain fart -- I only need the value (if any)*/
err_ioctl:
	free(c);
	return NULL;
}

int vslkv_put(vslkv_ctx *ctx, void *key, size_t klen, void *val, size_t vlen)
{
	struct vsl_cmd_kv *c = NULL;
	int ret;

	fprintf(stderr, "put 1\n");

	c = cmdkv_new(klen, vlen);
	if (!c) {
		errno = -ENOMEM;
		return -1;
	}
	fprintf(stderr, "put 2\n");

	c->opcode = VSL_KV_PUT;
	memcpy((void*)c->key_addr, key, klen);
	memcpy((void*)c->val_addr, val, vlen);

	fprintf(stderr, "vslkv_put: issuing "
		"{key:%"SCNx64",klen:%"SCNu16", val:%"SCNx64", vlen:%"SCNu16"}\n",
		c->key_addr, c->key_len, c->val_addr, c->val_len);
	fprintf(stderr, "vslkv_put: key val {%s}\n", (char*)c->key_addr);

	ret = ioctl(ctx->fd, VSL_IOCTL_KV, c);
	if (ret) {
		errno = -VSLKV_ERR_IOCTL;
		ret = -1;
	}

	fprintf(stderr, "put 4\n");
	
	free(c);
	return ret;
}

int vslkv_update(vslkv_ctx *ctx, void *key, size_t klen, void *val, size_t vlen)
{
	struct vsl_cmd_kv *c = NULL;
	int ret;

	c = cmdkv_new(klen, vlen);
	if (!c) {
		errno = -ENOMEM;
		return -1;
	}

	c->opcode = VSL_KV_PUT;
	memcpy((void*)c->key_addr, key, klen);
	memcpy((void*)c->val_addr, val, vlen);

	ret = ioctl(ctx->fd, VSL_IOCTL_KV, c);
	if (ret) {
		errno = -VSLKV_ERR_IOCTL;
		ret = -1;
	}
	
	free(c);
	return ret;
}

int vslkv_del(vslkv_ctx *ctx, void *key, size_t klen)
{
	struct vsl_cmd_kv *c = NULL;
	int ret = 0;

	c = cmdkv_new(klen, 0);
	if (!c) {
		errno = -ENOMEM;
		return -1;
	}

	c->opcode = VSL_KV_DEL;
	memcpy((void*)c->key_addr, key, klen);

	ret = ioctl(ctx->fd, VSL_IOCTL_KV, c);
	if (ret) {
		errno = -VSLKV_ERR_IOCTL;
		ret = -1;
	}
	
	free(c);
	return ret;
}

vslkv_ctx *vslkv_open(char *dev)
{
	vslkv_ctx *ctx;
	
	ctx = calloc(1, sizeof(struct vslkv_ctx));
	if (!ctx) {
		fprintf(stderr, "cannot allocate ctx\n");
		errno = -ENOMEM;
		return NULL;
	}
	
	ctx->dev = calloc(1, strlen(dev));
	if (!ctx->dev) {
		fprintf(stderr, "cannot allocate dev str\n");
		errno = -ENOMEM;
		goto err_devalloc;
	}
	
	strcpy((char *)ctx->dev, dev);
	
	ctx->fd = open(dev, O_RDONLY);
	
	/*TODO: blk size should be queried through standardized VSL interface*/
	ctx->blk_siz = 2048;
	
	if (ctx->fd == -1) {
		fprintf(stderr, "failed to open blk dev\n");
		errno = -VSLKV_ERR_OPEN;
		goto err_open;
	}
	
	return ctx;
err_open:
	free(ctx->dev);
err_devalloc:
	free(ctx);
	return NULL;
}

void vslkv_close(vslkv_ctx *ctx)
{
	free(ctx->dev);
	close(ctx->fd);
	free(ctx);
}
