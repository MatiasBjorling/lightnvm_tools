#ifndef __LNVMEKV_H
#define __LNVMEKV_H

#include <stdint.h>
#include <stddef.h>
#include <linux/ioctl.h>

#define PACKED __attribute__((packed))

enum VslKvCommands {
	VSL_KV_GET	= 0x00,
	VSL_KV_PUT	= 0x01,
	VSL_KV_UPDATE	= 0x02,
	VSL_KV_DEL	= 0x03,
};

struct PACKED vsl_cmd_kv {
	uint8_t	opcode;
	uint8_t	res[3];
	uint16_t	key_len;
	uint16_t	val_len;
	uint64_t	key_addr;
	uint64_t	val_addr;
};

#define VSL_IOC_MAGIC 'O'
#define VSL_IOCTL_ID		_IO(VSL_IOC_MAGIC, 0x40)
#define VSL_IOCTL_KV		_IOWR(VSL_IOC_MAGIC, 0x40, struct vsl_cmd_kv)

enum VslErr {
	VSLKV_ERR_OPEN	=	1,
	VSLKV_ERR_IOCTL,
	
};

struct vslkv_ctx;
typedef struct vslkv_ctx vslkv_ctx;

void *vslkv_get(vslkv_ctx *ctx, void *key, size_t klen);
int vslkv_put(vslkv_ctx *ctx, void *key, size_t klen, void *val, size_t vlen);
int vslkv_update(vslkv_ctx *ctx, void *key, size_t klen, void *val, size_t vlen);
int vslkv_del(vslkv_ctx *ctx, void *key, size_t klen);

vslkv_ctx *vslkv_open(char *dev);
void vslkv_close(vslkv_ctx *ctx);

#endif // __LNVMEKV_H
