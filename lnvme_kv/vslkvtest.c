#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "cheat.h"
#include "vslkv.h"

#define VSLKV_DEV "/dev/nvme0n1"

//Cheat continues evaluating a test until:
// a) segfault or similar forcefully terminates the test
// b) 'cheat_yield()' is called *AFTER* a failed assertion
#define REQUIRE_VALID_CTX do { \
	cheat_assert(ctx != NULL); \
	cheat_yield(); \
	} while(0);

CHEAT_DECLARE(
	vslkv_ctx *ctx;
)

CHEAT_SET_UP(
	errno = 0;
	ctx = vslkv_open(VSLKV_DEV);
	if (ctx == NULL) {
		switch (errno) {
		case -ENOMEM:
			fprintf(stderr, "setup: cannot create ctx (-ENOMEM)\n");
			break;
		case -VSLKV_ERR_OPEN:
			fprintf(stderr, "setup: cannot create ctx (-VSLKV_ERR_OPEN)\n");
			break;
		}
		cheat_yield();
	}
)

CHEAT_TEAR_DOWN(
	vslkv_close(ctx);
)

CHEAT_TEST(kv_put_test,
	int r;
	uint64_t key, val;

	REQUIRE_VALID_CTX

	key = 10;
	val = 20;
	fprintf(stderr, "vslkv_put, KV cmd id (%llx)\n", VSL_IOCTL_KV);
	//r = vslkv_put(ctx, &key, sizeof(uint64_t), &val, sizeof(uint64_t));
	r = vslkv_put(ctx, "hello", sizeof("hello"), "world", sizeof("world"));
	cheat_assert(r == 0);
)
