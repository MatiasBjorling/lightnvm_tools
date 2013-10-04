#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#define PAGE_SIZE (4096)

int test_latency_simple()
{
	return 0;
}

int test_swap_simple()
{
	return 0;
}

int main(int argc, char *argv[])
{
	int i, ret, max, fd, page_offset;
	static char buf[PAGE_SIZE] __attribute__ ((__aligned__ (4096)));

	if (argc <= 1) {
		perror("Not enough arguments. ./simple blkdev\n");
		return -1;
	}

	fd = open(argv[1], O_RDWR | O_DIRECT);

	if (fd < 0) {
		perror("Couldn't access the blkdev file");
		return -1;
	}

	max = 1000;
	unsigned ino = 1;
	int values[max];
	for(i=0; i<max; i++) values[i] = 0;
#if 1
	for(i=0; i<max; i++) {
		page_offset = random() % (1<<10);
		page_offset = i % 512;
		if(i%100 == 0) printf("wrote=%d\n", i);
#if 0
		if(i%2==0) {
			// only first write is identified
			fc  = FC_EMPTY;
			if(i==0) {
				fc  = FC_DB_INDEX;
			}

			memset(&hint_data, 0, sizeof(hint_data_t));
			CAST_TO_PAYLOAD(&hint_data)->is_write = 1;
			CAST_TO_PAYLOAD(&hint_data)->hint_flags |= HINT_LATENCY;
			CAST_TO_PAYLOAD(&hint_data)->count = 1;
			INO_HINT_SET(&hint_data, 0, ino, page_offset, 1, fc);

			//printf("hint latency to one PAGE=%u\n", page_offset);
			assert(!ioctl(fd, OPENSSD_IOCTL_SUBMIT_HINT, &hint_data));
		}
#endif
		values[page_offset] = ((int*)buf)[0] = i;
		printf("%d) write latency to one page=%u (buf[0]=%d)\n", i, page_offset, ((int*)buf)[0]);
		if(pwrite(fd, buf, PAGE_SIZE, page_offset*PAGE_SIZE) != PAGE_SIZE) {
			perror("pwrite");
			printf("i=%d page_offset=%d\n", i, page_offset);
			return -1;
		}
		//sync(fd);
	}
#endif
#if 0
	//assert(!close(fd));
	//static char buf1[PAGE_SIZE] __attribute__ ((__aligned__ (4096)));
	//fd = open("/dev/mapper/dm2", O_RDWR | O_DIRECT );
	printf("sleeping for GC...\n");
	sleep(3);
	//return 0;
	printf("now reading\n");
	//max = 512;
	for(i=0; i<max; i++) {
//       for(i=0;i<max;i++){
		//page_offset = random() % (1<<10);
		page_offset = i % 512;//random() % 512;
		if(i%100 == 0) printf("read=%d\n", i);
		printf("%d) read one page=%u\n", i, page_offset);
		if(pread(fd, buf, PAGE_SIZE, page_offset*PAGE_SIZE) != PAGE_SIZE) {
			perror("pread");
			printf("i=%d\n", i);
			return -1;
		}
		//printf("read page_offset %d buf[0]=%d\n", page_offset, ((int*)buf)[0]);
		if(values[page_offset] != ((int*)buf)[0]) {
			printf("%d) read page_offset=%d expected %d buf[0]=%d\n", i, page_offset, values[page_offset], ((int*)buf)[0]);
			assert(0);
		}
		sync(fd);
	}
#endif
	assert(!close(fd));
	return 0;
}
