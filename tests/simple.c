#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include "drivers/md/dm-openssd.h"
#include "drivers/md/dm-openssd-hint.h"

#define PAGE_SIZE (4096)
#define DISPLAY(...)         fprintf(stderr, __VA_ARGS__)
#define VDISPLAY(...)        if (verbose) fprintf(stderr, __VA_ARGS__)

#define OP_READ  0
#define OP_WRITE 1

int verbose = 0;

int badusage(char* msg)
{
	DISPLAY("Incorrect parameters. %s\n", msg);
	exit(1);
}

int usage_advanced()
{
	DISPLAY( "\n");
	DISPLAY( "Possible arguments :\n");
	DISPLAY( " -V     : verbose mode\n");
	DISPLAY( " -v     : verbose mode\n");
	DISPLAY( " -d     : device name\n");
	DISPLAY( " -i#    : number of reads/writes\n");
	DISPLAY( " -m     : mixed reads/writes\n");
	DISPLAY( " -w     : do writes\n");
	DISPLAY( " -r     : do reads\n");
	DISPLAY( " -l     : send latency hints for writes\n");
	DISPLAY( " -s     : send swap hints for writes\n");
	DISPLAY( " -p#    : send pack hints for writes, for given number of inodes\n");
	DISPLAY( " -z     : random offsets\n");
	DISPLAY( " -x#    : maximum offset\n");
	DISPLAY( " -f     : fanatic mode (only in non-mixed, sequential accesses\n");

	return 0;
}


void set_hint(struct hint_payload *d, int hint_type, unsigned ino,
				int page_offset, enum fclass fc, int is_write)
{
	memset(d, 0, sizeof(struct hint_payload));
	d->is_write = is_write;
	d->flags |= hint_type;

	d->ino.ino = ino;
	d->ino.start_lba = page_offset;
	d->ino.count = 1;
	d->ino.fc = fc;
}

void do_op(int is_write, int fd, char* buf, int page_offset, int i)
{
	int ret;

	VDISPLAY("%d) %s to one page=%u (buf[0]=%d)\n", 
		i, (is_write == OP_WRITE)? " write" : "read", 
		page_offset, ((int*)buf)[0]);

	if (is_write)
		ret = pwrite(fd, buf, PAGE_SIZE, page_offset * PAGE_SIZE);
	else
		ret = pread(fd, buf, PAGE_SIZE, page_offset * PAGE_SIZE);

	if (ret != PAGE_SIZE) {
		perror((is_write)? "pwrite" : "pread");
		DISPLAY("i=%d page_offset=%d\n", i, page_offset);
		exit(-1);
	}
}

int get_offset(int is_random, int i, int max)
{
	if (is_random)
		return random() % max;

	return i % max;
}

int main(int argc, char** argv){
	static char buf[PAGE_SIZE] __attribute__ ((__aligned__ (4096))); 
	char device[128] = "/dev/mapper/dm2";
	struct hint_payload d;
	unsigned ino = 1;
	int page_offset, fd, i;
	int *values;
	enum fclass fc;

	int mixed = 0, rd = 0, wr = 0, fanatic = 0, is_random = 0, inodes = 1;
	int iterations = 1000, max_offset = 0;
	int hint_type = -1;

	if (argc < 2){
		usage_advanced();
		exit(-1);
	}

	for(i = 1; i < argc; i++){
		char* argument = argv[i];

		if (!argument)
			continue;

		// Decode command (note : aggregated commands are allowed)
		if (argument[0]=='-')
		{
			switch(argument[1])
			{
				// Get device name
				case 'd':
					if (sscanf (&argument[2], "%s", device)!=1) {
						DISPLAY ("error - what follows -d is not a string");
						exit(-1);	
					}
					break;
				// Display help
				case 'h': 
				case 'H': usage_advanced(); return 0;
				// latency
				case 'l': hint_type = HINT_LATENCY;break;

				// swap
				case 's': hint_type = HINT_SWAP; break;

				// swap
				case 'p': 
					hint_type = HINT_PACK; 
					if (sscanf (&argument[2], "%i", &inodes)!=1) {
						inodes = 1;
					}
					DISPLAY("pack %d inodes\n", inodes);
					break;

				// mixed workload
				case 'm': mixed=1;wr=1;rd=1;break;

				// do reads
				case 'r': rd=1; break;

				// do writes
				case 'w': wr=1; break;

				// verbose mode
				case 'v': 
				case 'V': verbose=1; break;

				// fanatic mode
				case 'f': fanatic=1;break;

				// max offset
				case 'x':
					if (sscanf (&argument[2], "%i", &max_offset)!=1) {
						DISPLAY ("error - what follows -x is not an integer");
						exit(-1);	
					} 
					break;
				// random offset
				case 'z': is_random = 1; break;
	
				// number of reads/writes
				case 'i':
					if (sscanf (&argument[2], "%i", &iterations)!=1) {
						DISPLAY ("error - what follows -i is not an integer");
						exit(-1);	
					} 
					break;

				// unrecognised command
				default : badusage(argument); exit(-1);
			}
		}
	}

	DISPLAY("mixed=%d", mixed);

	// sanity fanatic
	if (fanatic && iterations > 50000000){
		DISPLAY("can't be fanatic with more than 50M writes\n");
		exit(1);
	}

	// assert open
	fd = open(device, O_RDWR | O_DIRECT );
	if (fd < 0) {
		perror("open");
		return -1;
	}

	if (max_offset==0 || max_offset >= lseek(fd, 0, SEEK_END) / PAGE_SIZE)
		max_offset = lseek(fd, 0, SEEK_END) / PAGE_SIZE;

	if (fanatic) {
		values = (int*)malloc(sizeof(int)*max_offset);
		assert(values);
		for(i = 0; i < max_offset; i++)
			values[i] = 0;
	}

	if (!wr) {
		if (!rd) {
			badusage("no reads or writes specified"); 
			exit(-1);
		}

		goto do_reads;
	}

	assert(inodes >= 1 && inodes < 99);
	int hinted[100] = {};
	ino = 0;
	
	for (i = 0; i < iterations; i++) {
		page_offset = get_offset(is_random, i, max_offset);
		if (i % 100 == 0)
			DISPLAY("wrote=%d\n", i);

		// only first write is identified for latency hint
		// TODO: also for slow/fast files
		if (hint_type > -1) {
			if (is_random)
				ino = rand() % (inodes + 1);
			else
				ino = (ino+1) % (inodes + 1);

			fc  = FC_EMPTY;
			if (hint_type == HINT_LATENCY && i == 0){
				fc = FC_DB_INDEX;
			}
			else if (hint_type == HINT_PACK && hinted[ino] == 0) {
				hinted[ino] = 1;
				fc = FC_VIDEO_SLOW;
			}

			// hint with varying inode number
			if (ino) {
				set_hint(&d, hint_type, ino, page_offset, fc, OP_WRITE);
				VDISPLAY("hint to one PAGE=%u ino=%d\n", page_offset, ino);
				assert(!ioctl(fd, LIGHTNVM_IOCTL_SUBMIT_HINT, &d));
			}
		}

		if (fanatic)
			values[page_offset] = ((int*)buf)[0] = i;

		do_op(OP_WRITE, fd, buf, page_offset, i);

		if (!mixed)
			continue;

		// random, no point in reading what we've just written
		page_offset = get_offset(1, i, max_offset); 
		do_op(OP_READ, fd, buf, page_offset, i);
        }
	
	DISPLAY("all written\n");

	if (!rd || mixed){
		assert(!close(fd));
		DISPLAY("test done\n");
		return 0;
	}
	DISPLAY("sleeping, to allow GC to kick in...\n");
	sleep(10);
do_reads:
	DISPLAY("now reading\n");

        for(i=0;i<iterations;i++){
		page_offset = get_offset(1, i, max_offset);

		if (i % 100 == 0)
			DISPLAY("read=%d\n", i);

		if (verbose)
			DISPLAY("%d) read one page=%u\n", i, page_offset);

		do_op(OP_READ, fd, buf, page_offset, i);

		if (fanatic && values[page_offset] != ((int*)buf)[0]) {
			DISPLAY("%d) read page_offset=%d expected %d buf[0]=%d\n", i, page_offset, values[page_offset], ((int*)buf)[0]);
			assert(0);
		}
	}

	DISPLAY("all read\n");
	assert(!close(fd));
	DISPLAY("test done\n");
        return 0;
}
