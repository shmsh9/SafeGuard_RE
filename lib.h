#ifndef _LIB_SGE
#define _LIB_SGE
#define PHEX(X) \
	printf("%s:\n", #X); \
	for(int i = 0; i < sizeof(X)/sizeof(X[0]); i++){ \
		printf("%02X ", X[i]); \
        if ((i + 1) % 8 == 0) printf("\n"); \
	} \
	printf("\n");

void dosdatefmt(char dst[20], uint16_t time, uint16_t date){
	static_assert(sizeof("16:01:00 16/06/2025") == 20);
	dst[19] = 0;
	sprintf(dst,
		"%02d:%02d:%02d %02d/%02d/%04d",
		time >> 11 & 0x1f,
		time >> 5 & 0x3f,
		(time & 0x1f) * 2,
		date & 0x1f,
		date >> 5 & 0x0f,
		(date >> 9 & 0x7f) + 1980
	);
}
struct __attribute__((__packed__)) _user_entry {
	char username[0x10];      // [0..0x0f]
	uint8_t unknown_0[2];     // [0x10..0x11]
	uint16_t unknown_word;    // [0x12] 0100:3780
	uint16_t timestamp_time;  // [0x14] 0100:37ad
	uint16_t timestamp_date;  // [0x16] 0100:37aa
	uint8_t unknown[2];       // [0x17..0x19]
	uint16_t syscall_0x11_dx; // [0x1a] 0100:3879
	uint16_t syscall_0x11_cx; // [0x1c] 0100:3876
};

struct __attribute__((__packed__)) user_entry {
	struct _user_entry entry;
	uint8_t b[0x60-sizeof(struct _user_entry)];
};
void print_user_entry(struct user_entry *user){
	char datebuff[20] = {0};	
	dosdatefmt(
		datebuff,
		user->entry.timestamp_time,
		user->entry.timestamp_date
	);
	printf(
		"\"user\" : {\n"
		"  \"name\": \"%s\",\n"
		"  \"unknown_0\": [0x%02X, 0x%02X],\n"
		"  \"timestamp\": \"%s\",\n"
		"  \"unknown\": [0x%02X, 0x%02X],\n"
		"  \"0x1a\": %04X,\n"
		"  \"0x1c\": %04X\n"
		"}\n",
		(char*)user->entry.username,
		user->entry.unknown_0[0],user->entry.unknown_0[1],
		datebuff,
		user->entry.unknown[0],user->entry.unknown[1],
		user->entry.syscall_0x11_dx,
		user->entry.syscall_0x11_cx
	);
}
#endif

