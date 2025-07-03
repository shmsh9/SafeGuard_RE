#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

static inline uint8_t ror8(uint8_t value, uint8_t count) {
    count &= 7;  // mask to 0-7 bits
    return (value >> count) | (value << (8 - count));
}

void modify_username(uint8_t ptr[0x24]) {
    uint8_t CH = 0;  // corresponds to the CH register, loop counter

    while (CH < 0x24) {  // 36 iterations
        ptr[0] = ptr[0] + CH;       // ADD byte ptr [SI], CH
        uint8_t CL = CH & 0x7;      // AND CL, 7
        ptr[0] = ror8(ptr[0], CL);  // ROR byte ptr [SI], CL

        CH++;      // INC CH
        ptr++;     // INC SI (move pointer to next byte)
    }
}

uint16_t derive_ax_from_bx(uint16_t bx) {
    uint16_t ax, dx, si, di, cx, bp;

    if (bx <= 1) {
        return bx;
    }

    ax = 1;
    dx = ax;
    si = ax;

    // Equivalent to: AX = 1 / BX (16-bit division: DX:AX / BX)
    uint32_t dividend = ((uint32_t)dx << 16) | ax;
    ax = dividend / bx;
    dx = dividend % bx;

    if (dx == si) {
        // Equivalent to: AX = -(AX) + 1
        ax = -ax + 1;
        return ax;
    }

    cx = dx;
    di = ax;

    while (1) {
        // AX = BX; DX = 0; AX = BX / CX
        ax = bx;
        dx = 0;
        dividend = ((uint32_t)dx << 16) | ax;
        ax = dividend / cx;
        dx = dividend % cx;
        bp = ax;
        bx = dx;

        // Multiply DI * BP, add to SI
        ax = di;
        ax *= bp;
        si += ax;

        if (bx == 1) {
            return si;
        }

        // AX = CX; DX = 0; AX = CX / BX
        ax = cx;
        dx = 0;
        dividend = ((uint32_t)dx << 16) | ax;
        ax = dividend / bx;
        dx = dividend % bx;
        bp = ax;
        cx = dx;

        // Multiply SI * BP, add to DI
        ax = si;
        ax *= bp;
        di += ax;

        if (cx == 1) {
            ax = -di + 1;
            return ax;
        }
    }
}
void store_ax_after_transformation_in(const uint16_t *buffer_base, uint16_t *output) {
    const uint16_t *buffer = buffer_base + 0x2E; // SI + 0x5C => word offset is 0x2E
    int i;

    // First batch
    *output++ = derive_ax_from_bx(buffer[2]);            // [SI + 0x04]
    *output++ = (uint16_t)(-((int16_t)buffer[3]));        // [SI + 0x06]
    *output++ = (uint16_t)(-((int16_t)buffer[4]));        // [SI + 0x08]
    *output++ = derive_ax_from_bx(buffer[5]);            // [SI + 0x0A]
    *output++ = buffer[0];                               // [SI]
    *output++ = buffer[1];                               // [SI + 0x02]

    // Loop for 7 times
    for (i = 0; i < 7; ++i) {
        buffer -= 6; // SI -= 0x0C (6 words)

        *output++ = derive_ax_from_bx(buffer[2]);         // [SI + 0x04]
        *output++ = (uint16_t)(-((int16_t)buffer[4]));     // [SI + 0x08]
        *output++ = (uint16_t)(-((int16_t)buffer[3]));     // [SI + 0x06]
        *output++ = derive_ax_from_bx(buffer[5]);         // [SI + 0x0A]
        *output++ = buffer[0];                            // [SI]
        *output++ = buffer[1];                            // [SI + 0x02]
    }

    // Final batch (original SI)
    const uint16_t *final = buffer_base;

    *output++ = derive_ax_from_bx(final[0]);              // [SI]
    *output++ = (uint16_t)(-((int16_t)final[1]));          // [SI + 0x02]
    *output++ = (uint16_t)(-((int16_t)final[2]));          // [SI + 0x04]
    *output++ = derive_ax_from_bx(final[3]);              // [SI + 0x06]
}

void create_DL_bytes_buff_from_input(
    const uint8_t* src,
    uint8_t* dest,
    uint8_t dl,     // desired length (buffer size)
    uint8_t cl,     // actual string length (source length)
    uint8_t ah_flag // AH register flag from asm
) {
    uint8_t si = 0; // source index
    uint8_t di = 0; // destination index

    int8_t special_byte = -(int8_t)cl; // -CL as signed byte

    if (cl >= dl) {
        // If input length >= buffer length, copy only dl bytes from src
        for (di = 0; di < dl; di++) {
            dest[di] = src[di];
        }
        return;
    }

    if (ah_flag == 0) {
        // AH == 0: Copy source bytes once into dest, then write special_byte,
        // then repeatedly cycle source bytes until buffer full.

        // Step 1: Copy src bytes to dest
        for (di = 0; di < cl; di++) {
            dest[di] = src[di];
        }

        // Step 2: Write special_byte
        dest[di++] = (uint8_t)special_byte;

        // Step 3: Fill remaining buffer cycling through src bytes again
        while (di < dl) {
            dest[di++] = src[si++];
            if (si >= cl) si = 0;
        }
    } else {
        // AH != 0: This looks like continuous cyclic copy of source bytes only
        while (di < dl) {
            dest[di++] = src[si++];
            if (si >= cl) si = 0;
        }
    }
}

static bool parity_even(uint8_t x) {
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return !(x & 1);
}

uint16_t derive_bx(uint16_t bx) {
    int cx = 8;
    bool carry = false;

    while (cx--) {
        uint8_t bh = (bx >> 8) & 0xFF;
        uint8_t bl = bx & 0xFF;

        uint8_t test_val = bl & 0x16;
        carry = false; // CLC

        if ((bh & 0x80) == 0) {
            // BH bit7 cleared
            if (!parity_even(test_val)) { // parity odd
                carry = true; // STC
            }
        } else {
            // BH bit7 set
            if (parity_even(test_val)) { // parity even
                carry = true; // STC
            }
        }

        // RCL BX,1 (rotate BX left through carry)
        bool new_carry = (bx & 0x8000) != 0;
        bx = ((bx << 1) & 0xFFFF) | (carry ? 1 : 0);
        carry = new_carry;
    }

    return bx;
}


void hashing_username(uint8_t *input, uint16_t input_l, uint8_t *output, uint16_t *bx) {
    int outer_loops = 8;
    int i;
    for (int outer = 0; outer < outer_loops; outer++) {
        uint8_t first = *input;
        int carry = (first & 0x80) ? 1 : 0;
        *input = (first << 1) | carry;

        if (carry) {
            uint8_t carry_out = 0;
            for (i = 0; i < 16; i++) {
                *bx = derive_bx(*bx);
                uint8_t bl = *bx & 0xFF;
                uint16_t sum = output[i] + bl + carry_out;
                output[i] = (uint8_t)sum;
                carry_out = (sum > 0xFF) ? 1 : 0;
            }
        } else {
            for (i = 0; i < 16; i++) {
                *bx = derive_bx(*bx);
            }
        }
    }
}
void syscall_0x16_wirite_derived_0x34(uint16_t* buf) {
    uint16_t dx = 8;

    while (dx < 0x34) {
        uint8_t dl = (uint8_t)(dx & 0xFF);

        // Calculate BL after subtraction and test
        int16_t bl = dl - 7;
        if ((bl & 7) == 0) {
            bl -= 8;
        }

        uint8_t bh = 0;
        uint16_t bx = ((uint16_t)bh << 8) | (uint8_t)bl;
        bx <<= 1;  // BX *= 2 (byte offset)

        // Load AX = word at buf[bx/2]
        uint16_t ax = buf[bx / 2];

        // Shift AX left by 9
        ax <<= 9;

        // Recalculate BL and BH
        bl = dl - 6;
        bh = bl & 0xFF;
        bh &= 7;

        if (bh <= 1) {
            bl -= 8;
        }

        bh = 0;
        bx = ((uint16_t)bh << 8) | (uint8_t)bl;
        bx <<= 1;

        // Load BX from buf at bx/2
        uint16_t tmp_bx = buf[bx / 2];

        // Shift BX right 7
        tmp_bx >>= 7;

        // OR AX and BX
        ax |= tmp_bx;

        // BX = DX * 2 (byte offset)
        bx = dx << 1;

        // Store AX back to buf at bx/2
        buf[bx / 2] = ax;

        dx++;
    }
}

static inline uint16_t read_le16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

// Helper: write 16-bit little-endian word to uint8_t pointer
static inline void write_le16(uint8_t* p, uint16_t val) {
    p[0] = val & 0xFF;
    p[1] = (val >> 8) & 0xFF;
}

static uint16_t special_mul_sub(uint16_t ax, uint16_t dx) {
    if (ax == 0 || dx == 0) {
        // NEG AX + 1 == (-AX) in 16-bit two's complement
        ax = (uint16_t)(-(int16_t)ax + 1);
        return ax;
    }

    uint32_t product = (uint32_t)ax * dx;
    uint16_t low = (uint16_t)(product & 0xFFFF);
    uint16_t high = (uint16_t)(product >> 16);

    // Simulate SUB low, high with borrow detection
    uint32_t sub = (uint32_t)low - high;
    uint16_t result = (uint16_t)(sub & 0xFFFF);

    // Borrow occurs if low < high
    uint16_t borrow = (low < high) ? 1 : 0;

    // ADC result, 0 means add borrow
    result += borrow;

    return result;
}

void do_bytes_rotation_1201(uint8_t* SI, uint8_t* DI) {
    int BP = 8;

    while (BP) {
        uint16_t AX = read_le16(DI + 6);
        uint16_t DX = read_le16(SI + 6);

        if (AX == 0) {
            AX = DX;
            AX = (uint16_t)(-(int16_t)AX + 1);
        } else if (DX == 0) {
            AX = (uint16_t)(-(int16_t)AX + 1);
        } else {
            AX = special_mul_sub(AX, DX);
        }
        write_le16(SI + 6, AX);

        uint16_t CX = AX;

        uint16_t BX = read_le16(DI + 2);
        uint16_t temp = read_le16(SI + 2);
        temp += BX;
        write_le16(SI + 2, temp);

        BX = read_le16(SI + 4);
        BX += read_le16(DI + 4);
        write_le16(SI + 4, BX);

        AX = read_le16(DI);
        DX = read_le16(SI);

        if (AX == 0) {
            AX = DX;
            AX = (uint16_t)(-(int16_t)AX + 1);
        } else if (DX == 0) {
            AX = (uint16_t)(-(int16_t)AX + 1);
        } else {
            AX = special_mul_sub(AX, DX);
        }
        write_le16(SI, AX);

        AX ^= BX;

        DX = read_le16(DI + 8);

        if (AX == 0) {
            AX = DX;
            AX = (uint16_t)(-(int16_t)AX + 1);
        } else if (DX == 0) {
            AX = (uint16_t)(-(int16_t)AX + 1);
        } else {
            AX = special_mul_sub(AX, DX);
        }

        CX ^= read_le16(SI + 2);

        // XCHG AX,CX:
        uint16_t tmp = AX;
        AX = CX;
        CX = tmp;

        AX += CX;

        DX = read_le16(DI + 10);

        if (AX == 0) {
            AX = DX;
            AX = (uint16_t)(-(int16_t)AX + 1);
        } else if (DX == 0) {
            AX = (uint16_t)(-(int16_t)AX + 1);
        } else {
            AX = special_mul_sub(AX, DX);
        }

        CX += AX;

        // XOR word ptr [SI], AX
        uint16_t si0 = read_le16(SI);
        si0 ^= AX;
        write_le16(SI, si0);

        // XOR word ptr [SI+6], CX
        uint16_t si6 = read_le16(SI + 6);
        si6 ^= CX;
        write_le16(SI + 6, si6);

        CX ^= read_le16(SI + 2);

        BX = read_le16(SI + 4);
        BX ^= AX;
        write_le16(SI + 2, BX);
        write_le16(SI + 4, CX);

        DI += 0xC;
        BP--;
    }

    // Final block outside the loop:
    uint16_t AX = read_le16(DI);
    uint16_t DX = read_le16(SI);

    if (AX == 0) {
        AX = DX;
        AX = (uint16_t)(-(int16_t)AX + 1);
    } else if (DX == 0) {
        AX = (uint16_t)(-(int16_t)AX + 1);
    } else {
        AX = special_mul_sub(AX, DX);
    }
    write_le16(SI, AX);

    uint16_t temp1 = read_le16(SI + 2);
    uint16_t temp2 = read_le16(SI + 4);

    temp1 += read_le16(DI + 4);
    temp2 += read_le16(DI + 2);

    write_le16(SI + 4, temp1);
    write_le16(SI + 2, temp2);

    AX = read_le16(DI + 6);
    DX = read_le16(SI + 6);

    if (AX == 0) {
        AX = DX;
        AX = (uint16_t)(-(int16_t)AX + 1);
    } else if (DX == 0) {
        AX = (uint16_t)(-(int16_t)AX + 1);
    } else {
        AX = special_mul_sub(AX, DX);
    }
    write_le16(SI + 6, AX);
}
#define PHEX(X) \
	printf("%s:\n", #X); \
	for(int i = 0; i < sizeof(X)/sizeof(X[0]); i++){ \
		printf("%02X ", X[i]); \
        if ((i + 1) % 8 == 0) printf("\n"); \
	} \
	printf("\n");

void dosdatefmt(char dst[20], uint16_t time, uint16_t date){
	static_assert(sizeof("16:01:00/16:06:2025") == 20);
	dst[19] = 0;
	sprintf(dst,
		"%02d:%02d:%02d/%02d:%02d:%04d",
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
	uint8_t unknown[3];       // [0x17..0x19]
	uint16_t syscall_0x10_dx; // [0x1a] 0100:3879
	uint16_t syscall_0x10_cx; // [0x1c] 0100:3876
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
		"  \"timestamp\": \"%s\"\n"
		"}\n",
		(char*)user->entry.username,
		datebuff
	);
}
uint8_t ascii_2_scancode[256] = {
    [' '] = 0x39,
    ['!'] = 0x02,   // ! is Shift+1
    ['"'] = 0x28,   // Shift+'
    ['#'] = 0x04,   // Shift+3
    ['$'] = 0x05,
    ['%'] = 0x06,
    ['&'] = 0x07,
    ['\''] = 0x28,
    ['('] = 0x09,
    [')'] = 0x0A,
    ['*'] = 0x0B,   // Shift+0
    ['+'] = 0x0D,   // Shift+=
    [','] = 0x33,
    ['-'] = 0x0C,
    ['.'] = 0x34,
    ['/'] = 0x35,
    ['0'] = 0x0B,
    ['1'] = 0x02,
    ['2'] = 0x03,
    ['3'] = 0x04,
    ['4'] = 0x05,
    ['5'] = 0x06,
    ['6'] = 0x07,
    ['7'] = 0x08,
    ['8'] = 0x09,
    ['9'] = 0x0A,
    [':'] = 0x27,   // Shift+;
    [';'] = 0x27,
    ['<'] = 0x33,   // Shift+,
    ['='] = 0x0D,
    ['>'] = 0x34,   // Shift+.
    ['?'] = 0x35,   // Shift+/
    ['@'] = 0x10,   // Shift+q
    ['['] = 0x1A,
    ['\\'] = 0x2B,
    [']'] = 0x1B,
    ['^'] = 0x08,   // Shift+7 (caret)
    ['_'] = 0x0C,   // Shift+-
    ['`'] = 0x29,
    ['{'] = 0x1A,   // Shift+[
    ['|'] = 0x2B,   // Shift+\
    ['}'] = 0x1B,   // Shift+]
    ['~'] = 0x29,   // Shift+`

    // Letters
    ['a'] = 0x1E, ['A'] = 0x1E,
    ['b'] = 0x30, ['B'] = 0x30,
    ['c'] = 0x2E, ['C'] = 0x2E,
    ['d'] = 0x20, ['D'] = 0x20,
    ['e'] = 0x12, ['E'] = 0x12,
    ['f'] = 0x21, ['F'] = 0x21,
    ['g'] = 0x22, ['G'] = 0x22,
    ['h'] = 0x23, ['H'] = 0x23,
    ['i'] = 0x17, ['I'] = 0x17,
    ['j'] = 0x24, ['J'] = 0x24,
    ['k'] = 0x25, ['K'] = 0x25,
    ['l'] = 0x26, ['L'] = 0x26,
    ['m'] = 0x32, ['M'] = 0x32,
    ['n'] = 0x31, ['N'] = 0x31,
    ['o'] = 0x18, ['O'] = 0x18,
    ['p'] = 0x19, ['P'] = 0x19,
    ['q'] = 0x10, ['Q'] = 0x10,
    ['r'] = 0x13, ['R'] = 0x13,
    ['s'] = 0x1F, ['S'] = 0x1F,
    ['t'] = 0x14, ['T'] = 0x14,
    ['u'] = 0x16, ['U'] = 0x16,
    ['v'] = 0x2F, ['V'] = 0x2F,
    ['w'] = 0x11, ['W'] = 0x11,
    ['x'] = 0x2D, ['X'] = 0x2D,
    ['y'] = 0x15, ['Y'] = 0x15,
    ['z'] = 0x2C, ['Z'] = 0x2C,
};
const uint8_t target_hash_1234[] = {
	0xC7, 0xA6, 0x54, 0x1B,
	0xE6, 0x16, 0x70, 0xF2,
	0x81, 0xB9, 0x8D, 0x31,
	0x58, 0xB4, 0x0D, 0xDC
};
const uint8_t target_hash[] ={
	0xB8, 0x1C, 0x29, 0x98,
	0xC1, 0x42, 0x04, 0x96,
	0x82, 0xA6, 0xD0, 0x99,
	0xA1, 0xF2, 0x3B, 0x9F
};
typedef struct {
    char **lines;
    int start;
    int end;
} thread_data_t;

// --- worker thread function ---
void *worker_thread(void *arg) {
    thread_data_t *td = (thread_data_t *)arg;

    for (int idx = td->start; idx < td->end; idx++) {
        char *orig = td->lines[idx];
        if (!orig) continue;

        char *line = strdup(orig);
        if (!line) continue;

        int strsz = (int)strlen(line);

        for (int i = 0; i < strsz; i++) {
            uint8_t ch = (uint8_t)line[i];
            line[i] = ascii_2_scancode[ch] | 0x80;
        }

        uint8_t extended_pass[0x10] = {0};
        create_DL_bytes_buff_from_input(
            (uint8_t *)line, extended_pass, sizeof(extended_pass), strsz, 0
        );

        uint8_t pass_hash[16] = {0};
        uint16_t bx = 0xc2d5;

        for (int i = 0; i < (int)sizeof(pass_hash); i++) {
            hashing_username(extended_pass + i, sizeof(pass_hash), pass_hash, &bx);
        }

        if (!memcmp(target_hash, pass_hash, sizeof(pass_hash))) {
            printf("[+] Found password: %s\n", orig);
        }

        free(line);
    }

    return NULL;
}

// --- main function ---
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s dictionary\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("fopen");
        return 1;
    }

    size_t capacity = 128;
    size_t count = 0;
    char **lines = malloc(capacity * sizeof(char *));
    if (!lines) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    char *line = NULL;
    size_t len = 0;

    while (getline(&line, &len, f) != -1) {
        if (count >= capacity) {
            capacity *= 2;
            char **tmp = realloc(lines, capacity * sizeof(char *));
            if (!tmp) {
                perror("realloc");
                break; // stop reading more lines
            }
            lines = tmp;
        }
        size_t linelen = strlen(line);
        if (linelen > 0 && line[linelen - 1] == '\n') {
            line[linelen - 1] = '\0'; // strip newline
        }
        lines[count] = strdup(line);
        if (!lines[count]) {
            perror("strdup");
            break;
        }
        count++;
    }
    free(line);
    fclose(f);

    if (count == 0) {
        fprintf(stderr, "No lines read from file.\n");
        free(lines);
        return 1;
    }

    // Detect number of CPU cores for threading
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus < 1) {
        num_cpus = 4; // fallback
    }
    int num_threads = (int)num_cpus;

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    thread_data_t *thread_data = malloc(num_threads * sizeof(thread_data_t));
    if (!threads || !thread_data) {
        perror("malloc threads");
        for (size_t i = 0; i < count; i++) free(lines[i]);
        free(lines);
        free(threads);
        free(thread_data);
        return 1;
    }

    int chunk = (count + num_threads - 1) / num_threads;
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].lines = lines;
        thread_data[i].start = i * chunk;
        thread_data[i].end = (i + 1) * chunk;
        if (thread_data[i].end > (int)count) thread_data[i].end = (int)count;
        pthread_create(&threads[i], NULL, worker_thread, &thread_data[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    for (size_t i = 0; i < count; i++) {
        free(lines[i]);
    }
    free(lines);
    free(threads);
    free(thread_data);

    return 0;
}

