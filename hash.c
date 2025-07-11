#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "lib.h"
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
#define DERIVE_KEY2(K)({\
	key __ret_key = {0};\
	key_derivation2((uint16_t*)K, (uint16_t*)__ret_key);\
	__ret_key; \
})
void key_derivation2(const uint16_t *buffer_base, uint16_t *output) {
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
/*

*/
void prepare_hash_buff(const char *in, uint8_t out[16]){
	int l = strlen(in);
	const char *__s = in;
	for(int i = 0; i < 16; i++){
		if(i == l){
			out[i] = (uint8_t)-((uint8_t)l); 	
			__s = in;
			continue;
		}
		out[i] = *__s++;
	}
}
uint8_t* create_DL_bytes_buff_from_input(const uint8_t* input, uint8_t desired_len, uint8_t actual_len) {
    if (actual_len >= desired_len) {
        return NULL;
    }

    uint8_t* buffer = (uint8_t*)malloc(desired_len);
    if (!buffer) {
        return NULL;
    }

    uint8_t di = 0;

    memcpy(buffer, input, actual_len);
    di += actual_len;

    buffer[di++] = (uint8_t)(-((int8_t)actual_len));

    uint8_t si = 0;
    while (di < desired_len) {
        buffer[di++] = input[si++];
    }

    return buffer;
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
typedef uint8_t hash[16];
const uint16_t hash_username_seed = 0xb71d;
const uint16_t hash_password_seed = 0xc2d5;
#define HASH_PASSWORD(P) ({ \
	\
})
#define HASH_USERNAME(U) ({\
	hash __hash_ret = {0};\
	hash __tmp = {0};\
	prepare_hash_buff(U, __tmp);\
	uint16_t hash_seed = hash_username_seed;\
	for(int i = 0; i < sizeof(__hash_ret); i++){\
		_hash(__tmp+i, 0x10, __hash_ret, &hash_seed);\
	}\
	__hash_ret;\
})
void _hash(uint8_t *input, uint16_t input_l, uint8_t *output, uint16_t *bx) {
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
typedef uint8_t key[104];
#define DERIVE_KEY(H) ({ \
	key __key_ret = {0};\
	key_derivation(H, __key_ret); \
	__key_ret; \
})
void key_derivation(const uint8_t hash[16], key k) {
    uint16_t buffer[52] = {0};
    memcpy(buffer, hash, 16);

    for (uint16_t dx = 8; dx < 0x34; dx++) {
        int8_t bl;
        uint8_t bh;
        uint16_t ax;
        uint16_t word_index1, word_index2;
        uint16_t bx_word;

        bl = dx - 7;
        if ((bl & 7) == 0) bl -= 8;
        word_index1 = (uint8_t)bl;
        word_index1 %= 52;

        ax = buffer[word_index1] << 9;

        bl = dx - 6;
        bh = bl & 7;
        if (bh <= 1) bl -= 8;
        word_index2 = (uint8_t)bl;
        word_index2 %= 52;

        bx_word = buffer[word_index2] >> 7;

        ax |= bx_word;

        buffer[dx] = ax;
    }

    for (int i = 0; i < 52; i++) {
        k[2*i] = buffer[i] & 0xFF;
        k[2*i + 1] = buffer[i] >> 8;
    }
}

static inline uint16_t read_le16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static inline void write_le16(uint8_t* p, uint16_t val) {
    p[0] = val & 0xFF;
    p[1] = (val >> 8) & 0xFF;
}
static uint16_t special_mul_sub(uint16_t ax, uint16_t dx) {
    if (ax == 0 || dx == 0) {
        ax = (uint16_t)(-(int16_t)ax + 1);
        return ax;
    }

    uint32_t product = (uint32_t)ax * dx;
    uint16_t low = (uint16_t)(product & 0xFFFF);
    uint16_t high = (uint16_t)(product >> 16);

    uint32_t sub = (uint32_t)low - high;
    uint16_t result = (uint16_t)(sub & 0xFFFF);

    uint16_t borrow = (low < high) ? 1 : 0;

    result += borrow;

    return result;
}

void encryption(uint8_t* SI, uint8_t* DI) {
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
void decrypt(uint8_t *block, size_t block_len, key k){
	for(int i = 0; i < block_len >> 3; i++){
		encryption(block+8*i, k);
	}
}
int main(int argc, char **argv){
	if(!argv[1]){
		printf("usage: %s string\n", argv[0]);
		return -1;
	}
	static_assert(sizeof(struct user_entry) == 0x60);
	int l = strlen(argv[1]);	
	char *s = strdup(argv[1]);
	uint8_t s2[0x24] = {0};
	strcpy((char*)s2, s);
	modify_username(s2); //0100:46b7
	PHEX(s2);
	printf("\n");
	auto u = HASH_USERNAME(s);
	uint8_t *buff = create_DL_bytes_buff_from_input((uint8_t*)s, 0x10, l);
	for(int i = 0; i < 0x10; i++){
		printf("%c", buff[i]);
	}
	printf("\n");
	uint8_t out[16] = {0};
	uint16_t hash_seed = hash_username_seed;
	for(int i = 0; i < sizeof(out); i++){
		_hash(buff+i, 0x10, out, &hash_seed);
	}
	PHEX(out);
	for(int i = 0; i < 0x10; i++){
		printf("%02X ", u[i]);
	}
	printf("\n");
	//found 0100:0bfd obfuscated password of *AUTOUSER
	uint8_t in2[] = {
		0xB8, 0x1C, 0x29, 0x98,
	   	0xC1, 0x42, 0x04, 0x96,
		0x82, 0xA6, 0xD0, 0x99, 
		0xA1, 0xF2, 0x3B, 0x9F
	};

	memset(out, 0, sizeof(out));
	hash_seed = hash_password_seed;
	for(int i = 0; i < sizeof(out); i++){
		_hash(in2+i, sizeof(in2), out, &hash_seed);
	}
	PHEX(out);
	auto k = DERIVE_KEY(out);
	//from 0100:01cc master key encrypted with obfuscated password hash of *AUTOUSER
	uint8_t in3[] = {
		0x68, 0x86, 0x93, 0x83,
	   	0x5A, 0x4E, 0x7A, 0x88, 
		0xAA, 0x44, 0xA9, 0x98, 
		0xBF, 0x09, 0xC4, 0xB0
	};
	//decrypt key with key derived from pw
	decrypt(in3, sizeof(in3), k);
	auto master_k = DERIVE_KEY(in3);
	auto master_k2 = DERIVE_KEY2(master_k);	
	//static database 0100:02ce
	uint8_t in4[] = { 0xf9, 0x37, 0x14, 0xad, 0xc0, 0x80, 0x68, 0x25, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0x67, 0x61, 0x64, 0xc7, 0x75, 0x16, 0x73, 0x5d, 0x9b, 0xd7, 0x05, 0x70, 0x08, 0xba, 0x3a, 0xe1, 0x5f, 0x11, 0xf9, 0x69, 0x7d, 0x82, 0x95, 0x7d, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0x0b, 0x59, 0x29, 0x9a, 0x9f, 0xc4, 0x49, 0xfd, 0x90, 0x27, 0xa1, 0xbc, 0xcc, 0xa3, 0xd1, 0x18, 0xcc, 0x8b, 0x5c, 0x7c, 0x34, 0x47, 0x3e, 0x44, 0x4a, 0x30, 0x7c, 0x8e, 0xf4, 0xe1, 0xdc, 0x91, 0x5c, 0x26, 0xe2, 0xb1, 0xe0, 0xc3, 0xc6, 0x3c, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0x5c, 0xd7, 0x0c, 0xe8, 0x4d, 0xfe, 0x55, 0x8f, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0x67, 0x61, 0x64, 0xc7, 0x75, 0x16, 0x73, 0x5d, 0x75, 0x75, 0x93, 0x4d, 0x95, 0x3b, 0xd7, 0xb4, 0xd3, 0xc6, 0x79, 0x97, 0x85, 0x2e, 0xa1, 0xab, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0x8f, 0xe4, 0x0e, 0x2b, 0xf0, 0x35, 0x90, 0x63, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0x67, 0x61, 0x64, 0xc7, 0x75, 0x16, 0x73, 0x5d, 0x9f, 0x8a, 0x65, 0xad, 0x81, 0x51, 0xcd, 0xfb, 0x58, 0xf6, 0x96, 0x1d, 0x3b, 0x62, 0x5f, 0x03, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0x1c, 0xc0, 0xe0, 0x43, 0x88, 0x35, 0xa1, 0xd9, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0x67, 0x61, 0x64, 0xc7, 0x75, 0x16, 0x73, 0x5d, 0x82, 0x54, 0xd9, 0xaf, 0x74, 0x81, 0x3b, 0xf0, 0xa0, 0x77, 0xa9, 0xba, 0x3c, 0x63, 0xdf, 0x3c, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde };
	decrypt(in4, sizeof(in4), master_k2);
	uint8_t in5[] = { 0xef, 0xd1, 0x05, 0x51, 0x21, 0x7c, 0x07, 0x1d, 0x10, 0xf5, 0x5a, 0x42, 0x8c, 0x3a, 0x21, 0xe6, 0x67, 0x16, 0xec, 0x10, 0x14, 0x85, 0xb7, 0x0f, 0xb8, 0x26, 0xcc, 0xfb, 0xdc, 0x11, 0x83, 0x13, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0x9a, 0xcd, 0xca, 0x80, 0x61, 0xa0, 0x7f, 0x1a, 0xac, 0x1e, 0xfb, 0x40, 0x97, 0x8c, 0xfb, 0x36, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde, 0xe8, 0xc9, 0x01, 0x12, 0xbd, 0xaa, 0x08, 0xdf, 0xc6, 0x55, 0x51, 0xa8, 0x12, 0xe5, 0x6e, 0x05, 0xbb, 0xec, 0xda, 0x45, 0x6e, 0x5f, 0xed, 0xde };	
	//out == key in = cyblock	
	decrypt(in5, sizeof(in5), master_k2);
	PHEX(in5);
	uint8_t in6[] = { 0xaf, 0x42, 0x05, 0x67, 0x20, 0xa6, 0xce, 0xf7, 0x60, 0xcc, 0x88, 0x6d, 0x00, 0x56, 0x1f, 0xad, 0xbe, 0x43, 0x41, 0x3b, 0xbc, 0x3d, 0x5b, 0xb9, 0xa1, 0xdf, 0x14, 0xb6, 0xed, 0x9f, 0x09, 0x28, 0x06, 0xbe, 0x36, 0x66, 0xe1, 0xd8, 0xb4, 0x16, 0xae, 0xfb, 0xa0, 0x98, 0x07, 0x92, 0x74, 0x2e, 0x29, 0x7d, 0x20, 0xd5, 0x7c, 0x14, 0x57, 0x89, 0x73, 0xb6, 0x9d, 0x4a, 0xf8, 0x7e, 0xa7, 0xff, 0x21, 0x77, 0xc4, 0x1b, 0x15, 0xd5, 0xb7, 0x60, 0x9c, 0x88, 0xe7, 0x08, 0x10, 0xd9, 0x48, 0xc6, 0xfe, 0x3e, 0xb4, 0x82, 0x7a, 0x81, 0x33, 0x01, 0xae, 0x9f, 0xc8, 0x90, 0xaa, 0xa6, 0x5e, 0x96, 0x83, 0xdd, 0x01, 0x33, 0xdf, 0xaa, 0x28, 0xfb, 0x75, 0x75, 0x86, 0xb6, 0x0f, 0x2a, 0xa6, 0x00, 0xff, 0xf2, 0x78, 0x9e, 0x3a, 0xfb, 0xee, 0x6d, 0x6e, 0xb0, 0x80, 0x30, 0x45, 0xff, 0x2a, 0xdc };

	// == testblock should decrypt to 0x40..0xBF
	decrypt(in6, sizeof(in6), master_k2);
		
	struct user_entry *db = (struct user_entry*)in4;
	for(int i = 0; i < 5; i++){
		print_user_entry(&db[i]);
	}
	free(buff);
	free(s);
}
