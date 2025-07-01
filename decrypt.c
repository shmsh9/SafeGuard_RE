#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint16_t myrand(uint32_t *seed){
	*seed = (0x343fdu * *seed) + 0x269ec3u;
	return *seed >> 16;
}

int main(int argc, char **argv){
	if(!argv[1]){

		printf("usage %s file\n", argv[0]);
		return -1;
	}
	FILE *f = fopen(argv[1], "rb");
	int l = strlen(argv[1]);
	char suffix[] = ".decrypted";
	static_assert(sizeof(suffix) == 11);	

	char *name2 = malloc(l+sizeof(suffix));
	name2[l+sizeof(suffix)-1] = 0;

	sprintf(name2, "%s%s", argv[1], suffix);
	FILE *f2 = fopen(name2, "wb");
	uint8_t buff[2] = {0};

	uint32_t seed = 0x23c98de1;

	int32_t r = fread(buff, sizeof(buff), 1, f);
	while(r > 0){
		*((uint16_t *)buff) ^= myrand(&seed);
		fwrite(buff, sizeof(buff), 1, f2);
		r = fread(buff, sizeof(buff), 1, f);
	}
	fclose(f2);
	fclose(f);
	free(name2);
}
