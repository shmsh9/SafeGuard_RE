# An effort to reverse engineer utimaco SafeGuard 4.2.1

### decrypt.c
	the algorithm used to decrypt stage2 and stage3 binaries 

### hash.c
	the structures and functions used to decrypt the database


### bootloader 
	The bootloader code is encrypted using the rand() function initialized with seed 0x23c97de1 and XORING each 16bits blocks with the result of rand():
	```
	uint16_t rand(uint32_t *seed){
        *seed = (0x343fdu * *seed) + 0x269ec3u;
        return *seed >> 16;
	}
	```
	The bootloader code is located at sector 0x1e8a68 and is 5120 bytes long.
	If you are tired of waiting to enter the password you can modify the 16bit value at 0xbd0

### Secrets
	The "master" key is stored at address 0x01bc 
	At this address Each 16 bytes value is the "master" key encrypted using the user password hash.
	Each entry is an user.
	Each char of the password is saved as bios scancode AND 0x80 (sets the MSB)
	The password is hashed like this:
	```
	char *username_padded = create_DL_bytes_buff_from_input(password, 0x10, strlen(password)); //return a 16bytes buffer with the password repeating itself if shorter than 16 bytes
	hash_seed = 0xc2d5; //the seed for a username is 0xb71d;
	uint8_t password_hash[0x10] = {0};
   	for(int i = 0; i < sizeof(out); i++){
		hashing_username(username_padded+i, 0x10, password_hash, &hash_seed);
	}
	```
