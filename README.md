n effort to reverse engineer utimaco SafeGuard Easy 4.2.1

### bootloader
The bootloader code is encrypted using the rand() function initialized with seed 0x23c97de1 and XORING each 16bits blocks with the result of rand():
```C
uint16_t rand(uint32_t *seed){
    *seed = (0x343fdu * *seed) + 0x269ec3u;
    return *seed >> 16;
}
```
The bootloader code is located at sector 0x1e8a68 and is 5120 bytes long.
If you are tired of waiting to enter the password you can modify the 16bit value at 0xbd0

### Secrets
The "master" key is stored at address `0x01bc`
At this address Each 16 bytes value is the "master" key encrypted using the user password hash.
Each entry is an user.
Each char of the password is saved as bios `(scancode | 0x80)`
The password is hashed like this:
```C
char *username_padded = create_DL_bytes_buff_from_input(password, 0x10, strlen(password)); //return a 16bytes buffer with the password repeating itself if shorter than 16 bytes
hash_seed = 0xc2d5; //the seed for a username is 0xb71d;
uint8_t password_hash[0x10] = {0};
for(int i = 0; i < sizeof(out); i++){
    hashing_username(username_padded+i, 0x10, password_hash, &hash_seed);
}
```

### Encryption
#### Every sector (512 bytes) is encrypted using the 32 bytes AES256 key decrypted by the "master key".
##### To decrypt a sector you need to calculate it's IV using it's LBA address:
```C
void lba_to_iv(uint64_t lba, uint8_t iv[16]) {
        const uint32_t sectors_per_track = 63;
        const uint32_t heads = 16;
        uint32_t sector = (lba % sectors_per_track) + 1;
        uint32_t temp = lba / sectors_per_track;
        uint32_t head = temp % heads;
        uint32_t cylinder = temp / heads;
        uint32_t lba_calc = (cylinder * heads + head) * sectors_per_track + (sector - 1);
        uint16_t ax = lba_calc & 0xFFFF;
        uint16_t dx = (lba_calc >> 16) & 0xFFFF;
        for (int i = 0; i < 4; i++) {
                iv[i * 4 + 0] = ax & 0xFF;
                iv[i * 4 + 1] = (ax >> 8) & 0xFF;
                iv[i * 4 + 2] = dx & 0xFF;
                iv[i * 4 + 3] = (dx >> 8) & 0xFF;
        }
}
```
#### decrypt it using AES256-CBC :
```
openssl enc -aes-256-cbc -d -K KEY -nopad -in input_file -out output_file -iv IV
```
#### Each sector has i'ts own IV you can't just decrypt the whole disk using openssl like this.
