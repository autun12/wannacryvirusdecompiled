#include <stdint.h>

/*
---------------------------------------------------
| OFFSET | Value                                  |
| 0x0000 | WANACRY!                               |
| 0x0008 | Length of RSA encrypted data           |
| 0x000C | RSA encrypted AES file encryption key  |
| 0x010C | File type internal to WannaCry         |
| 0x0110 | Original file size                     |
| 0x0118 | Encrypted file contents  (AES-128 CBC) |
---------------------------------------------------
*/

struct WannaCryFile {
    char magicHeader[8]; //WANACRY
    uint32_t enc_key_len; //needs to be 0x100
    char enc_key[enc_key_len];
    uint32_t unkown; // was 4
    uint64_t enc_data_len;
    char enc_data[enc_data_len];
};

