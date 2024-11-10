#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static uint32_t sigma0(uint32_t x) {
    uint32_t RightRotate7,RightRotate18,RightShift3;

    RightRotate7  = (x >> 7  | x << (25));
    RightRotate18 = (x >> 18 | x << (14));
    RightShift3   = x >> 3;

    return RightRotate7 ^ RightRotate18 ^ RightShift3; 
}

static uint32_t sigma1(uint32_t x) {
    uint32_t RightRotate17,RightRotate19,RightShift10;

    RightRotate17  = (x >> 17 | x << (15));
    RightRotate19  = (x >> 19 | x << (13));
    RightShift10   = x >> 10;

    return RightRotate17 ^ RightRotate19 ^ RightShift10; 
}

static uint32_t bigsigma1(uint32_t x) {
    uint32_t RightRotate6, RightRotate11, RightRotate25;

    RightRotate6  = (x >> 6  | x << (26));
    RightRotate11 = (x >> 11 | x << (21));
    RightRotate25 = (x >> 25 | x << (7));

    return RightRotate6 ^ RightRotate11 ^ RightRotate25; 
}

static uint32_t bigsigma0(uint32_t x) {
    uint32_t RightRotate2, RightRotate13, RightRotate22;

    RightRotate2  = (x >> 2  | x << (32 - 2));
    RightRotate13 = (x >> 13 | x << (32 - 13));
    RightRotate22 = (x >> 22 | x << (32 - 22));

    return RightRotate2 ^ RightRotate13 ^ RightRotate22; 
}

static uint32_t choice(uint32_t e,uint32_t f,uint32_t g) {
    return (e & f) ^ ((~e) & g);
}

static uint32_t majority(uint32_t a,uint32_t b,uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

static const uint32_t RoundKonstans[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

uint32_t *SHA256(int len,uint8_t input[len]) {
    
    uint64_t w_len = len*8 + 64,
             len_in_bin = len * 8;

    while (w_len % 512 != 0)
    {
        w_len++;
    }
    
	uint8_t *_8w = malloc((w_len/8)*sizeof(uint8_t)),curr = 0;

	for (int i = 0;i < w_len/8;i++) {
        _8w[i] = 0x0;
    }

    for (int i = 0;i < w_len/8;i++) {

        if (i <= len) {
            if (input[i] == 0x0) {
                _8w[i] = 0b10000000;
            }
            else _8w[i] = input[i];
        }

        if (i+8 >= w_len/8) {
            _8w[i] = (len_in_bin >> 56) & 0x00000000000000FF;
            _8w[i+1] = (len_in_bin >> 48) & 0x00000000000000FF;
            _8w[i+2] = (len_in_bin >> 40) & 0x00000000000000FF;
            _8w[i+3] = (len_in_bin >> 32) & 0x00000000000000FF;
            _8w[i+4] = (len_in_bin >> 24) & 0x00000000000000FF;
            _8w[i+5] = (len_in_bin >> 16) & 0x00000000000000FF;
            _8w[i+6] = (len_in_bin >> 8) & 0x00000000000000FF;
            _8w[i+7] = len_in_bin & 0x00000000000000FF;
            break;
        }

    }

    curr = 0;
    
    uint8_t z = 0;
    
    while (z*32 < w_len)
    {
        z++;
    }

    uint32_t *_32w = malloc((48 + (w_len/z))*sizeof(uint32_t));

    for (int i = 0;i < 64;i+=4) {
        _32w[i/4] = (_8w[i] << 24) | 
                    (_8w[i+1] << 16) | 
                    (_8w[i+2] << 8)  |
                    _8w[i+3];
    }

    for (int i = z;i < z+48;i++) {
        _32w[i] = 0x0;
    }

    for (int i = z;i < z+48;i++) {
        _32w[i] = sigma1(_32w[i-2]) + _32w[i-7] + sigma0(_32w[i-15]) + _32w[i-16];
    }

    uint32_t HashValues[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    };

    uint32_t *CurrentHashValues = malloc(8*sizeof(uint32_t));
    
    for (uint8_t i = 0;i < 8;i++) {
        CurrentHashValues[i] = HashValues[i];
    };

    uint32_t temp1 = 0,temp2 = 0;

    for (int i = 0;i < 64;i++) {
        temp1 = bigsigma1(CurrentHashValues[4]) + choice(CurrentHashValues[4],CurrentHashValues[5],CurrentHashValues[6]) + RoundKonstans[i] + _32w[i] + CurrentHashValues[7];
        temp2 = bigsigma0(CurrentHashValues[0]) + majority(CurrentHashValues[0],CurrentHashValues[1],CurrentHashValues[2]);

        CurrentHashValues[7] = CurrentHashValues[6];

        CurrentHashValues[6] = CurrentHashValues[5];

        CurrentHashValues[5] = CurrentHashValues[4];

        CurrentHashValues[4] = temp1 + CurrentHashValues[3];

        CurrentHashValues[3] = CurrentHashValues[2];

        CurrentHashValues[2] = CurrentHashValues[1];

        CurrentHashValues[1] = CurrentHashValues[0];

        CurrentHashValues[0] = temp2 + temp1;
    }

    for (int i = 0;i < 8;i++) {
        CurrentHashValues[i] = HashValues[i] + CurrentHashValues[i];
    }

	return CurrentHashValues;

    free(CurrentHashValues);
    free(_32w);
    free(_8w);
}

int main(void) {

    char *ch = "asd";

    uint8_t data[4];

    memmove(data,ch,4);

    uint32_t *res = SHA256(4,data);

    puts("");

    for (int i = 0;i < 8;i++) {
        if ((i) % 2 == 0) printf("\n");
        printf("%lx ",(unsigned long)res[i]);
    } 
    puts(" ");

  return 0; 
}
