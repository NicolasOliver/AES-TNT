#include "aes.h"

AES::AES()
{

}

void AES::shiftRows(uint8_t state[4][4]) {
    for(int i = 1; i < 4; i++) {
        uint8_t row[4];
        for(int j = 0; j < 4; j++) {
            row[j] = state[i][j];
        }
        for(int j = 0; j < 4; j++) {
            state[i][j] = row[(i + j) % 4];
        }
    }
}

void AES::mixColumns(uint8_t state[4][4]) {
    uint8_t h;
    /* The array 'col' is simply a copy of the input array 'state'
     * The array 'col2' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * col[n] ^ col2[n] is element n multiplied by 3 in Rijndael's Galois field */

    for(i = 0; i < 4; i++) {
        uint8_t col[4] = {state[0][i], state[1][i], state[2][i], state[3][i]};
        uint8_t col2[4];

        h = (uint8_t)((int8_t)state[i][i] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
        col2[i] = state[j][i] << 1; /* implicitly removes high bit */
        col2[i] ^= 0x1B & h; /* Rijndael's Galois field */
        /* h is 0xff if the high bit is set, 0 otherwise */

        state[0][j] = col2[0] ^ col[3] ^ col[2] ^ col2[1] ^ col[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
        state[1][j] = col2[1] ^ col[0] ^ col[3] ^ col2[2] ^ col[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
        state[2][j] = col2[2] ^ col[1] ^ col[0] ^ col2[3] ^ col[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
        state[3][j] = col2[3] ^ col[2] ^ col[1] ^ col2[0] ^ col[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
    }
}
