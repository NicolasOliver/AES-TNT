#include "aes.h"

constexpr uint8_t AES::S_BOX[];

AES::AES()
{

}

uint8_t AES::subBytes(uint8_t tab[4][4])
{
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            tab[i][j] = S_BOX[tab[i][j]];
        }
    }
    return tab;
}

uint8_t AES::addRoundKey(uint8_t state[4][4], const uint8_t roundKey[4][4])
 {
    for (uint8_t i = 0; i < 4; i++) {
        uint32_t* clefPtr = (uint32_t*) roundKey[i];
        uint32_t* statePtr = (uint32_t*) state[i];
        *statePtr ^= *clefPtr;
    }
    return state;
 }

uint8_t AES::shiftRows(uint8_t state[4][4])
{
    for(int i = 1; i < 4; i++) {
        uint8_t row[4];
        for(int j = 0; j < 4; j++) {
            row[j] = state[i][j];
        }
        for(int j = 0; j < 4; j++) {
            state[i][j] = row[(i + j) % 4];
        }
    }
    return state;
}


uint8_t AES::mixColumns(uint8_t state[4][4])
{
    uint8_t h;
    /* The array 'col' is simply a copy of the input array 'state'
     * The array 'col2' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * col[n] ^ col2[n] is element n multiplied by 3 in Rijndael's Galois field */

    for(int i = 0; i < 4; i++) {
        uint8_t col[4] = {state[0][i], state[1][i], state[2][i], state[3][i]};
        uint8_t col2[4];

        h = (uint8_t)((int8_t)state[i][i] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
        col2[i] = state[i][i] << 1; /* implicitly removes high bit */
        col2[i] ^= 0x1B & h; /* Rijndael's Galois field */
        /* h is 0xff if the high bit is set, 0 otherwise */

        state[0][i] = col2[0] ^ col[3] ^ col[2] ^ col2[1] ^ col[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
        state[1][i] = col2[1] ^ col[0] ^ col[3] ^ col2[2] ^ col[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
        state[2][i] = col2[2] ^ col[1] ^ col[0] ^ col2[3] ^ col[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
        state[3][i] = col2[3] ^ col[2] ^ col[1] ^ col2[0] ^ col[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
    }
    return state;
}

uint8_t AES::encryptionProcess(uint8_t state[4][4], uint8_t cypherKey[4][4])
{
    // Initial round
    addRoundKey(state, cypherKey);

    for(int i = 0; i < 10; i++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, cypherKey);
    }

    // Final round
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, cypherKey);

    return state; // state = cypherText
}

uint8_t AES::keySchedule(uint8_t cypherKey[4][4])
{
    uint8_t key[4][11*4];

    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            key[i][j] = cypherKey[i][j];
        }
    }

    for(int i = 0; i < 4; i++) {
        for(int j = 4; j < 11*4; j++) {
            if(j % 4 == 0) { // 1ère colonne de chaque bloc
                key[i][j] = cypherKey[i][(j-3)%4] ^ S_BOX[key[i][j-1]] ^ R_CON[i];
            } else { // les autres colonnes de chaque bloc
                key[i][j] = cypherKey[i][j%4] ^ key[i][j-1];
            }

        }
    }

    return key;
}
