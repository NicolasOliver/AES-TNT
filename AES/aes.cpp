#include "aes.h"

constexpr uint8_t AES::S_BOX[];
constexpr uint8_t AES::R_CON[4][10];

AES::AES(uint8_t state[4][4], uint8_t cipherKey[4][4])
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state_[i][j] = state[i][j];
            cipherKey_[i][j] = cipherKey[i][j];
        }
    }
}

void AES::subBytes()
{
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            state_[i][j] = S_BOX[state_[i][j]];
        }
    }
    //return tab;
}

void AES::subBytesKey()
{
    for (int i = 0; i < 4; i++) {
        colRot_[i] = S_BOX[colRot_[i]];
    }
}

void AES::addRoundKey()
 {
    for (uint8_t i = 0; i < 4; i++) {
        uint32_t* clefPtr = (uint32_t*) roundKey_[i];
        uint32_t* statePtr = (uint32_t*) state_[i];
        *statePtr ^= *clefPtr;
    }
    //return state;
 }

void AES::shiftRows()
{
    for(int i = 1; i < 4; i++) {
        uint8_t row[4];
        for(int j = 0; j < 4; j++) {
            row[j] = state_[i][j];
        }
        for(int j = 0; j < 4; j++) {
            state_[i][j] = row[(i + j) % 4];
        }
    }
}

void AES::rotWord() {
    uint8_t val = colRot_[0];
    for(int i = 0; i < 3; i++) {
        colRot_[i] = colRot_[i+1];
    }
    colRot_[3] = val;
    //return key;
}


void AES::mixColumns()
{
    uint8_t h;
    /* The array 'col' is simply a copy of the input array 'state'
     * The array 'col2' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * col[n] ^ col2[n] is element n multiplied by 3 in Rijndael's Galois field */

    for(int i = 0; i < 4; i++) {
        uint8_t col[4] = {state_[0][i], state_[1][i], state_[2][i], state_[3][i]};
        uint8_t col2[4];

        h = (uint8_t)((int8_t)state_[i][i] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
        col2[i] = state_[i][i] << 1; /* implicitly removes high bit */
        col2[i] ^= 0x1B & h; /* Rijndael's Galois field */
        /* h is 0xff if the high bit is set, 0 otherwise */

        state_[0][i] = col2[0] ^ col[3] ^ col[2] ^ col2[1] ^ col[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
        state_[1][i] = col2[1] ^ col[0] ^ col[3] ^ col2[2] ^ col[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
        state_[2][i] = col2[2] ^ col[1] ^ col[0] ^ col2[3] ^ col[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
        state_[3][i] = col2[3] ^ col[2] ^ col[1] ^ col2[0] ^ col[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
    }
}

void AES::encryptionProcess()
{
    keySchedule();

    // Initial round
    addRoundKey();

    for(int i = 0; i < 10; i++) {
        subBytes();
        shiftRows();
        mixColumns();
        addRoundKey();
    }

    // Final round
    subBytes();
    shiftRows();
    addRoundKey();

    // state = cipherText
}

void AES::keySchedule()
{
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            key_[i][j] = cipherKey_[i][j];
        }
    }

    for(int j = 4; j < 11*4; j++) {
        for(int i = 0; i < 4; i++) {
            if(j % 4 == 0) { // 1ère colonne de chaque bloc
                for(int k = 0; k < 4; k++) {
                    colRot_[k] = key_[k][j-1];
                }
                rotWord();
                subBytesKey();
                key_[i][j] = key_[i][j-4] ^ colRot_[i] ^ R_CON[i][(j-4)/4];
            } else { // les autres colonnes de chaque bloc
                key_[i][j] = key_[i][j-4] ^ key_[i][j-1];
            }
        }
    }

    for(int j = 0; j < 11*4; j++) {
         for(int i = 0; i < 4; i++) {
            std::cout << i << ", " << j << " : " << std::hex << static_cast<int>(key_[i][j]) << std::endl;
        }
    }
}
