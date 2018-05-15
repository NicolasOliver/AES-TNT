#include "aes.h"
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

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

void AES::addRoundKey(int j)
 {
    j = j*4;
    for(int i = 0; i < 4; i++) {
        for(int k = 0; k < 4; k++) {
            state_[i][k] ^= key_[i][k+j];
        }
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
    int i;
    unsigned char Tmp,Tm,t;
    for(i = 0; i < 4; i++) {
        t = state_[0][i];
        Tmp = state_[0][i] ^ state_[1][i] ^ state_[2][i] ^ state_[3][i] ;
        Tm = state_[0][i] ^ state_[1][i] ; Tm = xtime(Tm); state_[0][i] ^= Tm ^ Tmp ;
        Tm = state_[1][i] ^ state_[2][i] ; Tm = xtime(Tm); state_[1][i] ^= Tm ^ Tmp ;
        Tm = state_[2][i] ^ state_[3][i] ; Tm = xtime(Tm); state_[2][i] ^= Tm ^ Tmp ;
        Tm = state_[3][i] ^ t ; Tm = xtime(Tm); state_[3][i] ^= Tm ^ Tmp ;
    }
}

void AES::encryptionProcess()
{
    keySchedule();

    // Initial round
    addRoundKey(0);

    for(int i = 0; i < 9; i++) {
        //std::cout << "ITERATION " << i << std::endl;
        subBytes();
        shiftRows();
        mixColumns();
        addRoundKey(i+1);
    }

    // Final round
    subBytes();
    shiftRows();
    addRoundKey(10);

    std::cout << "Output CipherText :" << std::endl;
    for(int ii = 0; ii < 4; ii++) {
         for(int jj = 0; jj < 4; jj++) {
            std::cout << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(state_[ii][jj]) << " ";
        }
          std::cout << std::endl;
    }
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

    std::cout << "Output Key Schedule :" << std::endl;
    for(int ii = 0; ii < 4; ii++) {
         for(int jj = 0; jj < 11*4; jj++) {
            std::cout << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(key_[ii][jj]) << " ";
        }
          std::cout << std::endl;
    }
}
