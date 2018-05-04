#include "aes.h"

constexpr uint8_t Aes::S_BOX[];


Aes::Aes()
{

}

void Aes::SubBytes(uint8_t tab[4][4])
{
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            tab[i][j] = S_BOX[tab[i][j]];
        }
    }
}

 void AddRoundKey (uint8_t tab[4][4], const uint8_t roundKey[4][4]){
   for (uint8_t i = 0; i < 4; i++)
        {
            uint32_t* clefPtr = (uint32_t*) roundKey[i];
            uint32_t* statePtr = (uint32_t*) tab[i];
            *statePtr ^= *clefPtr;
        }
 }