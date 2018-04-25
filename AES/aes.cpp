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
