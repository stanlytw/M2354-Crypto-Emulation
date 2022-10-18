/**************************************************************************//**
 * @file     ecc.c
 * @version  V1.10
 * $Revision: 1 $
 * $Date: 16/07/28 3:38p $
 * @brief    ECC curve demo
 *
 * @note
 * Copyright (C) 2015 Nuvoton Technology Corp. All rights reserved.
*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "NuMicro.h"
#include "crypto.h"
#include "ecc.h"


int ecc_init_curve2(char *curve)
{
    int  i;

    pCurve2 = get_curve2(curve);
    if(pCurve2 == NULL)
    {
        printf("Cannot find curve P-192!\n");
        return -1;
    }

#ifdef USE_DMA
    memset((uint8_t *)((uint32_t)crpt + 0x808), 0, 144 * 4);
#endif

    for(i = 0; i < 18; i++)
    {
        crpt->ECC_A[i] = 0;
        crpt->ECC_B[i] = 0;
        crpt->ECC_X1[i] = 0;
        crpt->ECC_Y1[i] = 0;
        crpt->ECC_N[i] = 0;
    }

    Hex2Reg(pCurve2->Ea, (uint32_t *)&crpt->ECC_A[0]);
    Hex2Reg(pCurve2->Eb, (uint32_t *)&crpt->ECC_B[0]);
    Hex2Reg(pCurve2->Px, (uint32_t *)&crpt->ECC_X1[0]);
    Hex2Reg(pCurve2->Py, (uint32_t *)&crpt->ECC_Y1[0]);

    //printf("Key length = %d\n", pCurve->key_len);
    //dump_ecc_reg("CRPT_ECC_A", (uint32_t *)&CRPT->ECC_A[0], 10);
    //dump_ecc_reg("CRPT_ECC_B", (uint32_t *)&CRPT->ECC_B[0], 10);
    //dump_ecc_reg("CRPT_ECC_X1", (uint32_t *)&CRPT->ECC_X1[0], 10);
    //dump_ecc_reg("CRPT_ECC_Y1", (uint32_t *)&CRPT->ECC_Y1[0], 10);

    if(pCurve2->GF == CURVE_GF_2M)
    {
        crpt->ECC_N[ 0 ] = 0x1;
        crpt->ECC_N[(pCurve2->key_len) / 32 ] |= (1 << ((pCurve2->key_len) % 32));
        crpt->ECC_N[(pCurve2->irreducible_k1) / 32 ] |= (1 << ((pCurve2->irreducible_k1) % 32));
        crpt->ECC_N[(pCurve2->irreducible_k2) / 32 ] |= (1 << ((pCurve2->irreducible_k2) % 32));
        crpt->ECC_N[(pCurve2->irreducible_k3) / 32 ] |= (1 << ((pCurve2->irreducible_k3) % 32));
    }
    else
    {
        Hex2Reg(pCurve2->Pp, (uint32_t *)&crpt->ECC_N[0]);
    }

    //dump_ecc_reg("CRPT_ECC_N", (uint32_t *)&crpt->ECC_N[0], 10);

    return 0;
}

