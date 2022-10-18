/**************************************************************************//**
 * @file     main.c
 * @version  V1.10
 * $Revision: 10 $
 * $Date: 15/11/19 10:11a $
 * @brief    Show Crypto IP AES-128 ECB mode encrypt/decrypt function.
 *
 * @note
 * Copyright (C) 2016 Nuvoton Technology Corp. All rights reserved.
*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include "NuMicro.h"
#include "common.h"


uint32_t au32MyAESKey[8] =
{
    //0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
    //0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f
    //0x03020100,0x07060504,0x0b0a0908,0x0f0e0d0c,
    //0x03020100,0x07060504,0x0b0a0908,0x0f0e0d0c,
    0x16157e2b,0xa6d2ae28,0x8815f7ab,0x3c4fcf09
    
    
};

uint32_t au32MyAESIV[4] =
{
    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c
};

#ifdef __ICCARM__
#pragma data_alignment=4
uint8_t au8InputData[] =
{
#else
//const 
    __attribute__((aligned(4))) uint8_t au8InputData[64] =
{
#endif
    //0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    //0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20,
        0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A,
        0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03,
        0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e, 0xd8, 0x25,
        0x97, 0x40, 0x05, 0x1e, 0x9c, 0x5f, 0xec, 0xf6,
        0x43, 0x44, 0xf7, 0xa8, 0x22, 0x60, 0xed, 0xcc,
        0x30, 0x4c, 0x65, 0x28, 0xf6, 0x59, 0xc7, 0x78,
        0x66, 0xa5, 0x10, 0xd9, 0xc1, 0xd6, 0xae, 0x5e
        
};


__attribute__((aligned(4))) uint8_t g_au8Out[] = {0};



#ifdef __ICCARM__
#pragma data_alignment=4
uint8_t au8OutputData[1024];
#else
__attribute__((aligned(4))) uint8_t au8OutputData[1024];
#endif

static volatile int32_t  g_AES_done;

void CRPT_IRQHandler()
{
    if(AES_GET_INT_FLAG(CRPT))
    {
        g_AES_done = 1;
        AES_CLR_INT_FLAG(CRPT);
    }
}


void DumpBuffHex(uint8_t *pucBuff, int nBytes)
{
    int32_t i32Idx, i;

    i32Idx = 0;
    while(nBytes > 0)
    {
        printf("0x%04X  ", i32Idx);
        for(i = 0; i < 16; i++)
            printf("%02x ", pucBuff[i32Idx + i]);
        printf("  ");
        for(i = 0; i < 16; i++)
        {
            if((pucBuff[i32Idx + i] >= 0x20) && (pucBuff[i32Idx + i] < 127))
                printf("%c", pucBuff[i32Idx + i]);
            else
                printf(".");
            nBytes--;
        }
        i32Idx += 16;
        printf("\n");
    }
    printf("\n");
}


/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
int32_t main(void)
{
    int32_t i, i32Err;
    uint32_t u32Ctl;

    SYS_UnlockReg();

    /* Init System, IP clock and multi-function I/O */
    SYS_Init();

    /* Init UART0 for printf */
    DEBUG_PORT_Init();

    printf("+---------------------------------------+\n");
    printf("|     Crypto AES Driver Sample Code     |\n");
    printf("+---------------------------------------+\n");

    //NVIC_EnableIRQ(CRPT_IRQn);
    AES_ENABLE_INT(CRPT);

    /*---------------------------------------
     *  AES-128 ECB mode encrypt
     *---------------------------------------*/
    //AES_Open(CRPT, 0, 0, AES_MODE_CFB, AES_KEY_SIZE_128, AES_IN_OUT_SWAP);
    //AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_128);
    u32Ctl =    (AES_MODE_OFB << CRPT_AES_CTL_OPMODE_Pos) |
                (AES_KEY_SIZE_128 << CRPT_AES_CTL_KEYSZ_Pos) |
                (AES_IN_OUT_SWAP << CRPT_AES_CTL_OUTSWAP_Pos) | 
                CRPT_AES_CTL_KINSWAP_Msk;
                //CRPT_AES_CTL_DMAEN_Msk | CRPT_AES_CTL_DMACSCAD_Msk | CRPT_AES_CTL_DMALAST_Msk;
    
    CRPT->AES_KEY[0] = au32MyAESKey[0];
    CRPT->AES_KEY[1] = au32MyAESKey[1];
    CRPT->AES_KEY[2] = au32MyAESKey[2];
    CRPT->AES_KEY[3] = au32MyAESKey[3];
    
    CRPT->AES_IV[0] = au32MyAESIV[0];
    CRPT->AES_IV[1] = au32MyAESIV[1];
    CRPT->AES_IV[2] = au32MyAESIV[2];
    CRPT->AES_IV[3] = au32MyAESIV[3];
    
    CRPT->AES_SADDR = (uint32_t)au8InputData;
    CRPT->AES_DADDR = (uint32_t)au8OutputData;
    CRPT->AES_CNT = 16;
    
    
    /* Clear flag */
    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk;
    CRPT->AES_CTL = u32Ctl | CRPT_AES_CTL_START_Msk | CRPT_AES_CTL_DMAEN_Msk;
    //CRPT->AES_CTL = u32Ctl | CRPT_AES_CTL_START_Msk | CRPT_AES_CTL_DMAEN_Msk;

    while((CRPT->INTSTS & CRPT_INTSTS_AESIF_Msk) == 0);
    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk;

    //DumpBuffHex(au8OutputData, sizeof(au8InputData));

    //while(1);


    CRPT->AES_SADDR = (uint32_t)au8InputData + 16;
    CRPT->AES_DADDR = (uint32_t)au8OutputData + 16;
    CRPT->AES_CNT = 16;
    
    /* Clear flag */
    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk;
    CRPT->AES_CTL = u32Ctl | CRPT_AES_CTL_START_Msk | CRPT_AES_CTL_DMAEN_Msk | CRPT_AES_CTL_DMACSCAD_Msk;

    while((CRPT->INTSTS & CRPT_INTSTS_AESIF_Msk) == 0);
    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk;


    CRPT->AES_SADDR = (uint32_t)au8InputData + 32;
    CRPT->AES_DADDR = (uint32_t)au8OutputData + 32;
    CRPT->AES_CNT = 16;
    
    /* Clear flag */
    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk;
    CRPT->AES_CTL = u32Ctl | CRPT_AES_CTL_START_Msk | CRPT_AES_CTL_DMAEN_Msk | CRPT_AES_CTL_DMACSCAD_Msk ;

    while((CRPT->INTSTS & CRPT_INTSTS_AESIF_Msk) == 0);
    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk;


    CRPT->AES_SADDR = (uint32_t)au8InputData + 48;
    CRPT->AES_DADDR = (uint32_t)au8OutputData + 48;
    CRPT->AES_CNT = 16;
    
    /* Clear flag */
    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk;
    CRPT->AES_CTL = u32Ctl | CRPT_AES_CTL_START_Msk | CRPT_AES_CTL_DMAEN_Msk | CRPT_AES_CTL_DMACSCAD_Msk | CRPT_AES_CTL_DMALAST_Msk ;

    while((CRPT->INTSTS & CRPT_INTSTS_AESIF_Msk) == 0);
    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk;


    DumpBuffHex(au8OutputData, sizeof(au8InputData));

    while(1);
    
    /*---------------------------------------
     *  AES-128 ECB mode decrypt
     *---------------------------------------*/
    AES_Open(CRPT, 0, 0, AES_MODE_ECB, AES_KEY_SIZE_128, AES_IN_OUT_SWAP);
    AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_128);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)au8OutputData, (uint32_t)g_au8Out, sizeof(au8InputData));

    g_AES_done = 0;
    /* Start AES decrypt */
    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
    /* Waiting for AES calculation */
    while(!g_AES_done);

    printf("AES decrypt done.\n\n");
    DumpBuffHex(g_au8Out, sizeof(g_au8Out));

    i32Err = 0;
    for(i = 0; i < sizeof(au8InputData); i++)
    {
        if(g_au8Out[i] != au8InputData[i])
        {
            i32Err = -1;
            break;
        }
    }

    if(i32Err)
    {
        printf("TEST FAILED!\n");
    }
    else
    {
        printf("TEST PASSED\n");
    }



    while(1);
}



