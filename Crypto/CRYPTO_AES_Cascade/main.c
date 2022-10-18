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

const char *g_key_str = "FEFFE9928665731C6D6A8F9467308308";
const char *g_iv_str = "CAFEBABEFACEDBADDECAF888";
const char *g_p_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
__ALIGNED(4) uint8_t g_key[32];
__ALIGNED(4) uint8_t g_iv[32];
__ALIGNED(4) uint8_t g_au8Buf[4096];
__ALIGNED(4) uint8_t g_au8Buf2[4096];




static volatile int32_t  g_AES_done;

void CRPT_IRQHandler()
{
    if(AES_GET_INT_FLAG(CRPT))
    {
        g_AES_done = 1;
        AES_CLR_INT_FLAG(CRPT);
    }
}


void SYS_Init(void)
{


//    /* Enable PLL */
//    CLK->PLLCTL = CLK_PLLCTL_128MHz_HIRC;

//    /* Waiting for PLL stable */
//    while((CLK->STATUS & CLK_STATUS_PLLSTB_Msk) == 0);

//    /* Set HCLK divider to 2 */
//    CLK->CLKDIV0 = (CLK->CLKDIV0 & (~CLK_CLKDIV0_HCLKDIV_Msk)) | 1;

//    /* Switch HCLK clock source to PLL */
//    CLK->CLKSEL0 = (CLK->CLKSEL0 & (~CLK_CLKSEL0_HCLKSEL_Msk)) | CLK_CLKSEL0_HCLKSEL_PLL;

    
    CLK->PWRCTL |= CLK_PWRCTL_HIRCEN_Msk;
    CLK->CLKSEL0 = CLK_CLKSEL0_HCLKSEL_HIRC;
    CLK->CLKDIV0 = 0;
    
    CLK_SetCoreClock(FREQ_96MHZ);
    
    /* Select IP clock source */
    CLK->CLKSEL2 = CLK_CLKSEL2_UART0SEL_HIRC;
    CLK->CLKSEL3 = CLK_CLKSEL3_UART5SEL_HIRC;

    /* Enable IP clock */
    CLK->AHBCLK  |= CLK_AHBCLK_CRPTCKEN_Msk;
    CLK->APBCLK0 |= CLK_APBCLK0_UART0CKEN_Msk | CLK_APBCLK0_TMR0CKEN_Msk | CLK_APBCLK0_UART5CKEN_Msk;


    /* Update System Core Clock */
    /* User can use SystemCoreClockUpdate() to calculate PllClock, SystemCoreClock and CycylesPerUs automatically. */
    //SystemCoreClockUpdate();
    PllClock        = 128000000;           // PLL
    SystemCoreClock = 128000000 / 2;       // HCLK
    CyclesPerUs     = 64000000 / 1000000;  // For SYS_SysTickDelay()

    /*---------------------------------------------------------------------------------------------------------*/
    /* Init I/O Multi-function                                                                                 */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Set multi-function pins for UART0 RXD and TXD */
    SYS->GPB_MFPH = (SYS->GPB_MFPH & (~(UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk))) | UART0_RXD_PB12 | UART0_TXD_PB13;

}

void DEBUG_PORT_Init()
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART                                                                                               */
    /*---------------------------------------------------------------------------------------------------------*/
    DEBUG_PORT->LINE = UART_PARITY_NONE | UART_STOP_BIT_1 | UART_WORD_LEN_8;
    DEBUG_PORT->BAUD = UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(__HIRC, 115200);

}

/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
int32_t main(void)
{
    int32_t i, i32Err;
    uint32_t klen, ivlen, plen, plen_aligned;
    uint32_t inAddr, outAddr, size, chunk;

    SYS_UnlockReg();

    /* Init System, IP clock and multi-function I/O */
    SYS_Init();

    /* Init UART0 for printf */
    DEBUG_PORT_Init();

    printf("+---------------------------------------+\n");
    printf("|     Crypto AES Driver Sample Code     |\n");
    printf("+---------------------------------------+\n");

    NVIC_EnableIRQ(CRPT_IRQn);
    AES_ENABLE_INT(CRPT);

    klen = strlen(g_key_str) / 2;
    ivlen = strlen(g_iv_str) / 2;
    plen = strlen(g_p_str) / 2; 

    plen_aligned = (plen & 0xful) ? (plen + 15) / 16 * 16 : plen;

    printf("Key (%d): %s\n",klen, g_key_str);
    printf("IV  (%d): %s\n", ivlen, g_iv_str);
    printf("P   (%d): %s\n", plen, g_p_str);

    Str2Bin(g_key_str, g_key, klen);
    WordSwap(g_key, klen);

    memset(g_au8Buf2, 0, plen_aligned);
    Str2Bin(g_p_str, g_au8Buf2, plen);

    printf("input:\n");
    Dump(g_au8Buf2, plen_aligned);
    WordSwap(g_au8Buf2, plen_aligned);


    AES_Open(CRPT, 0, 1, AES_MODE_ECB, AES_KEY_SIZE_128, AES_NO_SWAP);
    AES_SetKey(CRPT, 0, (uint32_t *)g_key, AES_KEY_SIZE_128);
    AES_SetInitVect(CRPT, 0, (uint32_t *)g_iv);

    size = plen_aligned;
    inAddr = (uint32_t)g_au8Buf2;
    outAddr = (uint32_t)g_au8Buf;
    chunk = 16;
    while(size > 0)
    {
        AES_SetDMATransfer(CRPT, 0, inAddr, outAddr, chunk);

        g_AES_done = 0;
        /* Start AES Eecrypt */
        if(size > chunk)
            AES_Start(CRPT, 0, CRYPTO_DMA_CONTINUE);
        else
            AES_Start(CRPT, 0, CRYPTO_DMA_LAST);
        /* Waiting for AES calculation */
        while(!g_AES_done);
        
        size -= chunk;
        inAddr += chunk;
        outAddr += chunk;
    }

    printf("AES encrypt done.\n\n");
    Dump(g_au8Buf, plen_aligned);
    
    
    

    AES_Open(CRPT, 0, 0, AES_MODE_ECB, AES_KEY_SIZE_128, AES_NO_SWAP);
    AES_SetKey(CRPT, 0, (uint32_t *)g_key, AES_KEY_SIZE_128);
    AES_SetInitVect(CRPT, 0, (uint32_t *)g_iv);
    

    size = plen_aligned;
    inAddr = (uint32_t)g_au8Buf;
    outAddr = (uint32_t)g_au8Buf2;
    chunk = 32;
    while(size > 0)
    {
        AES_SetDMATransfer(CRPT, 0, inAddr, outAddr, chunk);

        g_AES_done = 0;
        /* Start AES Eecrypt */
        if(size > chunk)
            AES_Start(CRPT, 0, CRYPTO_DMA_CONTINUE);
        else
            AES_Start(CRPT, 0, CRYPTO_DMA_LAST);
        /* Waiting for AES calculation */
        while(!g_AES_done);
        
        size -= chunk;
        inAddr += chunk;
        outAddr += chunk;
    }



    printf("AES decrypt done.\n\n");
    WordSwap(g_au8Buf2, plen_aligned);
    Dump(g_au8Buf2, plen);
    Str2Bin(g_p_str, g_au8Buf, plen);

    i32Err = memcmp(g_au8Buf, g_au8Buf2, plen);

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



