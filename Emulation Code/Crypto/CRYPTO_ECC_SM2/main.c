/**************************************************************************//**
 * @file     main.c
 * @version  V1.00
 * @brief    Show whole ECC flow. Including private key/public key/Signature generation and
 *           Signature verification.
 *
 * @note
 * Copyright (C) 2016 Nuvoton Technology Corp. All rights reserved.
*****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "NuMicro.h"


//#define GEN_PRIV_KEY       
//#define RANDOM_K

#define KEY_LENGTH          256  /* Select ECC P-192 curve, 192-bits key length */
#define PRNG_KEY_SIZE       PRNG_KEY_SIZE_256
#define CURVE_P_SIZE        CURVE_SM2_256

char e[168];
char d[168];                         /* private key */
char Qx[168], Qy[168];               /* temporary buffer used to keep output public keys */
char k[168];                         /* random integer k form [1, n-1]                */
__ALIGNED(4) char msg[] = "abc";
char R[168], S[168];                 /* temporary buffer used to keep digital signature (R,S) pair */




#define ENDIAN(x)   ((((x)>>24)&0xff) | (((x)>>8)&0xff00) | (((x)<<8)&0xff0000) | ((x)<<24))

uint8_t Byte2Char(uint8_t c)
{
    if(c < 10)
        return (c + '0');
    if(c < 16)
        return (c - 10 + 'a');

    return 0;
}


void CRPT_IRQHandler()
{
    ECC_DriverISR(CRPT);
}


void  dump_buff_hex(uint8_t *pucBuff, int nBytes)
{
    int     nIdx, i;

    nIdx = 0;
    while(nBytes > 0)
    {
        printf("0x%04X  ", nIdx);
        for(i = 0; i < 16; i++)
            printf("%02x ", pucBuff[nIdx + i]);
        printf("  ");
        for(i = 0; i < 16; i++)
        {
            if((pucBuff[nIdx + i] >= 0x20) && (pucBuff[nIdx + i] < 127))
                printf("%c", pucBuff[nIdx + i]);
            else
                printf(".");
            nBytes--;
        }
        nIdx += 16;
        printf("\n");
    }
    printf("\n");
}



void SYS_Init(void)
{
    CLK->PWRCTL |= CLK_PWRCTL_HXTEN_Msk;
    

    /* Enable PLL */
    //CLK->PLLCTL = CLK_PLLCTL_128MHz_HIRC;

    /* Waiting for PLL stable */
    //while((CLK->STATUS & CLK_STATUS_PLLSTB_Msk) == 0);

    /* Set HCLK divider */
    //CLK->CLKDIV0 = (CLK->CLKDIV0 & (~CLK_CLKDIV0_HCLKDIV_Msk)) | 0;
    CLK->CLKSEL0 = CLK_CLKSEL0_HCLKSEL_HXT;
    CLK->CLKDIV0 = 0;

    CLK_SetCoreClock(FREQ_96MHZ);
    
    /* Switch HCLK clock source to PLL */
    //CLK->CLKSEL0 = (CLK->CLKSEL0 & (~CLK_CLKSEL0_HCLKSEL_Msk)) | CLK_CLKSEL0_HCLKSEL_PLL;

    /* Select IP clock source */
    CLK->CLKSEL2 = CLK_CLKSEL2_UART0SEL_HIRC;
    CLK->CLKSEL3 = CLK_CLKSEL3_UART5SEL_HIRC;

    /* Enable IP clock */
    CLK->AHBCLK  |= CLK_AHBCLK_CRPTCKEN_Msk;
    CLK->APBCLK0 |= CLK_APBCLK0_UART0CKEN_Msk | CLK_APBCLK0_TMR0CKEN_Msk | CLK_APBCLK0_UART5CKEN_Msk;


    /* Update System Core Clock */
    /* User can use SystemCoreClockUpdate() to calculate PllClock, SystemCoreClock and CycylesPerUs automatically. */
    SystemCoreClockUpdate();

    /*---------------------------------------------------------------------------------------------------------*/
    /* Init I/O Multi-function                                                                                 */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Set multi-function pins for UART0 RXD and TXD */
    //SYS->GPB_MFPH = (SYS->GPB_MFPH & (~(UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk))) | UART0_RXD_PB12 | UART0_TXD_PB13;
    SET_UART0_RXD_PA6();
    SET_UART0_TXD_PA7();

}

void DEBUG_PORT_Init()
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART                                                                                               */
    /*---------------------------------------------------------------------------------------------------------*/
    DEBUG_PORT->LINE = UART_PARITY_NONE | UART_STOP_BIT_1 | UART_WORD_LEN_8;
    DEBUG_PORT->BAUD = UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(__HIRC, 115200);

}


int32_t SM3(uint32_t* pu32Addr, int32_t size, uint32_t digest[])
{
#if 1
    int32_t timeout;
    int32_t i;

    /* Enable CRYPTO */
    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;

    /* Init SHA */
    CRPT->HMAC_CTL = (SHA_MODE_SHA256 << CRPT_HMAC_CTL_OPMODE_Pos) | CRPT_HMAC_CTL_SM3EN_Msk | CRPT_HMAC_CTL_DMAEN_Msk | CRPT_HMAC_CTL_DMALAST_Msk | CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk;
    CRPT->HMAC_DMACNT = size;
    CRPT->HMAC_SADDR = (uint32_t)pu32Addr;
    
    /* Clear status */
    CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk;

    /* Trigger to start SHA processing */
    CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;

    /* Waiting for SHA data input ready */
    timeout = SystemCoreClock;
    while((CRPT->INTSTS & CRPT_INTSTS_HMACIF_Msk) == 0)
    {
        if(timeout-- <= 0)
            return -1;
    }

    /* return SHA results */
    for(i = 0; i < 8; i++)
        digest[i] = CRPT->HMAC_DGST[i];

    return 0;

#else

    int32_t i;

    /* Enable CRYPTO */
    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;

    /* Init SHA */
    CRPT->HMAC_CTL = (SHA_MODE_SHA256 << CRPT_HMAC_CTL_OPMODE_Pos) | CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_SM3EN_Msk;
    CRPT->HMAC_DMACNT = size;

    /* Calculate SHA */
    while(size > 0)
    {
        if(size <= 4)
        {
            CRPT->HMAC_CTL |= CRPT_HMAC_CTL_DMALAST_Msk;
        }

        /* Trigger to start SHA processing */
        CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;

        /* Waiting for SHA data input ready */
        while((CRPT->HMAC_STS & CRPT_HMAC_STS_DATINREQ_Msk) == 0);

        /* Input new SHA date */
        CRPT->HMAC_DATIN = *pu32Addr;
        pu32Addr++;
        size -= 4;
    }

    /* Waiting for calculation done */
    while(CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk);

    /* return SHA results */
    for(i = 0; i < 8; i++)
        digest[i] = CRPT->HMAC_DGST[i];
#endif


    return 0;
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
int32_t main(void)
{
    int32_t i, j, nbits, m, err;
    uint32_t time;
    uint32_t au32r[(KEY_LENGTH + 31) / 32];
    uint8_t *au8r;
    uint32_t hash[8];

    SYS_UnlockReg();

    /* Init System, IP clock and multi-function I/O */
    SYS_Init();

    /* Init UART for printf */
    DEBUG_PORT_Init(); 

    printf("+---------------------------------------------+\n");
    printf("|            Crypto SM2 Demo                  |\n");
    printf("+---------------------------------------------+\n");

    NVIC_EnableIRQ(CRPT_IRQn);
    ECC_ENABLE_INT(CRPT);

    nbits = KEY_LENGTH;
    au8r = (uint8_t*)&au32r[0];

#if (defined(GEN_PRIV_KEY) || defined(RANDOM_K))
    err = RNG_Open();
    if(err)
    {
        printf("Fail to open random generator!\n");
    }
#endif

    /* hash the message */
    SM3((uint32_t*)msg, 3, hash);
    sprintf(e, "%08x%08x%08x%08x%08x%08x%08x%08x", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
    printf("msg         = %s\n", msg);
    printf("e           = %s\n", e);

#ifdef GEN_PRIV_KEY

    do
    {

        /* Generate random number for private key */
        //BL_Random(&rng, au8r, (nbits+7) / 8);
        RNG_Random(au32r, (nbits + 31) / 32);

        for(i = 0, j = 0; i < nbits / 8; i++)
        {
            d[j++] = Byte2Char(au8r[i] & 0xf);
            d[j++] = Byte2Char(au8r[i] >> 4);
        }
        d[j] = 0; // NULL end

        /* Check if the private key valid */
        if(ECC_IsPrivateKeyValid(CRPT, CURVE_P_SIZE, d))
        {
            break;
        }
        else
        {
            /* Invalid key */
            printf("Current private key is not valid. Need a new one.\n");
        }
    }
    while(1);
#else

    /* Use fixed private key */
    strcpy(d, "d2dfd278d14e2cdbf4d1275de45ce6d26d8f9d5094659fa43e44e94a253a2dce");
#endif
    printf("Private key = %s\n", d);

    /* Enable SysTick */
    SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;

    /* Reset SysTick to measure time */
    SysTick->VAL = 0;
    if(ECC_GeneratePublicKey(CRPT, CURVE_P_SIZE, d, Qx, Qy) < 0)
    {
        printf("ECC key generation failed!!\n");
        while(1);
    }
    time = 0xffffff - SysTick->VAL;

    printf("Public Qx   = %s\n", Qx);
    printf("Public Qy   = %s\n", Qy);
    printf("Elapsed time: %d.%d ms\n", time / CyclesPerUs / 1000, time / CyclesPerUs % 1000);

    /*
        Try to generate signature serveral times with private key and verificate them with the same
        public key.

    */
#ifdef RANDOM_K
    for(m = 0; m < 3; m++)
#endif
    {
        printf("//-------------------------------------------------------------------------//\n");
#ifdef RANDOM_K
        /* Generate random number k */
        RNG_Random(au32r, (nbits + 7) / 8);

        for(i = 0, j = 0; i < nbits / 8; i++)
        {
            k[j++] = Byte2Char(au8r[i] & 0xf);
            k[j++] = Byte2Char(au8r[i] >> 4);
        }
        k[j] = 0; // NULL End
#else
        strcpy(k, "98d5e030e1955bbcf332029c7becafdba683422f8cb0e5fd086867a65c25c20c");
#endif

        printf("  k   = %s\n", k);

        if(ECC_IsPrivateKeyValid(CRPT, CURVE_P_SIZE, k))
        {
            /* Private key check ok */
        }
        else
        {
            /* Invalid key */
            printf("Current k is not valid\n");
#ifdef RANDOM_K
            break;
#endif

        }

        SysTick->VAL = 0;
        if(SM2_Sign(CRPT, CURVE_P_SIZE, e, d, k, R, S) < 0)
        {
            printf("ECC signature generation failed!!\n");
#ifdef RANDOM_K
            break;
#endif
        }
        time = 0xffffff - SysTick->VAL;

        printf("  R  = %s\n", R);
        printf("  S  = %s\n", S);
        printf("Elapsed time: %d.%d ms\n", time / CyclesPerUs / 1000, time / CyclesPerUs % 1000);

        SysTick->VAL = 0;
        err = SM2_Verify(CRPT, CURVE_P_SIZE, e, Qx, Qy, R, S);
        time = 0xffffff - SysTick->VAL;
        if(err < 0)
        {
            printf("ECC signature verification failed!!\n");
#ifdef RANDOM_K
            break;
#endif
        }
        else
        {
            printf("ECC digital signature verification OK.\n");
        }
        printf("Elapsed time: %d.%d ms\n", time / CyclesPerUs / 1000, time / CyclesPerUs % 1000);
    }

#if (!defined(GEN_PRIV_KEY) && !defined(RANDOM_K))
    if(strcmp(e, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"))
        printf("SM3 hash value is wrong!\n");
    if(strcmp(Qx, "51dd00daee5b218d9c949e2762162d4292819e5ab3404b89638561813fcbf0d7"))
        printf("Public key 1 value is wrong!\n");
    if(strcmp(Qy, "ad57f1ac29ae44d262ef96f81a63da266c21b23ec82d34567f1b6b1cf7bbcc7c"))
        printf("Public key 2 value is wrong!\n");
    if(strcmp(R, "33b5ce127dadab5857333e335f39823c369e5bba7f8c58e40336b67e26e26ae8"))
        printf("SM2 sign R value is wrong!\n");
    if(strcmp(S, "e07742bea793bb427901bdffd4f4124aca712ff9df23b8f68b3ccf4265589881"))
        printf("SM2 sign S value is wrong!\n");
#endif



    while(1);
}



