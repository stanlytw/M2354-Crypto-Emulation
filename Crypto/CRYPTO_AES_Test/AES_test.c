/*---------------------------------------------------------------------------------------------------------*/
/*                                                                                                         */
/* Copyright(c) 2010 Nuvoton Technology Corp. All rights reserved.                                         */
/*                                                                                                         */
/*---------------------------------------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "NuMicro.h"
#include "crypto.h"

#define IS_REAL_CHIP

#define BUFF_SIZE           1024

#define SECURE_CODE_BASE    0x0             // Flash address
#define SECURE_CODE_LEN     32


volatile int g_AES_done, g_AESERR_done;
volatile int g_HMAC_done;

uint32_t au32MyAESKey[8] =
{
    0x10214387, 0x0f1f3e7c, 0xf8f1e3c6, 0x8c193265, 0xcb962d5a, 0xb56bd6ad, 0x5ab56bd6, 0xad5ab468
};

uint32_t au32MyAESIV[4] =
{
    0x00000000, 0x00000000, 0x00000000, 0x00000000
};

#pragma data_alignment=4
uint8_t au8InputData[BUFF_SIZE] =
{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};


uint32_t au32SHAData[8] =
{
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x11111111
};

#pragma data_alignment=4
uint8_t au8OutputData[BUFF_SIZE];
#pragma data_alignment=4
uint8_t au8CascadeOut[BUFF_SIZE];


extern int  AES_KAT_test(void);

#define PLLCON_SETTING      CLK_PLLCTL_96MHz_HXT
#define PLL_CLOCK           12000000



void SYS_Init(void)
{
    int32_t i;
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init System Clock                                                                                       */
    /*---------------------------------------------------------------------------------------------------------*/

    /* Enable External XTAL (4~24 MHz) */
    CLK->PWRCTL |= CLK_PWRCTL_HXTEN_Msk;

//    CLK->PLLCTL = PLLCON_SETTING;

//    /* Waiting for clock ready */
//    i = 2200; // For timeout
//    while(i-- > 0)
//    {
//        if((CLK->STATUS & (CLK_STATUS_PLLSTB_Msk | CLK_STATUS_HXTSTB_Msk)) ==
//                (CLK_STATUS_PLLSTB_Msk | CLK_STATUS_HXTSTB_Msk))
//            break;
//    }

    /* Switch HCLK clock source to HXT */
    CLK->CLKSEL0 = CLK_CLKSEL0_HCLKSEL_HXT;
    CLK->CLKDIV0 = 0;

    /* Enable IP clock */
    CLK->APBCLK0 |= CLK_APBCLK0_UART0CKEN_Msk | CLK_APBCLK0_UART1CKEN_Msk | CLK_APBCLK0_UART2CKEN_Msk;

    /* Select IP clock source */
    CLK->CLKSEL2 = CLK_CLKSEL2_UART0SEL_HXT;//CLK_CLKSEL1_UARTSEL_HXT;

    /* Update System Core Clock */
    /* User can use SystemCoreClockUpdate() to calculate PllClock, SystemCoreClock and CycylesPerUs automatically. */
    //SystemCoreClockUpdate();
    PllClock        = PLL_CLOCK;            // PLL
    SystemCoreClock = PLL_CLOCK / 1;        // HCLK
    CyclesPerUs     = PLL_CLOCK / 1000000;  // For SYS_SysTickDelay()

    /*---------------------------------------------------------------------------------------------------------*/
    /* Init I/O Multi-function                                                                                 */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Set P3 multi-function pins for UART0 RXD and TXD */
    //SYS->GPD_MFPL = SYS_GPD_MFPL_PD0MFP_UART0_RXD | SYS_GPD_MFPL_PD1MFP_UART0_TXD;
    //SYS->GPA_MFPL = SYS_GPA_MFPL_PA1MFP_UART1_RXD | SYS_GPA_MFPL_PA0MFP_UART1_TXD;
    //SYS->GPA_MFPH = SYS_GPA_MFPH_PA12MFP_UART2_RXD | SYS_GPA_MFPH_PA13MFP_UART2_TXD;
    //SYS->GPA_MFPH = SYS_GPA_MFPH_PA12MFP_UART1_RXD | SYS_GPA_MFPH_PA13MFP_UART1_TXD;
    //SYS->GPE_MFPL = SYS_GPE_MFPH_PE8MFP_UART1_TXD | SYS_GPE_MFPH_PE9MFP_UART1_RXD;

//    SYS->GPG_MFPL = 0x30000000ul;
//    SYS->GPG_MFPH = 0x00000003ul;

    //SYS->GPC_MFPH = UART0_TXD_PC12 | UART0_RXD_PC11;
    //SYS->GPD_MFPL = UART0_RXD_PD2 | UART0_TXD_PD3;
    //SYS->GPA_MFPL = UART0_RXD_PA0 | UART0_TXD_PA1;
    //SYS->GPB_MFPH = (SYS->GPB_MFPH & (~(UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk))) | UART0_RXD_PB12 | UART0_TXD_PB13;
    SYS->GPA_MFPL = (SYS->GPA_MFPL & (~(UART0_RXD_PA6_Msk | UART0_TXD_PA7_Msk))) | UART0_RXD_PA6 | UART0_TXD_PA7;

    // power gating
    M32(0x400001f4) = 0xfffffffful;
    // GPIO clk
    CLK->AHBCLK |= (0xff << 24);



}


void UART0_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART                                                                                               */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Reset IP */

    /* Configure UART0 and set UART0 Baudrate */
    UART0->BAUD = UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(__HXT, 115200);
    UART0->LINE = UART_WORD_LEN_8 | UART_PARITY_NONE | UART_STOP_BIT_1;
}

void CRPT_IRQHandler()
{
    if(CRPT->INTSTS & CRPT_INTSTS_AESIF_Msk)
    {
        g_AES_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk;
    }

    if(CRPT->INTSTS & CRPT_INTSTS_AESEIF_Msk)
    {
        g_AESERR_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_AESEIF_Msk;
        printf("AESERRIF is set!!\n");
    }

    if(CRPT->INTSTS & (CRPT_INTSTS_HMACIF_Msk | CRPT_INTSTS_HMACEIF_Msk))
    {
        g_HMAC_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk | CRPT_INTSTS_HMACEIF_Msk;
    }
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

void  AES_dump_key()
{
    int  i;

    printf("AES KEY: ");
    printf("AES KEY (%s): ", CRPT->AES_CTL & CRPT_AES_CTL_KEYPRT_Msk ? "LOCK" : "UNLOCK");
    for(i = 0; i < 8; i++)
        printf("%x ", CRPT->AES_KEY[i]);
    printf("\n");
}


int AES_basic_test(int use_irq)
{
    /*---------------------------------------
     *  AES-128 ECB mode encrypt
     *---------------------------------------*/
    AES_Open(CRPT, 0, 1, AES_MODE_ECB, AES_KEY_SIZE_128, AES_IN_OUT_SWAP);
    AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_128);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)au8InputData, (uint32_t)au8OutputData, sizeof(au8InputData));
    printf("Source\n");
    dump_buff_hex(au8InputData, 16);
    if(use_irq)
    {
        AES_ENABLE_INT(CRPT);
        g_AES_done = 0;
        AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
        while(!g_AES_done);
    }
    else
    {
        AES_DISABLE_INT(CRPT);
        AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
        while(CRPT->AES_STS & CRPT_AES_STS_BUSY_Msk);
        while(CRPT->AES_CTL & CRPT_AES_CTL_START_Msk);
    }

    printf("AES encrypt done.\n\n");
    dump_buff_hex(au8OutputData, 16);

    AES_dump_key();

    /*---------------------------------------
     *  AES-128 ECB mode decrypt
     *---------------------------------------*/
    AES_Open(CRPT, 0, 0, AES_MODE_ECB, AES_KEY_SIZE_128, AES_IN_OUT_SWAP);
    AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_128);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)au8OutputData, (uint32_t)au8InputData, sizeof(au8InputData));

    if(use_irq)
    {
        AES_ENABLE_INT(CRPT);
        g_AES_done = 0;
        AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
        while(!g_AES_done);
    }
    else
    {
        AES_DISABLE_INT(CRPT);
        AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
        while(CRPT->AES_STS & CRPT_AES_STS_BUSY_Msk);
        while(CRPT->AES_CTL & CRPT_AES_CTL_START_Msk);
    }

    printf("AES decrypt done.\n\n");

    printf("Output\n");
    dump_buff_hex(au8InputData, 16);

    printf("Press any key to continue...\n");
    return 0;
}


int AES_cascade_test(int keysz, int opmode)
{
    int  i, count;

    memset(au8OutputData, 0, BUFF_SIZE);
    memset(au8CascadeOut, 0, BUFF_SIZE);

    /*---------------------------------------
     *  AES-256 CBC mode one-shot encrypt
     *---------------------------------------*/
    AES_Open(CRPT, 0, 1, opmode, keysz, AES_IN_OUT_SWAP);
    AES_SetKey(CRPT, 0, au32MyAESKey, keysz);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)au8InputData, (uint32_t)au8OutputData, BUFF_SIZE);

    printf("Source\n");
    dump_buff_hex(au8InputData, sizeof(au8InputData));

    g_AES_done = 0;
    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
    while(!g_AES_done);

    printf("Output\n");
    dump_buff_hex(au8OutputData, sizeof(au8OutputData));
    printf("AES one-shot encrypt done.\n\n");

    /*---------------------------------------
     *  AES-256 CBC mode cascade encrypt
     *---------------------------------------*/
    AES_Open(CRPT, 0, 1, opmode, keysz, AES_IN_OUT_SWAP);
    AES_SetKey(CRPT, 0, au32MyAESKey, keysz);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)au8InputData, (uint32_t)au8CascadeOut, BUFF_SIZE);

    for(count = 0; count < BUFF_SIZE; count += 64)
    {
        AES_SetDMATransfer(CRPT, 0, (uint32_t)au8InputData + count, (uint32_t)au8CascadeOut + count, 64);

        printf("Round %d\n", count / 64);
        printf(" Input  address 0x%08X\n", (uint32_t)au8InputData + count);
        printf(" Output address 0x%08X\n", (uint32_t)au8CascadeOut + count);
        g_AES_done = 0;
        if(count == 0)
        {
            printf("  [DMA_FIRST]\n");
            AES_Start(CRPT, 0, CRYPTO_DMA_FIRST);
        }
        else if(count >= BUFF_SIZE - 64)
        {
            printf("  [DMA_LAST]\n");
            AES_Start(CRPT, 0, CRYPTO_DMA_LAST);
        }
        else
            AES_Start(CRPT, 0, CRYPTO_DMA_CONTINUE);
        while(!g_AES_done);
    }

    printf("AES cascade encrypt done.\n\n");

    printf("Result Check..");
    for(i = 0; i < BUFF_SIZE; i ++)
    {
        if(au8OutputData[i] != au8CascadeOut[i])
        {
            printf("Data mismatch at offset 0x%x!\n", i);
            dump_buff_hex(au8OutputData, 16);
            dump_buff_hex(au8CascadeOut, 16);
            return -1;
        }
    }
    printf("Pass\n\n");
    //dump_buff_hex(au8OutputData, BUFF_SIZE);
    return 0;
}


int  AES_force_stop_test(void)
{
    int i = 0;

    for(i = 0; i < 16; i++)
        au8InputData[i] = 0x11 * i;
    for(i = 0; i < 20; i++)
    {
        if(i % 2)
        {
            printf("Loop %d Force Stop\n", i);
            /*---------------------------------------
             *  AES-256 CBC mode one-shot encrypt
             *---------------------------------------*/
            AES_Open(CRPT, 0, 1, AES_MODE_CBC, AES_KEY_SIZE_256, AES_IN_OUT_SWAP);
            AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_256);
            AES_SetInitVect(CRPT, 0, au32MyAESIV);
            AES_SetDMATransfer(CRPT, 0, (uint32_t)au8InputData, (uint32_t)au8OutputData, BUFF_SIZE);

            g_AES_done = 0;
            AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
            if((CRPT->AES_STS & CRPT_AES_STS_BUSY_Msk) == 0)
                printf("AES_STS BUSY bit was not set!!\n");
            CRPT->AES_CTL = CRPT_AES_CTL_STOP_Msk;
            if((CRPT->AES_STS & CRPT_AES_STS_BUSY_Msk))
            {
                printf("AES_STS BUSY bit was not cleared!!\n");
                return -1;
            }
        }
        else
        {

            printf("Loop %d\n", i);
            /*---------------------------------------
             *  AES-128 ECB mode encrypt
             *---------------------------------------*/
            AES_Open(CRPT, 0, 1, AES_MODE_ECB, AES_KEY_SIZE_128, AES_IN_OUT_SWAP);
            AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_128);
            AES_SetInitVect(CRPT, 0, au32MyAESIV);
            AES_SetDMATransfer(CRPT, 0, (uint32_t)au8InputData, (uint32_t)au8OutputData, sizeof(au8InputData));
            printf("Source\n");
            dump_buff_hex(au8InputData, 16);
            AES_DISABLE_INT(CRPT);
            AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
            while(CRPT->AES_STS & CRPT_AES_STS_BUSY_Msk);
            while(CRPT->AES_CTL & CRPT_AES_CTL_START_Msk);

            printf("AES encrypt done.\n\n");
            dump_buff_hex(au8OutputData, 16);

            AES_dump_key();

            /*---------------------------------------
             *  AES-128 ECB mode decrypt
             *---------------------------------------*/
            AES_Open(CRPT, 0, 0, AES_MODE_ECB, AES_KEY_SIZE_128, AES_IN_OUT_SWAP);
            AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_128);
            AES_SetInitVect(CRPT, 0, au32MyAESIV);
            AES_SetDMATransfer(CRPT, 0, (uint32_t)au8OutputData, (uint32_t)au8InputData, sizeof(au8InputData));

            AES_DISABLE_INT(CRPT);
            AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
            while(CRPT->AES_STS & CRPT_AES_STS_BUSY_Msk);
            while(CRPT->AES_CTL & CRPT_AES_CTL_START_Msk);

            printf("AES decrypt done.\n\n");
            printf("Output\n");
            dump_buff_hex(au8InputData, 16);
        }
    }

    return 0;
}

int  AES_DMA_invalid_test()
{
    /*---------------------------------------
     *  AES-128 ECB mode encrypt
     *---------------------------------------*/
    AES_Open(CRPT, 0, 1, AES_MODE_ECB, AES_KEY_SIZE_128, AES_IN_OUT_SWAP);
    AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_128);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT, 0, 0x5000000, (uint32_t)au8OutputData, sizeof(au8InputData));

    g_AESERR_done = 0;
    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
    while(!g_AESERR_done);

    if(!(CRPT->AES_STS & CRPT_AES_STS_BUSERR_Msk))
    {
        printf("AES_STS = 0x%x\n", CRPT->AES_STS);
        printf("BUSERR(AES_STS[20]) is not set!!\n");
        return -1;
    }

    /*---------------------------------------
     *  AES-128 ECB mode encrypt
     *---------------------------------------*/
    AES_Open(CRPT, 0, 1, AES_MODE_ECB, AES_KEY_SIZE_128, AES_IN_OUT_SWAP);
    AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_128);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)au8InputData, 0x5000000, sizeof(au8InputData));

    g_AESERR_done = 0;
    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
    while(!g_AESERR_done);

    if(CRPT->AES_STS & CRPT_AES_STS_BUSERR_Msk)
        return 0;
    {
        printf("AES_STS = 0x%x\n", CRPT->AES_STS);
        printf("BUSERR(AES_STS[20]) is not set!!\n");
        return -1;
    }
}


static uint32_t  var_key = 0x123456;

int AES_key_protect_test()
{
    int   i;

    /*---------------------------------------
     *  AES-128 ECB mode encrypt
     *---------------------------------------*/
    AES_Open(CRPT, 0, 1, AES_MODE_ECB, AES_KEY_SIZE_256, AES_IN_OUT_SWAP);
    AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_256);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)au8InputData, (uint32_t)au8OutputData, sizeof(au8InputData));

    g_AES_done = 0;
    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
    while(!g_AES_done);

    printf("AES encrypt done.\n\n");
    dump_buff_hex(au8OutputData, 16);

    /*---------------------------------------
     *  AES-128 ECB mode decrypt
     *---------------------------------------*/
    printf("Lock AES key and decrypt again...\n");
    AES_Open(CRPT, 0, 0, AES_MODE_ECB, AES_KEY_SIZE_256, AES_IN_OUT_SWAP);
    CRPT->AES_CTL = CRPT_AES_CTL_KEYPRT_Msk;
    AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_256);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)au8OutputData, (uint32_t)au8InputData, sizeof(au8InputData));

    AES_dump_key();

    AES_ENABLE_INT(CRPT);
    g_AES_done = 0;
    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
    while(!g_AES_done);

    printf("AES decrypt done.\n\n");
    dump_buff_hex(au8InputData, 16);

    printf("Unprotect AES key...\n");

    CRPT->AES_CTL = 0x58000000;
    AES_dump_key();

    printf("Decrypt again. Because AES key was deleted, we should get different result.\n");
    AES_Open(CRPT, 0, 0, AES_MODE_ECB, AES_KEY_SIZE_256, AES_IN_OUT_SWAP);
    //AES_SetKey(0, au32MyAESKey, AES_KEY_SIZE_256);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    memset(au8InputData, 0, sizeof(au8InputData));
    AES_SetDMATransfer(CRPT, 0, (uint32_t)au8OutputData, (uint32_t)au8InputData, sizeof(au8InputData));

    AES_ENABLE_INT(CRPT);
    g_AES_done = 0;
    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
    while(!g_AES_done);

    printf("AES decrypt done. The output should be different.\n\n");
    AES_dump_key();
    dump_buff_hex(au8InputData, 16);
    for(i = 0; i < 16; i++)
        au8InputData[i] = 0x11 * i;
    printf("Press any key to continue...\n");
    return 0;
}

#if 0
int AES_secure_boot_verify_test()
{
    uint32_t    code_ptr;
    int         i, data_cnt;

    FMC->ISPCTL = 0x7d;

    SHA_ENABLE_INT(CRPT);

    /*---------------------------------------------------------
     *  Use SHA-256 to get digest of boot image (1 Kbyes)
     *---------------------------------------------------------*/

    printf("[Using SHA-256 S/W mode to calculate boot image]\n");
    CRPT->HMAC_CTL = (SHA_MODE_SHA256 << CRPT_HMAC_CTL_OPMODE_Pos) | CRPT_HMAC_CTL_INSWAP_Msk;
    CRPT->HMAC_DMACNT = SECURE_CODE_LEN;

    code_ptr = SECURE_CODE_BASE;
    data_cnt = CRPT->HMAC_DMACNT;
    CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;

    while(data_cnt > 0)
    {
        if(CRPT->HMAC_STS & CRPT_HMAC_STS_DATINREQ_Msk)
        {
            if(data_cnt - 4 <= 0)
            {
                CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk | CRPT_HMAC_CTL_DMALAST_Msk;
            }

            CRPT->HMAC_DATIN = FMC_Read(code_ptr);
            data_cnt -= 4;
            code_ptr += 4;
        }
    }
    while(!g_HMAC_done) ;

    while(CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk)
        printf("!");

    printf("    Output plain digest is =>\n    ");
    for(i = 0; i < 8; i++)
        printf("%08x ", CRPT->HMAC_DGST[i]);
    printf("\n\n");

    /*--------------------------------------------------------
     *  Using AES-256 ECB to encrypt SHA plain digest...
     *--------------------------------------------------------*/

    printf("[Using AES-256 ECB to encrypt SHA plain digest] \n");

    // Write SHA plain digest to AES input buffer
    for(i = 0; i < 8; i++)
        outpw((uint32_t)&au8InputData[i * 4], CRPT->HMAC_DGST[i]);

    // Set initial vector as 000000000-000000000-000000000-000000000
    for(i = 0; i < 4; i++)
        au32MyAESIV[i] = 0;

    AES_Open(CRPT, 0, 1, AES_MODE_ECB, AES_KEY_SIZE_256, AES_NO_SWAP);
    AES_SetKey(CRPT, 0, au32MyAESKey, AES_KEY_SIZE_256);
    AES_SetInitVect(CRPT, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)au8InputData, (uint32_t)au8OutputData, 32);

    printf("    AES key is =>\n    ");
    for(i = 0; i < 8; i++)
        printf("%08x ", CRPT->AES0_KEY[i]);
    printf("\n\n");

    AES_ENABLE_INT(CRPT);
    g_AES_done = 0;
    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
    while(!g_AES_done);

    printf("    Output cypher digest is =>\n    ");
    for(i = 0; i < 8; i++)
        printf("%08x ", inpw(&au8OutputData[i * 4]));
    printf("\n\n");

    /*--------------------------------------------------------
     *  Write cypher digest to AES0_KEY0 ~ AES0_KEY7
     *--------------------------------------------------------*/

    printf("[Write cypher digest to AES0_KEY0 ~ AES0_KEY7]\n");

    for(i = 0; i < 8; i++)
        CRPT->AES0_KEY[i] = inpw(&au8OutputData[i * 4]);
    printf("\n\n");

    /*--------------------------------------------------------
     *  Setup secure boot key
     *--------------------------------------------------------*/

    printf("[Setup secure boot key]\n");

    printf("    Secure boot key key is =>\n    ");
    for(i = 0; i < 8; i++)
        printf("%08x ", au32MyAESKey[i]);
    printf("\n");

    FMC_ENABLE_CFG_UPDATE();

    FMC_Erase(0x300000);
    for(i = 0; i < 8; i++)
        FMC_Write(0x0060C100 + i * 4, au32MyAESKey[i]);
    FMC_Write(0x0060C120, 1);

    while(FMC->KPKEYSTS & FMC_KPKEYSTS_SBKPBUSY_Msk) ;

    if(FMC->KPKEYSTS & FMC_KPKEYSTS_SBKPFLAG_Msk)
    {
        printf("    Secure boot key setup failed! SBKFLAG is 1!\n");
        return -1;
    }
    else
        printf("    Secure boot key setup OK.\n");

    /*--------------------------------------------------------
     *  Start AES secure boot verification
     *--------------------------------------------------------*/

    printf("[Start AES secure boot verification]\n");

#define CRPT_AES_CTL_SBVSTART_Pos        (17)                                              /*!< CRPT AES_CTL: SBVSTART Position        */
#define CRPT_AES_CTL_SBVSTART_Msk        (0x1ul << CRPT_AES_CTL_SBVSTART_Pos)              /*!< CRPT AES_CTL: SBVSTART Mask            */

#define CRPT_AES_STS_SBVBUSY_Pos         (24)                                              /*!< CRPT AES_STS: SBVBUSY Position         */
#define CRPT_AES_STS_SBVBUSY_Msk         (0x1ul << CRPT_AES_STS_SBVBUSY_Pos)               /*!< CRPT AES_STS: SBVBUSY Mask             */

#define CRPT_AES_STS_SBVERR_Pos          (25)                                              /*!< CRPT AES_STS: SBVERR Position          */
#define CRPT_AES_STS_SBVERR_Msk          (0x1ul << CRPT_AES_STS_SBVERR_Pos)                /*!< CRPT AES_STS: SBVERR Mask              */


    CRPT->AES_CTL = CRPT_AES_CTL_SBVSTART_Msk;

    while(CRPT->AES_STS & CRPT_AES_STS_SBVBUSY_Msk) ;

    if(CRPT->AES_STS & CRPT_AES_STS_SBVERR_Msk)
    {
        printf("\nSecure boot verification failed!\n");
        return -1;
    }
    else
    {
        printf("\nSecure boot verification pass.\n");
        return 0;
    }
}
#endif


/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
int32_t main(void)
{
    int   i, j;
    int   item, ret;

    /* Disable register write-protection function */
    SYS_UnlockReg();

    /* Initial clocks and multi-functions */
    SYS_Init();

    /* Initial UART */
    UART0_Init();

    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;   // enable crypto engine clock

    SYS->SRAMPC0 = 0;
    SYS->SRAMPC1 = 0;

#if 0
    printf("[Setup secure boot key]\n");

    printf("    Secure boot key key is =>\n    ");
    for(i = 0; i < 8; i++)
        printf("%08x ", au32MyAESKey[i]);
    printf("\n");

    FMC_ENABLE_CFG_UPDATE();

    FMC_Erase(0x300000);
    for(i = 0; i < 8; i++)
        FMC_Write(0x0060C100 + i * 4, au32MyAESKey[i]);
    FMC_Write(0x0060C120, 1);

    while(FMC->KPKEYSTS & FMC_KPKEYSTS_SBKPBUSY_Msk) ;

    if(FMC->KPKEYSTS & FMC_KPKEYSTS_SBKPFLAG_Msk)
    {
        printf("    Secure boot key setup failed! SBKFLAG is 1!\n");
        return -1;
    }
    else
        printf("    Secure boot key setup OK.\n");

    while(1);
#endif

    NVIC_EnableIRQ(CRPT_IRQn);
    AES_ENABLE_INT(CRPT);

    while(1)
    {
        printf("\n");
        printf("+---------------------------------------------------------------+\n");
        printf("|  TC8234 CRYPTO AES test program                               |\n");
        printf("+---------------------------------------------------------------+\n");
        printf("| [1] AES encode/decode pair test                               |\n");
        printf("| [2] AES DMA cascade test                                      |\n");
        printf("| [3] AES NIST known answer test                                |\n");
        printf("| [4] AES force stop test                                       |\n");
        printf("| [5] AES encrypt/decrypt polling                               |\n");
        printf("| [6] AES KEYZE+OPMODE combination test                         |\n");
        printf("| [7] AES DMA invalid test                                      |\n");
//              printf("| [8] AES key protect test                                      |\n");
//              printf("| [9] AES secure boot verification test                         |\n");
        printf("+---------------------------------------------------------------+\n");

        printf("\nSelect [1~9]: \n");

        item = getchar();

        switch(item)
        {
            case '1':
                ret = AES_basic_test(1);
                break;

            case '2':
                ret = AES_cascade_test(AES_KEY_SIZE_256, AES_MODE_CBC);
                break;

            case '3':
                ret = AES_KAT_test();
                break;

            case '4':
                ret = AES_force_stop_test();
                break;

            case '5':
                ret = AES_basic_test(0);
                AES_ENABLE_INT(CRPT);
                break;

            case '6':
                for(i = AES_KEY_SIZE_128; i <= AES_KEY_SIZE_256; i++)
                {
                    for(j = AES_MODE_ECB; j <= AES_MODE_CTR; j++)
                    {
                        ret = AES_cascade_test(i, j);
                        if(ret < 0)
                        {
                            printf("FAILED at %d %d!!\n", i, j);
                            break;
                        }
                    }
                    if(ret < 0) break;
                }
                break;

            case '7':
                ret = AES_DMA_invalid_test();
                break;

            case '8':
                ret = AES_key_protect_test();
                break;

            case '9':
                //ret = AES_secure_boot_verify_test();
                printf("No AES secure boot supported\n");
                break;

            default:
                ret = 1;
                break;
        }

        if(ret == 0)
        {
            printf("\nTest passed. Press any key to continue...\n");
            getchar();
        }

        if(ret < 0)
        {
            printf("\nTest FAILED!!!\n\nPress any key to continue...\n");
            getchar();
        }
    }
    return 0;
}



