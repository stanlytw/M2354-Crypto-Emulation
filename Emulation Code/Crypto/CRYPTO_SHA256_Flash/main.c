/**************************************************************************//**
 * @file     main.c
 * @version  V1.00
 * @brief    Show how to calculate SHA256 of the data in Flash.
 *
 *
 * @copyright (C) 2016 Nuvoton Technology Corp. All rights reserved.
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "NuMicro.h"

//#define printf(...)

void SYS_Init(void)
{
    /* Enable PLL */
    //CLK->PLLCTL = CLK_PLLCTL_128MHz_HIRC;

    /* Waiting for PLL stable */
    //while((CLK->STATUS & CLK_STATUS_PLLSTB_Msk) == 0);

    /* Set HCLK divider to 2 */
    //CLK->CLKDIV0 = (CLK->CLKDIV0 & (~CLK_CLKDIV0_HCLKDIV_Msk)) | 1;

    /* Switch HCLK clock source to PLL */
    //CLK->CLKSEL0 = (CLK->CLKSEL0 & (~CLK_CLKSEL0_HCLKSEL_Msk)) | CLK_CLKSEL0_HCLKSEL_PLL;

    
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


int32_t SHA256(uint32_t *pu32Addr, int32_t size, uint32_t digest[])
{
    int32_t i;

    /* Enable CRYPTO */
    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;

    /* Init SHA */
    CRPT->HMAC_CTL = (SHA_MODE_SHA256 << CRPT_HMAC_CTL_OPMODE_Pos) | CRPT_HMAC_CTL_INSWAP_Msk;
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

    // Delay for a while
    //CLK_SysTickLongDelay(1000000);

    /* return SHA results */
    for(i = 0; i < 8; i++)
        digest[i] = CRPT->HMAC_DGST[i];

    return 0;
}

const __attribute__((aligned(4))) uint8_t g_au8Test[32] =
{
    0x64, 0x36, 0x2E, 0x4D, 0x28, 0x16, 0x0D, 0xB4, 0x44, 0xEF, 0x39
    , 0x47, 0xE1, 0xC4, 0x05, 0x51, 0x51, 0x8C, 0x71, 0xE7, 0x50, 0x30
    , 0x7C, 0xA4, 0x93, 0xD5, 0xC8, 0x10, 0x3E, 0xD2, 0xBF, 0x53
};

/*-----------------------------------------------------------------------------*/
int main(void)
{
    uint32_t hash[8] = {0};
    int32_t i;
    uint32_t ans[8];

    SYS_UnlockReg();

    /* Init System, IP clock and multi-function I/O */
    SYS_Init();

    /* Init UART0 for printf */
    DEBUG_PORT_Init();

    printf("+-----------------------------------+\n");
    printf("|  M2355 Crypto SHA Sample Demo      |\n");
    printf("+-----------------------------------+\n");

    NVIC_EnableIRQ(CRPT_IRQn);

    printf("Input data:\n");
    for(i = 0; i < 32; i++)
    {
        printf("%02x", g_au8Test[i]);
    }
    printf("\n");

    SHA256((uint32_t *)g_au8Test, 32, hash);

    printf("\nOutput Hash:\n");
    printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);

    printf("The result should be:\n");
    // The result should be:
    printf("0794275e5931708bfce9d2a9f28d9465fe9dab9ed29198e9e40a23452dea973d\n\n");

    ans[0] = 0x0794275e;
    ans[1] = 0x5931708b;
    ans[2] = 0xfce9d2a9;
    ans[3] = 0xf28d9465;
    ans[4] = 0xfe9dab9e;
    ans[5] = 0xd29198e9;
    ans[6] = 0xe40a2345;
    ans[7] = 0x2dea973d;

    for(i = 0; i < 8; i++)
    {
        if(ans[i] != hash[i])
        {
            printf("SHA256 result compare fail!\n");
            PA->DOUT = 1;
            while(1);
        }
    }

    printf("SHA256 Test Pass!\n");

    PA->DOUT = 2;

    while(1);
}
