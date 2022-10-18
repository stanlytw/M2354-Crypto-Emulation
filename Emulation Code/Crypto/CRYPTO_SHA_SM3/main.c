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
    PllClock        = FREQ_96MHZ;           // PLL
    SystemCoreClock = FREQ_96MHZ;       // HCLK
    CyclesPerUs     = FREQ_96MHZ / 1000000;  // For SYS_SysTickDelay()

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


int32_t SM3(uint32_t *pu32Addr, int32_t size, uint32_t digest[])
{
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

    // Delay for a while
    //CLK_SysTickLongDelay(1000000);

    /* return SHA results */
    for(i = 0; i < 8; i++)
        digest[i] = CRPT->HMAC_DGST[i];

    return 0;
}

const __attribute__((aligned(4))) uint8_t g_au8Test[3] =
{
    0x61, 0x62, 0x63
};


const __attribute__((aligned(4))) uint8_t g_au8Test2[64] =
{
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64
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
    printf("|      M2354 Crypto SM3 Test        |\n");
    printf("+-----------------------------------+\n");

    NVIC_EnableIRQ(CRPT_IRQn);

    printf("Input data:\n");
    for(i = 0; i < 3; i++)
    {
        printf("%02x", g_au8Test[i]);
    }
    printf("\n");

    SM3((uint32_t *)g_au8Test, 3, hash);

    printf("\nOutput Hash:\n");
    printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);

    printf("The result should be:\n");
    // The result should be:
    printf("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0\n\n");

    ans[0] = 0x66c7f0f4;
    ans[1] = 0x62eeedd9;
    ans[2] = 0xd1f2d46b;
    ans[3] = 0xdc10e4e2;
    ans[4] = 0x4167c487;
    ans[5] = 0x5cf2f7a2;
    ans[6] = 0x297da02b;
    ans[7] = 0x8f4ba8e0;
    
    for(i = 0; i < 8; i++)
    {
        if(ans[i] != hash[i])
        {
            printf("SHA256 result compare fail!\n");
            PA->DOUT = 1;
            while(1);
        }
    }
    
    
    printf("Input data2:\n");
    for(i = 0; i < 64; i++)
    {
        printf("%02x", g_au8Test2[i]);
    }
    printf("\n");

    SM3((uint32_t *)g_au8Test2, 64, hash);

    printf("\nOutput Hash:\n");
    printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);

    printf("The result should be:\n");
    // The result should be:
    printf("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732\n\n");

    ans[0] = 0xdebe9ff9;
    ans[1] = 0x2275b8a1;
    ans[2] = 0x38604889;
    ans[3] = 0xc18e5a4d;
    ans[4] = 0x6fdb70e5;
    ans[5] = 0x387e5765;
    ans[6] = 0x293dcba3;
    ans[7] = 0x9c0c5732;    
    
    for(i = 0; i < 8; i++)
    {
        if(ans[i] != hash[i])
        {
            printf("SHA256 result compare fail!\n");
            PA->DOUT = 1;
            while(1);
        }
    }

    printf("SM3 Test Pass!\n");
    
    PA->DOUT = 2;

    while(1);
}
