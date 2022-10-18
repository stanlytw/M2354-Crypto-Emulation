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


int AES_MasterVIOTest(void);

void SYS_Init(void)
{
    int32_t i;
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init System Clock                                                                                       */
    /*---------------------------------------------------------------------------------------------------------*/

    /* Enable External XTAL (4~24 MHz) */
    //CLK->PWRCTL |= CLK_PWRCTL_HXTEN_Msk;

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
    //CLK->CLKSEL0 = CLK_CLKSEL0_HCLKSEL_HXT;
    
    CLK->PWRCTL |= CLK_PWRCTL_HIRCEN_Msk;
    CLK->CLKSEL0 = CLK_CLKSEL0_HCLKSEL_HIRC;
    CLK->CLKDIV0 = 0;
    
    CLK_SetCoreClock(FREQ_96MHZ);

    /* Enable IP clock */
    CLK->APBCLK0 |= CLK_APBCLK0_UART0CKEN_Msk | CLK_APBCLK0_UART1CKEN_Msk | CLK_APBCLK0_UART2CKEN_Msk;

    /* Select IP clock source */
    CLK->CLKSEL2 = CLK_CLKSEL2_UART0SEL_HIRC;//CLK_CLKSEL1_UARTSEL_HXT;

    /* Update System Core Clock */
    /* User can use SystemCoreClockUpdate() to calculate PllClock, SystemCoreClock and CycylesPerUs automatically. */
    //SystemCoreClockUpdate();
    PllClock        = FREQ_96MHZ;            // PLL
    SystemCoreClock = FREQ_96MHZ / 1;        // HCLK
    CyclesPerUs     = FREQ_96MHZ / 1000000;  // For SYS_SysTickDelay()

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

    SYS->GPB_MFPH = (SYS->GPB_MFPH & (~(UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk))) | UART0_RXD_PB12 | UART0_TXD_PB13;

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
    UART0->BAUD = UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(__HIRC, 115200);
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


int AES_MasterVIOTest(void)
{
    int32_t err = 0;

    printf("CRPT Master Violation Flag/Address/ID Test ... ");

    // Force CRPT to be nonsecure
    SCU->PNSSET[1] |= (1 << 18);

    /*---------------------------------------
     *  AES-128 ECB mode encrypt
     *---------------------------------------*/
    AES_Open(CRPT_NS, 0, 1, AES_MODE_ECB, AES_KEY_SIZE_128, AES_IN_OUT_SWAP);
    AES_SetKey(CRPT_NS, 0, au32MyAESKey, AES_KEY_SIZE_128);
    AES_SetInitVect(CRPT_NS, 0, au32MyAESIV);
    AES_SetDMATransfer(CRPT_NS, 0, (uint32_t)au8InputData, (uint32_t)au8OutputData, sizeof(au8InputData));

    AES_DISABLE_INT(CRPT_NS);
    AES_Start(CRPT_NS, 0, CRYPTO_DMA_ONE_SHOT);
    while(CRPT_NS->AES_STS & CRPT_AES_STS_BUSY_Msk);
    while(CRPT_NS->AES_CTL & CRPT_AES_CTL_START_Msk);

    if(SCU->SVINTSTS != SCU_SVINTSTS_SRAM0IF_Msk)
    {
        printf("\nViolation flag test fail!\n");
        err = -1;
        goto lexit;
    }

    if(SCU->SRAM0VA != (uint32_t)&au8InputData)
    {
        printf("\nViolation address test fail!\n");
        err = -1;
        goto lexit;
    }

    if(SCU->SRAM0VSRC != 5)
    {
        printf("\nViolation source master test fail\n");
        err = -1;
        goto lexit;
    }

    printf("[PASS]\n");

lexit:

    return err;
}



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

    AES_MasterVIOTest();



    while(1);
}



