/**************************************************************************//**
 * @file     main.c
 * @version  V1.10
 * $Revision: 4 $
 * $Date: 17/02/22 1:51p $
 * @brief    Generate random numbers using Crypto IP PRNG
 *
 * @note
 * Copyright (C) 2013 Nuvoton Technology Corp. All rights reserved.
*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "NuMicro.h"
#include "ecc.h"


#define IS_REAL_CHIP

volatile int g_ECC_done, g_ECCERR_done;

uint32_t    dma_buff[144];
volatile CRPT_T  *crpt;


volatile uint32_t   g_tick_cnt;
static uint32_t     last_tick_print;

void SysTick_Handler(void)
{
    g_tick_cnt++;

    if(g_tick_cnt - last_tick_print > 500)
    {
        printf(".");
        last_tick_print = g_tick_cnt;
    }
}

uint32_t  get_cur_ticks()
{
    return g_tick_cnt;
}

static void enable_sys_tick(int ticks_per_second)
{
    SystemCoreClock = 84000000UL;
    if(SysTick_Config(SystemCoreClock / ticks_per_second))
    {
        /* Setup SysTick Timer for 1 second interrupts  */
        printf("Set system tick error!!\n");
        while(1);
    }
    g_tick_cnt = 0;
    last_tick_print = 0;
}


void CRPT_IRQHandler()
{

    if(CRPT->INTSTS & CRPT_INTSTS_ECCEIF_Msk)
    {
        g_ECCERR_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_ECCEIF_Msk;
        printf("ECCERRIF is set!!\n");
    }
    if(CRPT->INTSTS & CRPT_INTSTS_ECCIF_Msk)
    {
        g_ECC_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_ECCIF_Msk;
        printf("ECC done IRQ.\n");
    }
}


#define PLLCON_SETTING      CLK_PLLCTL_96MHz_HXT // test
#define PLL_CLOCK           12000000    // test 1234


void SYS_Init(void)
{
    int32_t i;
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init System Clock                                                                                       */
    /*---------------------------------------------------------------------------------------------------------*/

    /* Enable External XTAL (4~24 MHz) */
    CLK->PWRCTL |= CLK_PWRCTL_HIRCEN_Msk;

//    CLK->PLLCTL = PLLCON_SETTING;

//    /* Waiting for clock ready */
//    i = 2200; // For timeout
//    while(i-- > 0)
//    {
//        if((CLK->STATUS & (CLK_STATUS_PLLSTB_Msk | CLK_STATUS_HXTSTB_Msk)) ==
//                (CLK_STATUS_PLLSTB_Msk | CLK_STATUS_HXTSTB_Msk))
//            break;
//    }

    /* Switch HCLK clock source to PLL */
    CLK->CLKSEL0 = CLK_CLKSEL0_HCLKSEL_HIRC;
    CLK->CLKDIV0 = 0;

    /* Enable IP clock */
    CLK->APBCLK0 |= CLK_APBCLK0_UART0CKEN_Msk | CLK_APBCLK0_UART1CKEN_Msk | CLK_APBCLK0_UART2CKEN_Msk;

    /* Select IP clock source */
    CLK->CLKSEL2 = CLK_CLKSEL2_UART0SEL_HIRC;//CLK_CLKSEL1_UARTSEL_HXT;

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
//    SYS->GPD_MFPL = SYS_GPD_MFPL_PD0MFP_UART0_RXD | SYS_GPD_MFPL_PD1MFP_UART0_TXD;
    //SYS->GPA_MFPL = SYS_GPA_MFPL_PA1MFP_UART1_RXD | SYS_GPA_MFPL_PA0MFP_UART1_TXD;
    //SYS->GPA_MFPH = SYS_GPA_MFPH_PA12MFP_UART2_RXD | SYS_GPA_MFPH_PA13MFP_UART2_TXD;
    //SYS->GPA_MFPH = SYS_GPA_MFPH_PA12MFP_UART1_RXD | SYS_GPA_MFPH_PA13MFP_UART1_TXD;
    //SYS->GPE_MFPL = SYS_GPE_MFPH_PE8MFP_UART1_TXD | SYS_GPE_MFPH_PE9MFP_UART1_RXD;

//    SYS->GPG_MFPL = 0x30000000ul;
//    SYS->GPG_MFPH = 0x00000003ul;

    //SYS->GPA_MFPL = UART0_RXD_PA0 | UART0_TXD_PA1;
    SYS->GPB_MFPH &= ~(UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk);
    SYS->GPB_MFPH |= UART0_RXD_PB12 | UART0_TXD_PB13;

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
    SYS->IPRST0 |= SYS_IPRST1_UART0RST_Msk;
    SYS->IPRST0 ^= SYS_IPRST1_UART0RST_Msk;

    /* Configure UART0 and set UART0 Baudrate */
    UART0->BAUD = UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(__HXT, 115200);
    UART0->LINE = UART_WORD_LEN_8 | UART_PARITY_NONE | UART_STOP_BIT_1;
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
int32_t main(void)
{
    uint32_t    item, ret;


    /* Disable register write-protection function */
    SYS_UnlockReg();

    /* Initial clocks and multi-functions */
    SYS_Init();

    /* Initial UART */
    UART0_Init();
    
    printf("This is a test ...\n\n");

    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;   // enable crypto engine clock

    NVIC_EnableIRQ(CRPT_IRQn);
    ECC_ENABLE_INT(CRPT);

    enable_sys_tick(100);

#ifdef USE_DMA
    crpt = (volatile CRPT_T *)((uint32_t)&dma_buff[0] - 0x808);
#else
    crpt = CRPT;
#endif

    while(1)
    {
        printf("\n");
        printf("+---------------------------------------------------------+\n");
        printf("|  TC8234 Crypto ECC                                      |\n");
        printf("+---------------------------------------------------------+\n");
        printf("| [1] Key pair generation test                            |\n");
        printf("| [2] Key generation and verification test                |\n");
        printf("| [3] ECC DMA invalid test                                |\n");
        printf("| [4] Force Stop test                                     |\n");
        printf("+---------------------------------------------------------+\n");

        printf("\nSelect [1~2]: \n");

        item = getchar();

        switch(item)
        {
            case '1':
                ret = key_pair_test();
                break;

            case '2':
                ret = sig_gen_test();
                break;
            case '3':
                ret = ECC_DMA_invalid_test();
                break;
            case '4':
                ForceStop();
                break;
        }
    }
}


