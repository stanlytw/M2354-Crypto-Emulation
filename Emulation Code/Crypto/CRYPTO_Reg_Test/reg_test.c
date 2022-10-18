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

#define IS_TC8226

//#define REG_TEST_END_OFFSET    0x354  // without ECC
#define REG_TEST_END_OFFSET    0xA54    // with ECC

#include "default_mask.c"
#include "rw_mask.c"
#include "ro_mask.c"

static const CRPT_T  reg_default =
{
    /* INTEN */
    0x00000000,
    /* INTSTS */
    0x00000000,
    /* PRNG_CTL */
    0x00000000,
    /* PRNG_SEED */
    0x00000000,
    /* PRNG_KEY0 ~ PRNG_KEY7 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* RESERVE0[8] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* AES_FDBCK0 ~ AES_FDBCK3 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* TDES_FDBCKH/L */
    0x00000000, 0x00000000,
    /* RESERVE1[38] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* AES_CTL */
    0x00000000,
    /* AES_STS */
    0x00010100,
    /* AES_DATIN */
    0x00000000,
    /* AES_DATOUT */
    0x00000000,
    /* AES0_KEY0 ~ AES0_KEY7 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* AES0_IV0 ~ AES0_IV3 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* AES0_SADDR */
    0x00000000,
    /* AES0_DADDR */
    0x00000000,
    /* AES0_CNT */
    0x00000000,
    /* AES1_KEY0 ~ AES1_KEY7 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* AES1_IV0 ~ AES1_IV3 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* AES1_SADDR */
    0x00000000,
    /* AES1_DADDR */
    0x00000000,
    /* AES1_CNT */
    0x00000000,
    /* AES2_KEY0 ~ AES2_KEY7 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* AES2_IV0 ~ AES2_IV3 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* AES2_SADDR */
    0x00000000,
    /* AES2_DADDR */
    0x00000000,
    /* AES2_CNT */
    0x00000000,
    /* AES3_KEY0 ~ AES3_KEY7 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* AES3_IV0 ~ AES3_IV3 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* AES3_SADDR */
    0x00000000,
    /* AES3_DADDR */
    0x00000000,
    /* AES3_CNT */
    0x00000000,
    /* TDES_CTL */
    0x00000000,
    /* TDES_STS */
    0x00000000, // DES/TDES removed in M2355
    /* TDES0_KEY1H, TDES0_KEY1L, TDES0_KEY2H, TDES0_KEY2L, TDES0_KEY3H, TDES0_KEY3L */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* TDES0_IVH, TDES0_IVL */
    0x00000000, 0x00000000,
    /* TDES0_SADDR */
    0x00000000,
    /* TDES0_DADDR */
    0x00000000,
    /* TDES0_CNT */
    0x00000000,
    /* TDES_DATIN */
    0x00000000,
    /* TDES_DATOUT */
    0x00000000,
    /* RESERVE2[3] */
    0x00000000, 0x00000000, 0x00000000,
    /* TDES1_KEY1H, TDES1_KEY1L, TDE S1_KEY2H, TDES1_KEY2L, TDES1_KEY3H, TDES1_KEY3L */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* TDES1_IVH, TDES1_IVL */
    0x00000000, 0x00000000,
    /* TDES1_SADDR */
    0x00000000,
    /* TDES1_DADDR */
    0x00000000,
    /* TDES1_CNT */
    0x00000000,
    /* RESERVE3[5] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* TDES2_KEY1H, TDES2_KEY1L, TDES2_KEY2H, TDES2_KEY2L, TDES2_KEY3H, TDES2_KEY3L */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    /* TDES2_IVH, TDES2_IVL */
    0x00000000, 0x00000000,
    0x00000000,
    /* RESERVE6[298] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    /* ECC_CTL */
    0x00000000,
    /* ECC_STS */
    0x00000000,
    /* ECC_POINT_X1[18] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    /* ECC_POINT_Y1[18] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    /* ECC_POINT_X2[18] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    /* ECC_POINT_Y2[18] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    /* ECC_CURVE_A[18] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    /* ECC_CURVE_B[18] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    /* ECC_CURVE_N[18] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    /* ECC_SCALAR_K[18] */
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    /* ECC_SADDR */
    0x00000000,
    /* ECC_DADDR */
    0x00000000,
    /* ECC_STARTREG */
    0x00000000,
    /* ECC_WORDCNT */
    0x00000000
};


void Delay(uint32_t delayCnt)
{
    while(delayCnt--)
    {
        __NOP();
        __NOP();
    }
}


#define PLLCON_SETTING      CLK_PLLCTL_48MHz_HXT // test
#define PLL_CLOCK           12000000    // test 1234


void SYS_Init(void)
{
    int32_t i;
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init System Clock                                                                                       */
    /*---------------------------------------------------------------------------------------------------------*/

    /* Enable External XTAL (4~24 MHz) */
    //CLK->PWRCTL |= CLK_PWRCTL_HXTEN_Msk;

    //CLK->PLLCTL = PLLCON_SETTING;

    /* Waiting for clock ready */
//    i = 2200; // For timeout
//    while(i-- > 0)
//    {
//        if((CLK->STATUS & (CLK_STATUS_PLLSTB_Msk | CLK_STATUS_HXTSTB_Msk)) ==
//                (CLK_STATUS_PLLSTB_Msk | CLK_STATUS_HXTSTB_Msk))
//            break;
//    }

    /* Switch HCLK clock source to PLL */
    //CLK->CLKSEL0 = CLK_CLKSEL0_HCLKSEL_HXT;
    
    CLK->PWRCTL |= CLK_PWRCTL_HIRCEN_Msk;
    CLK->CLKSEL0 = CLK_CLKSEL0_HCLKSEL_HIRC;
    CLK->CLKDIV0 = 0;
    
    CLK_SetCoreClock(FREQ_96MHZ);

    /* Enable IP clock */
    CLK->APBCLK0 |= CLK_APBCLK0_UART0CKEN_Msk | CLK_APBCLK0_UART1CKEN_Msk | CLK_APBCLK0_UART2CKEN_Msk;

    /* Select IP clock source */
    CLK->CLKSEL2 = CLK_CLKSEL2_UART0SEL_HIRC;

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

    //SYS->GPA_MFPL = UART0_RXD_PA0 | UART0_TXD_PA1;
    SYS->GPB_MFPH &= ~(UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk);
    SYS->GPB_MFPH |= UART0_RXD_PB12 | UART0_TXD_PB13;

    // power gating
    M32(0x400001f4) = 0xfffffffful;


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

/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
int main()
{
    int   i;
    uint32_t   pDefault, pDefMask, pRwMask, pRoMask;
    uint32_t   data32, val32;
    /* Disable register write-protection function */
    SYS_UnlockReg();

    /* Initial clocks and multi-functions */
    SYS_Init();

    /* Initial UART */
    UART0_Init();

    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;   // enable crypto engine clock

    printf("\n\n");
    printf("+----------------------------------------+\n");
    printf("|                                        |\n");
    printf("|  TC8234 CRYPTO register test program   |\n");
    printf("|                                        |\n");
    printf("+----------------------------------------+\n");

    //SECURE_init();

    pDefault = (uint32_t)&reg_default;
    pDefMask = (uint32_t)&reg_default_mask;
    pRwMask  = (uint32_t)&reg_rw_mask;
    pRoMask  = (uint32_t)&reg_ro_mask;


    printf("    Default register value test...");
    for(i = 0; i <= REG_TEST_END_OFFSET ; i += 4)
    {
        if((inpw(CRPT_BASE + i) & inpw(pDefMask + i)) != (inpw(pDefault + i) & inpw(pDefMask + i)))
        {
            printf("\nError: Register(0x%x) Read:[0x%x], Expect:[0x%x], mask:0x%x\n",
                   (unsigned int)CRPT_BASE + i, inpw(CRPT_BASE + i), inpw(pDefault + i), inpw(pDefMask + i));
            while(1);
        }
        //else
        //    printf("Register(0x%x) Read:[0x%x], Expect:[0x%x]\n",
        //          CRPT_BASE + i, inpw(CRPT_BASE+i), inpw(pDefault+i));
    }
    printf("OK\n");

    // Write all 0's to test R/W register
    printf("    R/W test for 0x00000000...");
    for(i = 0; i <= REG_TEST_END_OFFSET ; i += 4)
    {
        outpw(CRPT_BASE + i, 0x00000000);
        if((inpw(pRwMask + i) & inpw(CRPT_BASE + i)) != 0)
        {
            printf("\nR/W write all 0 test failed: Register(0x%x) Read:[0x%x], Test mask:[0x%x]\n",
                   (unsigned int)CRPT_BASE + i, inpw(CRPT_BASE + i), inpw(pRwMask + i));
            goto failed;
        }
    }
    printf("OK\n");

    // Write all 1's to test R/W register
    printf("    R/W test for 0xFFFFFFFF...");
    for(i = 0; i <= REG_TEST_END_OFFSET ; i += 4)
    {
        CRPT->ECC_CTL = 0;
        outpw(CRPT_BASE + i, inpw(pRwMask + i));
        if((inpw(pRwMask + i) & inpw(CRPT_BASE + i)) != inpw(pRwMask + i))
        {
            printf("\nR/W write all 1 test failed: Register(0x%x) Read:[0x%x], Test mask:[0x%x]\n",
                   (unsigned int)CRPT_BASE + i, inpw(CRPT_BASE + i), inpw(pRwMask + i));
            goto failed;
        }
        outpw(CRPT_BASE + i, inpw(pDefault + i)); // write back default value
    }
    printf("OK\n");

    SYS->IPRST0 = SYS_IPRST0_CRPTRST_Msk;

    SYS->IPRST0 = 0;

    printf("    Default register value test (After Reset)...");
    for(i = 0; i <= REG_TEST_END_OFFSET ; i += 4)
    {
        if((inpw(CRPT_BASE + i) & inpw(pDefMask + i)) != (inpw(pDefault + i) & inpw(pDefMask + i)))
        {
            printf("\nError: Register(0x%x) Read:[0x%x], Expect:[0x%x], mask:0x%x\n",
                   (unsigned int)CRPT_BASE + i, inpw(CRPT_BASE + i), inpw(pDefault + i), inpw(pDefMask + i));
            while(1);
        }
        //else
        //    printf("Register(0x%x) Read:[0x%x], Expect:[0x%x]\n",
        //          CRPT_BASE + i, inpw(CRPT_BASE+i), inpw(pDefault+i));
    }
    printf("OK\n");

    // Write 0x55555555 to test R/W register
    printf("    R/W test for 0x55555555...");
    for(i = 0; i <= REG_TEST_END_OFFSET ; i += 4)
    {
        if(reg_rw_test_mask[i / 4])
        {
            outpw(CRPT_BASE + i, 0x55555555);
            if((inpw(pRwMask + i) & inpw(CRPT_BASE + i)) != (inpw(pRwMask + i) & 0x55555555))
            {
                printf("\nR/W write 0x55555555 test failed: Register(0x%x) Read:[0x%x], Test mask:[0x%x]\n",
                       (unsigned int)CRPT_BASE + i, inpw(CRPT_BASE + i), inpw(pRwMask + i));
                goto failed;
            }

        }
    }
    printf("OK\n");

    // Write 0xAAAAAAAA to test R/W register
    printf("    R/W test for 0xAAAAAAAA...");
    for(i = 0; i <= REG_TEST_END_OFFSET ; i += 4)
    {
        if(reg_rw_test_mask[i / 4])
        {
            outpw(CRPT_BASE + i, 0xAAAAAAAA);
            if((inpw(pRwMask + i) & inpw(CRPT_BASE + i)) != (inpw(pRwMask + i) & 0xAAAAAAAA))
            {
                printf("\nR/W write 0xAAAAAAAA test failed: Register(0x%x) Read:[0x%x], Test mask:[0x%x]\n",
                       (unsigned int)CRPT_BASE + i, inpw(CRPT_BASE + i), inpw(pRwMask + i));
                goto failed;
            }
            outpw(CRPT_BASE + i, inpw(pDefault + i)); // write back default value
        }
    }
    printf("OK\n");

    printf("    Read only test...");
    for(i = 0; i <= REG_TEST_END_OFFSET ; i += 4)
    {
        if(inpw(pRoMask + i) == 0x0)
            continue;

        val32 = inpw(CRPT_BASE + i) & inpw(pRoMask + i);
        outpw(CRPT_BASE + i, 0xFFFFFFFF);
        data32 = inpw(CRPT_BASE + i);
        if((inpw(pRoMask + i) & data32) != val32)
        {
            printf("\nError: Register(0x%x) Read:[0x%x], expect:[0x%x]\n",
                   (unsigned int)CRPT_BASE + i, data32 & inpw(pRoMask + i), val32);
            goto failed;
        }

        outpw(CRPT_BASE + i, 0x00000000);
        data32 = inpw(CRPT_BASE + i);
        if((inpw(pRoMask + i) & data32) != val32)
        {
            printf("\nError: Register(0x%x) Read:[0x%x], expect:[0x%x]\n",
                   (unsigned int)CRPT_BASE + i, data32 & inpw(pRoMask + i), val32);
            goto failed;
        }
    }
    printf("OK\n");

    printf("\nCrypto register test passed.\n");
    while(1);

failed:
    printf("\nTest failed!!\n");
    while(1);
}



