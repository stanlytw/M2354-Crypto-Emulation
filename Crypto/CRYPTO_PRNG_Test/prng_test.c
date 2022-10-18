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

//#define TEST_SEED    0x5
//#define TEST_SEED    0x20061108
#define TEST_SEED     0x76223

extern int kbhit(void);

static volatile int g_AES_done;
static volatile int g_TDES_done;
static volatile int g_SHA_done;
static volatile int g_PRNG_done;

uint32_t  rand_num[8];

#define PLLCON_SETTING      CLK_PLLCTL_96MHz_HXT
#define PLL_CLOCK           12000000

uint32_t g_u32RandSum = 0;

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

    //SYS->GPC_MFPH = UART0_RXD_PC11 | UART0_TXD_PC12;
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
    if(CRPT->INTSTS & (CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk))
    {
        g_AES_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;
    }

    if(CRPT->INTSTS & (CRPT_INTSTS_HMACIF_Msk | CRPT_INTSTS_HMACEIF_Msk))
    {
        g_SHA_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk | CRPT_INTSTS_HMACEIF_Msk;
    }

    if(CRPT->INTSTS & CRPT_INTSTS_PRNGIF_Msk)
    {
        g_PRNG_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_PRNGIF_Msk;
    }
}


void  dump_PRNG()
{
    int   i;

    printf("PRNG DATA ==>\n");
    for(i = 0; i < 8; i++)
        printf("  0x%08x", CRPT->PRNG_KEY[i]);
    printf("\n");
}


void Delay(uint32_t delayCnt)
{
    while(delayCnt--)
    {
        __NOP();
        __NOP();
    }
}
#if 0
void Timer_Init()
{
    CLK->CLKSEL1 = (CLK->CLKSEL1 & (~CLK_CLKSEL1_TMR0_S_Msk)) | CLK_CLKSEL1_TMR0_XTAL;
    CLK->APBCLK0 |= CLK_APBCLK0_TMR0_EN_Msk;
    TIMER0->TCMPR = 0xFFFFFF;
    TIMER0->TCSR = (0x3 << TIMER_TCSR_MODE_Pos) | TIMER_TCSR_CRST_Msk | (119 << TIMER_TCSR_PRESCALE_Pos);
    TIMER0->TCSR |= TIMER_TCSR_CEN_Msk;
}
#endif



void  prng_gen_and_dump(int keysz)
{
    int  j;

    for(j = 0; j < 10; j++)
    {
        g_PRNG_done = 0;
        CRPT->PRNG_CTL = (keysz << CRPT_PRNG_CTL_KEYSZ_Pos) | CRPT_PRNG_CTL_START_Msk;
        printf("Start PRNG...\n");
        while(!g_PRNG_done);
        dump_PRNG();
    }
}


#if 0
void  prng_gen_performance(int keysz)
{
    int  count;

    printf("PRNG 256 performance test...\n");

    Timer_Init();

    for(count = 0; ; count++)
    {
        g_PRNG_done = 0;
        CRPT->PRNG_CTL = (keysz << CRPT_PRNG_CTL_KEYSZ_Pos) | CRPT_PRNG_CTL_START_Msk;
        while(!g_PRNG_done);

        if(TIMER0->TDR >= 100000)
            break;

        //if(count % 10000 == 0)
        //printf("count = %d\n", count);
    }

    printf("Generate %d rando number in one second.\n", count);
}
#endif

#if 0  // desginer confirmed
void  dump_PRNG_binary()
{
    int        i, ss;
    uint32_t   data32;

    for(i = 0; i < 8; i++)
    {
        data32 = CRPT->PRNG_KEY[i];

        for(ss = 0; ss < 32; ss++)
        {
            printf("%d ", (data32 >> ss) & 0x1);
        }
    }
    printf("\n");
}
#else  // just try
void  dump_PRNG_binary()
{
    int        i, ss;
    uint32_t   data32;

    for(i = 0; i < 8; i++)
    {
        data32 = CRPT->PRNG_KEY[i];
        g_u32RandSum += data32;
        printf("%08x", data32);

//              for (ss = 31; ss >= 0; ss--)
//              {
//                      printf("%d", (data32 >> ss) & 0x1);
//              }
    }
    //printf("\n");
}
#endif

void  prng_sp800_22()
{
    int     i, j;
    int     seed;

#if 1
    g_PRNG_done = 0;
    CRPT->PRNG_SEED = TEST_SEED;
    CRPT->PRNG_CTL = (PRNG_KEY_SIZE_256 << CRPT_PRNG_CTL_KEYSZ_Pos) | CRPT_PRNG_CTL_SEEDRLD_Msk | CRPT_PRNG_CTL_START_Msk;
    //printf("Start PRNG...\n");
    while(!g_PRNG_done);
    dump_PRNG_binary();
#endif

    for(i = 0; i < 10; i++)
    {
        for(j = 0; j < 2000; j++)
        {
            g_PRNG_done = 0;
            CRPT->PRNG_CTL = (PRNG_KEY_SIZE_256 << CRPT_PRNG_CTL_KEYSZ_Pos) | CRPT_PRNG_CTL_START_Msk;
            //printf("Start PRNG...\n");
            while(!g_PRNG_done);
            dump_PRNG_binary();
        }
    }
}


/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
int32_t main(void)
{
    int   i, j, item;

    /* Disable register write-protection function */
    SYS_UnlockReg();

    /* Initial clocks and multi-functions */
    SYS_Init();

    /* Initial UART */
    UART0_Init();

    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;   // enable crypto engine clock

    NVIC_EnableIRQ(CRPT_IRQn);
    PRNG_ENABLE_INT(CRPT);

    CRPT->PRNG_SEED = 0x3; //0x123;

    while(1)
    {
#if 1
        item = '8';
#else
        printf("\n");
        printf("+---------------------------------------------------------------+\n");
        printf("|  TC8226 CRYPTO PRNG test program                              |\n");
        printf("+---------------------------------------------------------------+\n");
        printf("| [1] Generate  64 bits random runber                           |\n");
        printf("| [2] Generate 128 bits random runber                           |\n");
        printf("| [3] Generate 192 bits random runber                           |\n");
        printf("| [4] Generate 256 bits random runber                           |\n");
        printf("| [5] Inifinite loop redundancy check                           |\n");
        printf("| [6] Inifinite loop seed reload test                           |\n");
        printf("| [7] Seed differential test                                    |\n");
        printf("| [8] Generate SP800-22 test pattern                            |\n");
        printf("| [9] Performance test of generating 256 bits random runber     |\n");
        printf("+---------------------------------------------------------------+\n");

        printf("\nSelect [1~6]: \n");

        item = getchar();
#endif

        switch(item)
        {
            case '1':
                //prng_gen_and_dump(PRNG_KEY_SIZE_64);
                printf("\nPress any key...\n");
                getchar();
                break;

            case '2':
                prng_gen_and_dump(PRNG_KEY_SIZE_128);
                printf("\nPress any key...\n");
                getchar();
                break;

            case '3':
                prng_gen_and_dump(PRNG_KEY_SIZE_192);
                printf("\nPress any key...\n");
                getchar();
                break;

            case '4':
                prng_gen_and_dump(PRNG_KEY_SIZE_256);
                printf("\nPress any key...\n");
                getchar();
                break;

            case '5':
                printf("\nPress 'x' to stop test...\n");
                for(i = 1; ; i++)
                {
                    printf("Test cycle: %d\r", i);

                    g_PRNG_done = 0;
                    CRPT->PRNG_CTL = (PRNG_KEY_SIZE_256 << CRPT_PRNG_CTL_KEYSZ_Pos) | CRPT_PRNG_CTL_START_Msk;
                    while(!g_PRNG_done);

                    if(!kbhit())
                    {
                        if(getchar() == 'x')
                            break;
                    }
                    if(i == 1) continue;

                    for(j = 0; j < 8; j++)
                    {
                        if(CRPT->PRNG_KEY[j] == rand_num[j])
                        {
                            printf("Random number not changed!! Test failed!!\n");
                            while(1);
                        }
                        rand_num[j] = CRPT->PRNG_KEY[j];
                    }
                }
                printf("\nTest passed. Press any key...\n");
                getchar();
                break;

            case '6':
            case '7':
                printf("\nPress any key to reload seed and press 'x' to stop test...\n");

                /* Get the random number of TEST_SEED */
                g_PRNG_done = 0;

                if(item == '6')
                    CRPT->PRNG_SEED = TEST_SEED;
                else
                    CRPT->PRNG_SEED = item++;

                CRPT->PRNG_CTL = CRPT_PRNG_CTL_SEEDRLD_Msk | (PRNG_KEY_SIZE_256 << CRPT_PRNG_CTL_KEYSZ_Pos) | CRPT_PRNG_CTL_START_Msk;
                while(!g_PRNG_done);
                for(j = 0; j < 8; j++)
                    rand_num[j] = CRPT->PRNG_KEY[j];

                for(i = 1; ; i++)
                {
                    printf("Test cycle: %d\r", i);

                    if(!kbhit())
                    {
                        if(getchar() == 'x')
                        {
                            break;
                        }
                        else
                        {
                            g_PRNG_done = 0;
                            CRPT->PRNG_CTL = CRPT_PRNG_CTL_SEEDRLD_Msk | (PRNG_KEY_SIZE_256 << CRPT_PRNG_CTL_KEYSZ_Pos) | CRPT_PRNG_CTL_START_Msk;
                            while(!g_PRNG_done);

                            for(j = 0; j < 8; j++)
                            {
                                if(CRPT->PRNG_KEY[j] != rand_num[j])
                                {
                                    printf("\nSeed reload test failed!\n");
                                    while(1);
                                }
                            }

                            if(item > '7')
                            {
                                printf("Seed differential test failed!!\n");
                                break;
                            }

                            printf("\nSeed reload test passed.\n");
                        }
                    }

                    g_PRNG_done = 0;
                    CRPT->PRNG_CTL = (PRNG_KEY_SIZE_256 << CRPT_PRNG_CTL_KEYSZ_Pos) | CRPT_PRNG_CTL_START_Msk;
                    while(!g_PRNG_done);
                }
                break;

            case '8':
                printf("Press any key to start\n");
                getchar();
                printf("//-- START --//\n");
                prng_sp800_22();
                printf("\n//-- END --//");
                printf("\n Random Check Sum = %u", g_u32RandSum);
                while(1);
#if 0
            case '9':
                prng_gen_performance(PRNG_KEY_SIZE_256);
                printf("\nPress any key...\n");
                getchar();
                break;
#endif
        }
    }
}



