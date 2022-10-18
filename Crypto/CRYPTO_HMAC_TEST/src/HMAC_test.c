/*---------------------------------------------------------------------------------------------------------*/
/*                                                                                                         */
/* Copyright(c) 2010 Nuvoton Technology Corp. All rights reserved.                                         */
/*                                                                                                         */
/*---------------------------------------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "NuMicro.h"


#define PLLCON_SETTING      CLK_PLLCTL_96MHz_HXT
#define PLL_CLOCK           12000000

#define IS_REAL_CHIP
//#define DMA_MODE

extern uint8_t      g_hmac_msg[1024];
extern uint8_t      g_hmac_mac[1024];
extern int      g_key_len, g_msg_len, g_mac_len;
extern uint32_t g_sha_mode;

int  g_digest_len = 0;

static volatile int g_AES_done;
static volatile int g_TDES_done;
static volatile int g_HMAC_done;

extern int  open_test_file(char *filename);
extern int  close_test_file(void);
extern int  get_next_pattern(void);


void CRPT_IRQHandler()
{
    if(CRPT->INTSTS & (CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk))
    {
        g_AES_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;
    }

    if(CRPT->INTSTS & (CRPT_INTSTS_HMACIF_Msk | CRPT_INTSTS_HMACEIF_Msk))
    {
        g_HMAC_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk | CRPT_INTSTS_HMACEIF_Msk;
    }
}


int  do_compare(uint8_t *output, uint8_t *expect, int cmp_len)
{
    int   i;

    if(memcmp(expect, output, cmp_len))
    {
        printf("\nMismatch!! - %d\n", cmp_len);
        for(i = 0; i < cmp_len; i++)
            printf("0x%02x    0x%02x\n", expect[i], output[i]);
        return -1;
    }
    return 0;
}


int  HMAC_test()
{
    int         i;
    uint32_t        *dptr;
#ifndef DMA_MODE
    uint32_t        *data_ptr;
    int         data_cnt;
#endif

    CRPT->HMAC_CTL |= CRPT_HMAC_CTL_HMACEN_Msk | CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk;
    CRPT->HMAC_CTL = (CRPT->HMAC_CTL & ~CRPT_HMAC_CTL_OPMODE_Msk) | g_sha_mode;
    CRPT->HMAC_KEYCNT = g_key_len;
    CRPT->HMAC_DMACNT = g_msg_len + ((g_key_len + 3) & 0xfffffffc);
    CRPT->HMAC_SADDR = (uint32_t)&g_hmac_msg[0];
    printf(">>  &HMAC_SADDR 0x%08x  CRPT 0x%08x\n", (uint32_t)&CRPT->HMAC_SADDR, (uint32_t)CRPT);

    printf("GY 0x%x, 0x%x, 0x%x, 0x%x\n", g_hmac_msg[0], g_hmac_msg[1], g_hmac_msg[2], g_hmac_msg[3]);
    printf("CRPT->HMAC_SADDR = 0x%x\n", CRPT->HMAC_SADDR);
    printf("CRPT->HMAC_DMACNT = 0x%x\n", CRPT->HMAC_DMACNT);

    printf("0x%x, HMAC key + message byte count = %d\n", CRPT->HMAC_CTL, g_key_len + g_msg_len);

#ifdef DMA_MODE
    g_HMAC_done = 0;
    CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk | CRPT_HMAC_CTL_DMAEN_Msk | CRPT_HMAC_CTL_DMALAST_Msk;
    while(!g_HMAC_done) ;
    while(CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk)
        printf("!");
#else
    data_ptr = (uint32_t *)CRPT->HMAC_SADDR;
    data_cnt = CRPT->HMAC_DMACNT;
    CRPT->HMAC_CTL &= ~CRPT_HMAC_CTL_DMALAST_Msk;
    CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;
    while(data_cnt > 0)
    {
        if(CRPT->HMAC_STS & CRPT_HMAC_STS_DATINREQ_Msk)
        {
            if(data_cnt - 4 <= 0)
            {
                CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk | CRPT_HMAC_CTL_DMALAST_Msk;
            }

            CRPT->HMAC_DATIN = *data_ptr++;
            data_cnt -= 4;
        }
    }
    while(!g_HMAC_done) ;

    while(CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk)
        printf("!");
#endif

    /*--------------------------------------------*/
    /*  Compare                                   */
    /*--------------------------------------------*/
#if 1
    printf("OUTPUT digest ==> \n");
    dptr = (uint32_t *)(CRPT_BASE + 0x308);
    for(i = 0; i < 8; i++, dptr++)
        printf("    HMAC%d = 0x%08x\n", i, *dptr);
    printf("\n");
#endif
    if(do_compare((uint8_t *)(CRPT_BASE + 0x308), &g_hmac_mac[0], g_mac_len) < 0)
    {
        while(1);
    }
    printf("Data verify OK.\n\n");
    return 0;
}


static char  _str_prn_buff[64];

char  *print_ENG_unistr(uint8_t *suStr)
{
    int  i;

    _str_prn_buff[0] = '\0';
    for(i = 0; i < 60;)
    {
        if((*suStr == 0) && (*(suStr + 1) == 0))
            break;

        _str_prn_buff[i++] = *suStr++;

        if(*suStr)
            _str_prn_buff[i++] = *suStr;

        suStr++;
    }
    _str_prn_buff[i] = '\0';
    return _str_prn_buff;
}


static __INLINE void SYS_WaitingForClockReady(uint32_t u32Mask)
{
    while((CLK->STATUS & u32Mask) != u32Mask)
    {
    }
}

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

    /* Enable IP clock */
    CLK->APBCLK0 |= CLK_APBCLK0_UART0CKEN_Msk | CLK_APBCLK0_UART1CKEN_Msk | CLK_APBCLK0_UART2CKEN_Msk | CLK_APBCLK0_UART5CKEN_Msk;

    /* Select IP clock source */
    CLK->CLKSEL2 = CLK_CLKSEL2_UART0SEL_HIRC;
    CLK->CLKSEL3 = CLK_CLKSEL3_UART5SEL_HIRC;

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

    //SYS->GPG_MFPL = 0x30000000ul;
    //SYS->GPG_MFPH = 0x00000003ul;

    //SYS->GPC_MFPH = UART0_TXD_PC12 | UART0_RXD_PC11;
    //SYS->GPD_MFPL = UART0_TXD_PD3 | UART0_RXD_PD2;
    SYS->GPB_MFPH &= ~(UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk);
    SYS->GPB_MFPH |= UART0_RXD_PB12 | UART0_TXD_PB13;



}


void DEBUG_PORT_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART                                                                                               */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Reset IP */

    /* Configure UART0 and set UART0 Baudrate */
    DEBUG_PORT->BAUD = UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(__HXT, 115200);
    DEBUG_PORT->LINE = UART_WORD_LEN_8 | UART_PARITY_NONE | UART_STOP_BIT_1;
}



/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
int  main(void)
{
    volatile int loop;

    /* Unlock protected registers */
    SYS_UnlockReg();

    SYS_Init();
    DEBUG_PORT_Init();

    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;   // enable crypto engine clock

    printf("\n\n");
    printf("+-----------------------------------------+\n");
    printf("|        Crypto HMAC test program         |\n");
    printf("+-----------------------------------------+\n");

    NVIC_EnableIRQ(CRPT_IRQn);
    SHA_ENABLE_INT(CRPT);

    open_test_file(NULL);

    while(1)
    {
        if(get_next_pattern() < 0)
            break;

        HMAC_test();
    }
    close_test_file();
    printf("\n\nTEST OK!\n");
    while(1);
}



