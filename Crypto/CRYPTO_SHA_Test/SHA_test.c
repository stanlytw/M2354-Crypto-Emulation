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
#include "sha1.h"


/*
    If change bellow test options, you must change relative image in sha_image.s
*/

//#define SHA160_TEST
//#define SHA224_TEST
//#define SHA256_TEST
//#define SHA384_TEST
//#define SHA512_TEST

uint8_t  g_sha_key[24 * 1024]; // CWS: modify from 32k to 24k due to M2355 only 96K sram
uint8_t  g_sha_digest[64];
int      g_key_len;

static volatile int g_HMAC_error;
static volatile int g_HMAC_done;

extern int  open_test_file(char *filename);
extern int  close_test_file(void);
extern int  get_next_pattern(void);

#if defined(SHA512_TEST)
#define SHA_MODE        (SHA_MODE_SHA512 << CRPT_HMAC_CTL_OPMODE_Pos)
#define DIGEST_LEN      64
#elif defined(SHA384_TEST)
#define SHA_MODE        (SHA_MODE_SHA384 << CRPT_HMAC_CTL_OPMODE_Pos)
#define DIGEST_LEN      48
#elif defined(SHA256_TEST)
#define SHA_MODE        (SHA_MODE_SHA256 << CRPT_HMAC_CTL_OPMODE_Pos)
#define DIGEST_LEN      32
#elif defined(SHA224_TEST)
#define SHA_MODE        (SHA_MODE_SHA224 << CRPT_HMAC_CTL_OPMODE_Pos)
#define DIGEST_LEN      28
#else
#define SHA_MODE        (SHA_MODE_SHA1 << CRPT_HMAC_CTL_OPMODE_Pos)
#define DIGEST_LEN      20
#endif


#include "SHA_vector_parser_image.c"

void dump_digest()
{
    int  i = 8;

    printf("SHA digest:  ");
#ifdef SHA160_TEST
    for(i = 0; i < 5; i++)
#endif
#ifdef SHA224_TEST
        for(i = 0; i < 7; i++)
#endif
#ifdef SHA256_TEST
            for(i = 0; i < 8; i++)
#endif
#ifdef SHA384_TEST
                for(i = 0; i < 12; i++)
#endif
#ifdef SHA512_TEST
                    for(i = 0; i < 16; i++)
#endif
                        printf("%08x ", CRPT->HMAC_DGST[i]);
    printf("\n");
}


void CRPT_IRQHandler()
{
    printf("INT!\n");
    if(CRPT->INTSTS & CRPT_INTSTS_HMACIF_Msk)
    {
        g_HMAC_done = 1;
        CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk;
    }
    if(CRPT->INTSTS & CRPT_INTSTS_HMACEIF_Msk)
    {
        g_HMAC_error = 1;
        CRPT->INTSTS = CRPT_INTSTS_HMACEIF_Msk;
    }
}

void do_swap(uint8_t *buff, int len)
{
    int       i;
    uint8_t   val8;

    len = (len + 3) & 0xfffffffc;
    for(i = 0; i < len; i += 4)
    {
        val8 = buff[i];
        buff[i] = buff[i + 3];
        buff[i + 3] = val8;
        val8 = buff[i + 1];
        buff[i + 1] = buff[i + 2];
        buff[i + 2] = val8;
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

int  SHA_test()
{
    printf("SHA DMA mode test with INSWAP & OUTSWAP...\n");
    CRPT->HMAC_CTL = SHA_MODE | CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk;
    CRPT->HMAC_DMACNT = g_key_len / 8;
    CRPT->HMAC_SADDR = (uint32_t)&g_sha_key[0];

    printf("SHA byte count = %d\n", g_key_len / 8);

    g_HMAC_done = 0;
    CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk | CRPT_HMAC_CTL_DMAEN_Msk | CRPT_HMAC_CTL_DMALAST_Msk;

    printf("CRPT->HMAC_CTL    0x%X\n", CRPT->HMAC_CTL);
    printf("CRPT->HMAC_DMACNT 0x%X\n", CRPT->HMAC_DMACNT);
    printf("CRPT->HMAC_SADDR  0x%X\n", CRPT->HMAC_SADDR);

    while(!g_HMAC_done) ;
    while(CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk)
        printf("!");

    dump_digest();

    do_swap((uint8_t *)&g_sha_digest[0], DIGEST_LEN);

    if(do_compare((uint8_t *)(CRPT_BASE + 0x308), &g_sha_digest[0], DIGEST_LEN) < 0)
        while(1);

    do_swap((uint8_t *)&g_sha_digest[0], DIGEST_LEN);

    /*--------------------------------------------*/
    /*  INSWAP test                               */
    /*--------------------------------------------*/
    printf("SHA DMA mode test with INSWAP...\n");
    CRPT->HMAC_CTL = SHA_MODE | CRPT_HMAC_CTL_INSWAP_Msk;
    CRPT->HMAC_DMACNT = g_key_len / 8;
    CRPT->HMAC_SADDR = (uint32_t)&g_sha_key[0];

    printf("SHA byte count = %d\n", g_key_len / 8);

    g_HMAC_done = 0;
    CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk | CRPT_HMAC_CTL_DMAEN_Msk | CRPT_HMAC_CTL_DMALAST_Msk;
    while(!g_HMAC_done) ;
    while(CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk)
        printf("!");

    dump_digest();

    if(do_compare((uint8_t *)(CRPT_BASE + 0x308), &g_sha_digest[0], DIGEST_LEN) < 0)
    {
        while(1);
    }

    /*--------------------------------------------*/
    /*  No INSWAP & OUTSWAP test                  */
    /*--------------------------------------------*/
    printf("SHA DMA mode test without SWAP...\n");
    CRPT->HMAC_CTL = SHA_MODE;
    CRPT->HMAC_DMACNT = g_key_len / 8;
    CRPT->HMAC_SADDR = (uint32_t)&g_sha_key[0];

    do_swap((uint8_t *)&g_sha_key[0], g_key_len / 8);

    printf("SHA byte count = %d\n", g_key_len / 8);

    g_HMAC_done = 0;
    CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk | CRPT_HMAC_CTL_DMAEN_Msk | CRPT_HMAC_CTL_DMALAST_Msk;
    while(!g_HMAC_done) ;
    while(CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk)
        printf("!");

    dump_digest();

    if(do_compare((uint8_t *)(CRPT_BASE + 0x308), &g_sha_digest[0], DIGEST_LEN) < 0)
    {
        while(1);
    }

    do_swap((uint8_t *)&g_sha_key[0], g_key_len / 8);

    return 0;
}

int  SHA_SW_test()
{
    uint32_t    *data_ptr;
    int         data_cnt;

    printf("Do S/W mode test...\n");
    CRPT->HMAC_CTL = SHA_MODE | CRPT_HMAC_CTL_INSWAP_Msk;
    CRPT->HMAC_DMACNT = g_key_len / 8;
    CRPT->HMAC_SADDR = (uint32_t)&g_sha_key[0];

    printf("SHA byte count = %d\n", g_key_len / 8);

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

    /*--------------------------------------------*/
    /*  Compare                                   */
    /*--------------------------------------------*/
    if(do_compare((uint8_t *)(CRPT_BASE + 0x308), &g_sha_digest[0], DIGEST_LEN) < 0)
    {
        getchar();
        //while (1);
    }
    return 0;
}

int  SHA_force_stop_test()
{
    printf("[SHA force stop test] => ");
    //printf("SHA DMA mode test with INSWAP & OUTSWAP...\n");
    CRPT->HMAC_CTL = SHA_MODE | CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk;
    CRPT->HMAC_DMACNT = g_key_len / 8;
    CRPT->HMAC_SADDR = (uint32_t)&g_sha_key[0];

    //printf("SHA byte count = %d\n", g_key_len/8);

    g_HMAC_done = 0;
    CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk | CRPT_HMAC_CTL_DMAEN_Msk | CRPT_HMAC_CTL_DMALAST_Msk;
    if(!(CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk))
    {
        printf("BUSY flag is not set!!\n");
        return -1;
    }

    CRPT->HMAC_CTL = CRPT_HMAC_CTL_STOP_Msk;
    if(CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk)
    {
        printf("BUSY flag is not cleared!!\n");
        return -1;
    }

    printf("PASS.\n");
    return 0;
}


int  SHA_DMA_error_test()
{
    printf("[SHA DMA error test] => ");
    CRPT->HMAC_CTL = SHA_MODE | CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk;
    CRPT->HMAC_DMACNT = g_key_len / 8;
    CRPT->HMAC_SADDR = 0x5000000;

    g_HMAC_error = 0;
    g_HMAC_done = 0;
    CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk | CRPT_HMAC_CTL_DMAEN_Msk | CRPT_HMAC_CTL_DMALAST_Msk;
    while(!g_HMAC_error && !g_HMAC_done) ;

    if(!(CRPT->HMAC_STS & CRPT_HMAC_STS_DMAERR_Msk))
    {
        printf("DMA error status not set!!");
        return -1;
    }

    printf("PASS.\n");
    return 0;
}


void Delay(uint32_t delayCnt)
{
    while(delayCnt--)
    {
        __NOP();
        __NOP();
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
    SystemCoreClock = FREQ_96MHZ;        // HCLK
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

    //SYS->GPG_MFPL = 0x30000000ul;
    //SYS->GPG_MFPH = 0x00000003ul;

    //SYS->GPD_MFPL = UART0_TXD_PD3 | UART0_RXD_PD2;
    //SYS->GPA_MFPL = (SYS->GPA_MFPL &(~(UART0_RXD_PA0_Msk|UART0_TXD_PA1_Msk))) | UART0_RXD_PA0 | UART0_TXD_PA1;

    SYS->GPB_MFPH &= UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk;
    SYS->GPB_MFPH |= UART0_RXD_PB12 | UART0_TXD_PB13;
    //SET_UART0_RXD_PA6();
    //SET_UART0_TXD_PA7();


    // power gating
    M32(0x400001f4) = 0xfffffffful;
    // GPIO clk
    CLK->AHBCLK |= (0xfff << 20);


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

/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
int32_t main(void)
{
    volatile int loop;

    /* Disable register write-protection function */
    SYS_UnlockReg();

    /* Initial clocks and multi-functions */
    SYS_Init();

    /* Initial UART */
    UART0_Init();

    printf("\n\n");
    printf("+----------------------------------------+\n");
    printf("|  TC8234 SHA test verification          |\n");
    printf("+----------------------------------------+\n");

    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;   // enable crypto engine clock

    NVIC_EnableIRQ(CRPT_IRQn);
    SHA_ENABLE_INT(CRPT);

    open_test_file(NULL);

    while(1)
    {
        memset(g_sha_key, 0, sizeof(g_sha_key));

        if(get_next_pattern() < 0)
            break;

        SHA_test();
        SHA_SW_test();
    }

    SHA_force_stop_test();
    SHA_DMA_error_test();

    close_test_file();
    printf("\n\nTEST OK!\n");
    while(1);
}



