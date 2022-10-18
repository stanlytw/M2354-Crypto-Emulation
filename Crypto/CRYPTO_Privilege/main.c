/**
  ******************************************************************************
  * @file    main.c
  * @author  NuMicro MCU Software Team
  * @brief   Test program for M0564
  ******************************************************************************
  */


#include <stdio.h>
#include <string.h>
#include "NuMicro.h"

//#define FOR_SIMULATION
#ifdef FOR_SIMULATION
#define dbg(...)
#else
#define dbg printf
#endif



void UART0_Init(void);
void UART1_Init(void);
void SYS_Init(void);
void IP_Init(void);


#define ACK     0xf0
#define NAK     0xf1

#define WAIT_UART() {while((DEBUG_PORT->FIFOSTS & UART_FIFOSTS_TXEMPTY_Msk) == 0);}

int volatile g_Item = 0;

uint32_t ProcessHardFault(uint32_t lr, uint32_t msp, uint32_t psp)
{
    if(g_Item == 2)
    {
        printf("[PASS]\n");
        WAIT_UART();
        SYS->IPRST0 |= SYS_IPRST0_CHIPRST_Msk;
        while(1);
    }

    printf("Hardfault\n");
    while(1);
}

__attribute__((always_inline)) __STATIC_INLINE void __SVC()
{
    __ASM volatile("svc 0x1");
}

void SVC_Handler(void)
{
    CONTROL_Type ctrl;

    printf("SVC Handler\n");

    /* Change Thread mode to privileged */
    ctrl.w = __get_CONTROL();
    ctrl.b.nPRIV = 0;
    __set_CONTROL(ctrl.w);
}

volatile int g_done = 0;

void CRPT_IRQHandler(void)
{
    CAN_T *can;
    uint32_t u8IIDRstatus;

    can = CAN0;
    u8IIDRstatus = can->IIDR;

    if(u8IIDRstatus == 0x00008000)        /* Check Status Interrupt Flag (Error status Int and Status change Int) */
    {
        g_done = 1;

        /**************************/
        /* Status Change interrupt*/
        /**************************/
        if(can->STATUS & CAN_STATUS_RXOK_Msk)
        {
            can->STATUS &= ~CAN_STATUS_RXOK_Msk;   /* Clear Rx Ok status*/

            g_done = 1;
            printf("RX OK INT!!\n");
        }

        if(can->STATUS & CAN_STATUS_TXOK_Msk)
        {
            can->STATUS &= ~CAN_STATUS_TXOK_Msk;    /* Clear Tx Ok status*/

            g_done = 1;
            printf("TX OK INT!!\n");
        }

        /**************************/
        /* Error Status interrupt */
        /**************************/
        if(can->STATUS & CAN_STATUS_EWARN_Msk)
        {
            printf("EWARN INT\n") ;
        }

        if(can->STATUS & CAN_STATUS_BOFF_Msk)
        {
            printf("BOFF INT\n") ;
        }
    }
    else
    {
        printf("Should not be here\n");
        while(1);
    }


}


//----------------------------------------------------------------------------
// Implement IP Test function to verify the access of peripheral with secure path


const __attribute__((aligned(4))) uint8_t g_au8Test[32] =
{
    0x64, 0x36, 0x2E, 0x4D, 0x28, 0x16, 0x0D, 0xB4, 0x44, 0xEF, 0x39
    , 0x47, 0xE1, 0xC4, 0x05, 0x51, 0x51, 0x8C, 0x71, 0xE7, 0x50, 0x30
    , 0x7C, 0xA4, 0x93, 0xD5, 0xC8, 0x10, 0x3E, 0xD2, 0xBF, 0x53
};


int32_t SHA256(uint32_t *pu32Addr, int32_t size, uint32_t digest[])
{
    int32_t i;

    /* Enable CRYPTO */
    //CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk; // Disable due to it need privilege

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

int Engine_Test(void *ip)
{
    CRPT_T *crpt;

    uint32_t hash[8] = {0};
    int32_t i;
    uint32_t ans[8];

    crpt = (CRPT_T *)ip;

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
            while(1);
        }
    }

    printf("SHA256 Test Pass!\n");

    return 0;
}

//----------------------------------------------------------------------------

int main()
{
    int32_t i;
    uint32_t u32Reg0, u32Reg1, u32Reg2, u32Reg3;
    char c;
    CONTROL_Type ctrl;

    SYS_UnlockReg();

    SYS_Init();


    /* UART0 configuration */
    UART0_Init();
    UART1_Init();

    IP_Init();

    printf("\n\n+---------------------------------------------------+\n");
    printf("|                 Privilege Test Code               |\n");
    printf("+---------------------------------------------------+\n");
    printf("     CPU        Peripheral\n");
    printf(" [0] Pri         Pri\n");
    printf(" [1] Pri         Unpri\n");
    printf(" [2] Unpri       Pri\n");
    printf(" [3] Unpri       UnPri\n");
    printf("+---------------------------------------------------+\n");
    printf("Enter your select:");
    c = getchar();
    printf(" %c\n", c);

    NVIC_EnableIRQ(CRPT_IRQn);
    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;

    // Assume CPU default to privilege mode
    switch(c)
    {
        case '0':
            g_Item = 0;
            Engine_Test(CRPT);
            printf("[PASS]\n");
            WAIT_UART();
            SYS_ResetChip();
            while(1);
            break;
        case '1':
            g_Item = 1;
            SCU->PNPSET[1] |= SCU_PNPSET1_CRPT_Msk;
            Engine_Test(CRPT);
            printf("[PASS]\n");
            WAIT_UART();
            SYS_ResetChip();
            while(1);
            break;
        case '2':
            g_Item = 2;
            // set to non-privilege
            ctrl.w = __get_CONTROL();
            ctrl.b.nPRIV = 1;
            __set_CONTROL(ctrl.w);
            printf("We are in unprivilege mode now!\n");

            Engine_Test(CRPT);
            printf("[FAIL]\n");
            WAIT_UART();
            SYS_ResetChip();
            while(1);
        case '3':
            g_Item = 3;
            // set to non-privilege
            SCU->PNPSET[1] |= SCU_PNPSET1_CRPT_Msk;
            SCU->PNPSET[3] |= SCU_PNPSET3_UART0_Msk;

            ctrl.w = __get_CONTROL();
            ctrl.b.nPRIV = 1;
            __set_CONTROL(ctrl.w);
            printf("We are in unprivilege mode now!\n");
            //printf("IP privilege=%d\n", ((SCU->PPSET[1] & SCU_PPSET1_CRPT_Msk) != 0));

            Engine_Test(CRPT);
            printf("[PASS]\n");
            WAIT_UART();

            // Return to privilege mode
            __SVC();

            SYS_ResetChip();
            while(1);

        default:
            break;

    }

#if 0
    // set to non-privilege
    ctrl.w = __get_CONTROL();
    ctrl.b.nPRIV = 1;
    __set_CONTROL(ctrl.w);

    printf("We are in non-privilege mode now!\n");


    // Use SVC to set to privilege mode
    __SVC();

    printf("We are in privilege mode now!\n");

#endif

    printf("Privilege Test Done\n");

    while(1);
}

void UART0_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART                                                                                               */
    /*---------------------------------------------------------------------------------------------------------*/

    CLK->APBCLK0 |= CLK_APBCLK0_UART0CKEN_Msk;


    //GPD[2]    V37 CON30.40
    //GPD[3]    V35 CON30.42

    //SYS->GPC_MFPH = UART0_RXD_PC11 | UART0_TXD_PC12;
//    SYS->GPD_MFPL &= ~(UART0_RXD_PD2_Msk | UART0_TXD_PD3_Msk);
//    SYS->GPD_MFPL |= UART0_RXD_PD2 | UART0_TXD_PD3;

    //SYS->GPA_MFPL = (SYS->GPA_MFPL & (~(UART0_RXD_PA0_Msk|UART0_TXD_PA1_Msk))) | UART0_RXD_PA0 | UART0_TXD_PA1;
    /* Set multi-function pins for UART0 RXD and TXD */
    SYS->GPB_MFPH = (SYS->GPB_MFPH & (~(UART0_RXD_PB12_Msk | UART0_TXD_PB13_Msk))) | UART0_RXD_PB12 | UART0_TXD_PB13;


    /* Configure UART0 and set UART0 Baudrate */
    UART0->BAUD = UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(12000000, 115200);
    UART0->LINE = UART_WORD_LEN_8 | UART_PARITY_NONE | UART_STOP_BIT_1;
}

void UART1_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART                                                                                               */
    /*---------------------------------------------------------------------------------------------------------*/
    CLK->APBCLK0 |= CLK_APBCLK0_UART1CKEN_Msk;


    // GPD[6]       CON30.58
    // GPD[7]       CON30.60
    SYS->GPD_MFPL &= ~(UART1_RXD_PD6_Msk | UART1_TXD_PD7_Msk);
    SYS->GPD_MFPL |= UART1_RXD_PD6 | UART1_TXD_PD7;


    /* Configure UART0 and set UART0 Baudrate */
    UART1->BAUD = UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(12000000, 115200);
    UART1->LINE = UART_WORD_LEN_8 | UART_PARITY_NONE | UART_STOP_BIT_1;
}


void IP_Init(void)
{
    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;
    NVIC_EnableIRQ(CRPT_IRQn);


}

void SYS_Init(void)
{

    CLK->PWRCTL |= CLK_PWRCTL_HIRCEN_Msk;
    CLK->CLKSEL0 = CLK_CLKSEL0_HCLKSEL_HIRC;
    CLK->CLKDIV0 = 0;
    

    PllClock = 12000000;
    SystemCoreClock = 12000000;
    CyclesPerUs = 12000000 / 1000000;


    /* Enable UART0 peripheral clock */
    CLK->APBCLK0 |= CLK_APBCLK0_UART0CKEN_Msk | CLK_APBCLK0_CAN0CKEN_Msk;
    /* CLKSEL1. UART clock source: external high speed crystal (12 MHz). */
    CLK->CLKSEL1 &= (~CLK_CLKSEL2_UART0SEL_Msk);
    CLK->CLKSEL1 |= CLK_CLKSEL2_UART0SEL_HIRC;
    /* UARTDIV = 0 */
    CLK->CLKDIV0 &= ~CLK_CLKDIV0_UART0DIV_Msk;



}
