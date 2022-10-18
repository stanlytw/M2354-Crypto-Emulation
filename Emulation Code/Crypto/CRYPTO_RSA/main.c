/**************************************************************************//**
 * @file     main.c
 * @version  V1.00
 * $Revision: 10 $
 * $Date: 15/11/19 10:11a $
 * @brief    Shows how to use Crypto RSA engine to sign and verify
 *           signatures.
 * @note
 * Copyright (C) 2019 Nuvoton Technology Corp. All rights reserved.
*****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "NuMicro.h"



#if 1

#define RSA_BIT_LEN         3072
#define RSA_KEY_SIZE_IDX    RSA_KEY_SIZE_3072

__ALIGNED(4) static char    N[RSA_KBUF_HLEN] = "883a510c705c06b574e000c199c45ff24c7cc5929ae8ad1db99b68b721e80e21fd733e8af11fc1d3ed0c2a8f35d332fdf5fe1eb6cefb36a3af2feb156758f0e78506e5234196cb1c212da0a9eb1bed5a7dddec4b28ab0453b2a12678f29142cb0b777e8709ce0a45ce16cafbe898bbd1cabbae078edf8916833ccdc91b129d27ff9229b353ad3afe138a8a98202b8376da553e3de14f9876df221587bff3193d6e990f300b14c5a2050a8eff3c790c33dc01ab3cecd754b2b865bd1705a53c1dd9aca4b02cb86502e6f9761462ca616f5bb4c1197adc569f9bdcec73b43cb99f5601d8cf0c7d5e77c1f05af873f9e614614124e4930e0ae05118cfea25e19fc4f08f5723c880232b4f7f112f779654c69d7f82c72536792bb2c3a291796925626ef6d2222d083926c4bfba01eb6d3920cdf74cb2318132b4bc555b633f90c454acabc4708db51e874b4b05f864a8c2186442e52310b94f96020b5d4045a8afeaae8896fbbbb2e22c5c8793bc475f2f5d07b9f6dc0ba0a3247345673a2f35b431";
__ALIGNED(4) static char    E[RSA_KBUF_HLEN] = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
__ALIGNED(4) static char    d[RSA_KBUF_HLEN] = "2b9b976446f77e8249b687277244a57e17b3fd3eefedb9b5013c5969fe259d988ddc7d51d6dc169cf38de875cd821d19a4cc4322bbe138dd6ef004ede616578f954adec0c9772eef83436ae1d9cc27cfc6e8ea8228b38e0008f7832c4661efa2b5b9fbbbd88ca7472f30a6abbb0a615d47eb8a4b0b164d78f26bdd681a0d7c57587d7e71d44068d8fa8267d948bb052b5fbad7e0d1263ca518ca7d5fe63738862cc83c4f61ccb57326eff95485142eaecf278d9c4428ae0943f3f572d030d3ac36f9258e05f1f6b6040acb0a405226870e29d40bf2897d3ab8838994e45e42826338b1f7e5cdec785498192876f23dd5b0270872dc53b2a76c0c8ee7f1edd78bc5e573089347aa144d82aad26ce4c980ae912a949a40b18ec1f9544dfb8a3452499165013484954734545d18171cce36bb1f3c756eaa40c1676f92e18714ab4bb61640fd6606b752d76b444d42115538cbb904acd1d1e5ef21f28a7605706eef29d6bf6f489b16f3e8ae1800a4dd22c87dcf42aebdd10528c86da54c81a7861d";
__ALIGNED(4) static char    Msg[RSA_KBUF_HLEN] = "70992c9d95a4908d2a94b3ab9fa1cd643f120e326f9d7808af50cac42c4b0b4eeb7f0d4df303a568fbfb82b0f58300d25357645721bb71861caf81b27a56082c80a146499fb4eab5bde4493f5d00f1a437bbc360dfcd8056fe6be10e608adb30b6c2f7652428b8d32d362945982a46585d2102ef7995a8ba6e8ad8fd16bd7ae8f53c3d7fcfba290b57ce7f8f09c828d6f2d3ce56f131bd9461e5667e5b73edac77f504dac4f202a9570eb4515b2bf516407db831518db8a2083ec701e8fd387c430bb1a72deca5b49d429cf9deb09cc4518dc5f57c089aa2d3420e567e732102c2c92b88a07c69d70917140ab3823c63f312d3f11fa87ba29da3c7224b4fb4bc";


#elif 1

#define RSA_BIT_LEN         3072
#define RSA_KEY_SIZE_IDX    RSA_KEY_SIZE_3072

__ALIGNED(4) static char    N[RSA_KBUF_HLEN] = "883a510c705c06b574e000c199c45ff24c7cc5929ae8ad1db99b68b721e80e21fd733e8af11fc1d3ed0c2a8f35d332fdf5fe1eb6cefb36a3af2feb156758f0e78506e5234196cb1c212da0a9eb1bed5a7dddec4b28ab0453b2a12678f29142cb0b777e8709ce0a45ce16cafbe898bbd1cabbae078edf8916833ccdc91b129d27ff9229b353ad3afe138a8a98202b8376da553e3de14f9876df221587bff3193d6e990f300b14c5a2050a8eff3c790c33dc01ab3cecd754b2b865bd1705a53c1dd9aca4b02cb86502e6f9761462ca616f5bb4c1197adc569f9bdcec73b43cb99f5601d8cf0c7d5e77c1f05af873f9e614614124e4930e0ae05118cfea25e19fc4f08f5723c880232b4f7f112f779654c69d7f82c72536792bb2c3a291796925626ef6d2222d083926c4bfba01eb6d3920cdf74cb2318132b4bc555b633f90c454acabc4708db51e874b4b05f864a8c2186442e52310b94f96020b5d4045a8afeaae8896fbbbb2e22c5c8793bc475f2f5d07b9f6dc0ba0a3247345673a2f35b431";
__ALIGNED(4) static char    E[RSA_KBUF_HLEN] = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
__ALIGNED(4) static char    d[RSA_KBUF_HLEN] = "2b9b976446f77e8249b687277244a57e17b3fd3eefedb9b5013c5969fe259d988ddc7d51d6dc169cf38de875cd821d19a4cc4322bbe138dd6ef004ede616578f954adec0c9772eef83436ae1d9cc27cfc6e8ea8228b38e0008f7832c4661efa2b5b9fbbbd88ca7472f30a6abbb0a615d47eb8a4b0b164d78f26bdd681a0d7c57587d7e71d44068d8fa8267d948bb052b5fbad7e0d1263ca518ca7d5fe63738862cc83c4f61ccb57326eff95485142eaecf278d9c4428ae0943f3f572d030d3ac36f9258e05f1f6b6040acb0a405226870e29d40bf2897d3ab8838994e45e42826338b1f7e5cdec785498192876f23dd5b0270872dc53b2a76c0c8ee7f1edd78bc5e573089347aa144d82aad26ce4c980ae912a949a40b18ec1f9544dfb8a3452499165013484954734545d18171cce36bb1f3c756eaa40c1676f92e18714ab4bb61640fd6606b752d76b444d42115538cbb904acd1d1e5ef21f28a7605706eef29d6bf6f489b16f3e8ae1800a4dd22c87dcf42aebdd10528c86da54c81a7861d";
__ALIGNED(4) static char    Msg[RSA_KBUF_HLEN] = "70992c9d95a4908d2a94b3ab9fa1cd643f120e326f9d7808af50cac42c4b0b4eeb7f0d4df303a568fbfb82b0f58300d25357645721bb71861caf81b27a56082c80a146499fb4eab5bde4493f5d00f1a437bbc360dfcd8056fe6be10e608adb30b6c2f7652428b8d32d362945982a46585d2102ef7995a8ba6e8ad8fd16bd7ae8f53c3d7fcfba290b57ce7f8f09c828d6f2d3ce56f131bd9461e5667e5b73edac77f504dac4f202a9570eb4515b2bf516407db831518db8a2083ec701e8fd387c430bb1a72deca5b49d429cf9deb09cc4518dc5f57c089aa2d3420e567e732102c2c92b88a07c69d70917140ab3823c63f312d3f11fa87ba29da3c7224b4fb4bc";


#elif 1

#define RSA_BIT_LEN         1024
#define RSA_KEY_SIZE_IDX    RSA_KEY_SIZE_1024

__ALIGNED(4) static char    N[RSA_KBUF_HLEN] = "b524a5d22c4df982e24d42684075f1d281be7668b180df4d631ef5822e3659bbc5d105512df342377a7101fc2032c02677ac306920d4fc9a695a0ab5e66d23eef9b2c204ab90bf7396bd96a14135c46c499c2c4f763b92d7bd60fb23a21f650e3f5989f84287ebdf8d564e5ea095c7295008135dae0e2033d69a600bc783d4b3";
__ALIGNED(4) static char    E[RSA_KBUF_HLEN] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
__ALIGNED(4) static char    d[RSA_KBUF_HLEN] = "4a96640726421736eb0b0808985e586c270b6f834d6fb4c30f48fcab956ec0c53e3f82927a3abbadcf677ffb3aa0db191bd6d57a3c50271147c71138f44045765c888318a465f68d84639d0823e002f736413156a988bc7e2e7ca38f465852b6017993fc4b323343d236fcfcd79ef2ff37c7bd0c0de24d44470682611b8b6fc9";
__ALIGNED(4) static char    Msg[RSA_KBUF_HLEN] = "70992c9d95a4908d2a94b3ab9fa1cd643f120e326f9d7808af50cac42c4b0b4eeb7f0d4df303a568fbfb82b0f58300d25357645721bb71861caf81b27a56082c80a146499fb4eab5bde4493f5d00f1a437bbc360dfcd8056fe6be10e608adb30b6c2f7652428b8d32d362945982a46585d2102ef7995a8ba6e8ad8fd16bd7ae8f53c3d7fcfba290b57ce7f8f09c828d6f2d3ce56f131bd9461e5667e5b73edac77f504dac4f202a9570eb4515b2bf516407db831518db8a2083ec701e8fd387c430bb1a72deca5b49d429cf9deb09cc4518dc5f57c089aa2d3420e567e732102c2c92b88a07c69d70917140ab3823c63f312d3f11fa87ba29da3c7224b4fb4bc";

#elif 1
#define RSA_BIT_LEN         2048
#define RSA_KEY_SIZE_IDX    RSA_KEY_SIZE_2048
__ALIGNED(4) static char    N[RSA_KBUF_HLEN] = "d716c76fdf63960d444a8e8b682640a5dffa5dcf15c64d517deb172fb83f5086a8e5b2453f6cead4e0efe05dc2a4bb21bad469a4a2c36001d780672b7197649eb2b53929dedede1946ea1c115bc866136073c32c0c10238cad164550c7c9f0a9f5d511f9f5b64b9f4d2831fd936fb03420bb1788955dcac40e1d29b59829bf6b66d71087803173d2f17620e6814436b7f4487857073abe26b5770d9b3dba132725f582997432cd9a360defc744bfc863b6eb3b16e373cf4c5cefeccdf87b4f9a50e99e2ed8f898f0bb78b70ccbaee11b995c796efce669cd72551636d536f4ab0148d5df80f23f9e0327d2758f2b4df3a0a64e3d39961048badc9f36d4eccfff";
__ALIGNED(4) static char    E[RSA_KBUF_HLEN] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
__ALIGNED(4) static char    d[RSA_KBUF_HLEN] = "c39aa3a4c9b2f732f978144a135d364da3733cfca700c02fec236fe2a5dc6e8f07ea5c453d78ffd6b8f96d41d751981d049b47b7c18d8c3220995539dd03a12df1b77d54e6aa27b1351c9289f6be38964691005d7e5aeef9702f60ba25f7303660aa74bead062b9fa3bb7a3af16a110456ffce5717ff43f7281ebd5fb811bf5170c3951fa00b11eb0d401a29f9c648d6b9771077d3a563ec0a1cfb76fa3be4208cfb7fd581c9d8a89027998e101844430619cf9fd95aa693e05c11b58c9be6d168e9fc9e304f1944f0a77d290098396a7fd7e495c5592efcec34ae9a38ffd83e248de7855a3583cfa8e16158def0d8a27d0fd5dfb40ab078456ec3e6fd24381";
__ALIGNED(4) static char    Msg[RSA_KBUF_HLEN] = "70992c9d95a4908d2a94b3ab9fa1cd643f120e326f9d7808af50cac42c4b0b4eeb7f0d4df303a568fbfb82b0f58300d25357645721bb71861caf81b27a56082c80a146499fb4eab5bde4493f5d00f1a437bbc360dfcd8056fe6be10e608adb30b6c2f7652428b8d32d362945982a46585d2102ef7995a8ba6e8ad8fd16bd7ae8f53c3d7fcfba290b57ce7f8f09c828d6f2d3ce56f131bd9461e5667e5b73edac77f504dac4f202a9570eb4515b2bf516407db831518db8a2083ec701e8fd387c430bb1a72deca5b49d429cf9deb09cc4518dc5f57c089aa2d3420e567e732102c2c92b88a07c69d70917140ab3823c63f312d3f11fa87ba29da3c7224b4fb4bc";

#else
#define RSA_BIT_LEN         2048
#define RSA_KEY_SIZE_IDX    RSA_KEY_SIZE_2048
__ALIGNED(4) static char    N[RSA_KBUF_HLEN] = "bad47a84c1782e4dbdd913f2a261fc8b65838412c6e45a2068ed6d7f16e9cdf4462b39119563cafb74b9cbf25cfd544bdae23bff0ebe7f6441042b7e109b9a8afaa056821ef8efaab219d21d6763484785622d918d395a2a31f2ece8385a8131e5ff143314a82e21afd713bae817cc0ee3514d4839007ccb55d68409c97a18ab62fa6f9f89b3f94a2777c47d6136775a56a9a0127f682470bef831fbec4bcd7b5095a7823fd70745d37d1bf72b63c4b1b4a3d0581e74bf9ade93cc46148617553931a79d92e9e488ef47223ee6f6c061884b13c9065b591139de13c1ea2927491ed00fb793cd68f463f5f64baa53916b46c818ab99706557a1c2d50d232577d1";
__ALIGNED(4) static char    E[RSA_KBUF_HLEN] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
__ALIGNED(4) static char    d[RSA_KBUF_HLEN] = "40d60f24b61d76783d3bb1dc00b55f96a2a686f59b3750fdb15c40251c370c65cada222673811bc6b305ed7c90ffcb3abdddc8336612ff13b42a75cb7c88fb936291b523d80acce5a0842c724ed85a1393faf3d470bda8083fa84dc5f31499844f0c7c1e93fb1f734a5a29fb31a35c8a0822455f1c850a49e8629714ec6a2657efe75ec1ca6e62f9a3756c9b20b4855bdc9a3ab58c43d8af85b837a7fd15aa1149c119cfe960c05a9d4cea69c9fb6a897145674882bf57241d77c054dc4c94e8349d376296137eb421686159cb878d15d171eda8692834afc871988f203fc822c5dcee7f6c48df663ea3dc755e7dc06aebd41d05f1ca2891e2679783244d068f";
__ALIGNED(4) static char    Msg[RSA_KBUF_HLEN] = "70992c9d95a4908d2a94b3ab9fa1cd643f120e326f9d7808af50cac42c4b0b4eeb7f0d4df303a568fbfb82b0f58300d25357645721bb71861caf81b27a56082c80a146499fb4eab5bde4493f5d00f1a437bbc360dfcd8056fe6be10e608adb30b6c2f7652428b8d32d362945982a46585d2102ef7995a8ba6e8ad8fd16bd7ae8f53c3d7fcfba290b57ce7f8f09c828d6f2d3ce56f131bd9461e5667e5b73edac77f504dac4f202a9570eb4515b2bf516407db831518db8a2083ec701e8fd387c430bb1a72deca5b49d429cf9deb09cc4518dc5f57c089aa2d3420e567e732102c2c92b88a07c69d70917140ab3823c63f312d3f11fa87ba29da3c7224b4fb4bc";
#endif


static volatile int g_RSA_done;
static volatile int g_RSA_error;

void CRPT_IRQHandler(void);
void SYS_Init(void);
void DEBUG_PORT_Init(void);



uint32_t GetUartData(char *buf, uint32_t size)
{
    uint32_t i;
    char ch;

    for(i = 0; i < size; i++)
    {
        ch = (char)getchar();
        buf[i] = ch;
        
        if(ch == '\r')
        {
            buf[i] = 0;
            break;
        }
        
        putchar(ch);
    }
    buf[i] = 0; // NULL end

    return size;
}

uint32_t GetLength(void);

/*
    Get number. The input number should be in dec
*/
int32_t GetNumber(void)
{
    char str[64] = {0};
    int32_t i;
    char ch;


    i = 0;
    do
    {
        ch = (char)getchar();
        if(ch != '\r')
        {
            putchar(ch);
            str[i++] = ch;
        }
        else
        {
            str[i] = 0;
            break;
        }

        if(i >= 64)
        {
            str[63] = 0;
            break;
        }
    }
    while(1);


    return atoi(str);

}



void CRPT_IRQHandler(void)
{
    if(RSA_GET_INT_FLAG(CRPT))
    {
        g_RSA_done = 1;
        if(RSA_GET_INT_FLAG(CRPT)&CRPT_INTSTS_RSAEIF_Msk)
        {
            g_RSA_error = 1;
            printf("RSA error flag is set!!\n");
        }
        RSA_CLR_INT_FLAG(CRPT);
    }
}

void SYS_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init System Clock                                                                                       */
    /*---------------------------------------------------------------------------------------------------------*/
//    /* Enable HIRC clock (Internal RC 12MHz) */
//    CLK_EnableXtalRC(CLK_PWRCTL_HIRCEN_Msk);

//    /* Waiting for HIRC clock ready */
//    CLK_WaitClockReady(CLK_STATUS_HIRCSTB_Msk);

//    /* Select HCLK clock source as HIRC and and HCLK clock divider as 1 */
//    CLK_SetHCLK(CLK_CLKSEL0_HCLKSEL_HIRC, CLK_CLKDIV0_HCLK(1));

//    /* Set power level to 0 */
//    SYS_SetPowerLevel(SYS_PLCTL_PLSEL_PL0);

//    /* Set core clock to 96MHz */
//    CLK_SetCoreClock(96000000);
    
    CLK->PWRCTL |= CLK_PWRCTL_HIRCEN_Msk;
    CLK->CLKSEL0 =CLK_CLKSEL0_HCLKSEL_HIRC;
    CLK->CLKDIV0 = 0;
    

    /* Select IP clock source */
    CLK->CLKSEL2 = CLK_CLKSEL2_UART0SEL_HIRC;

    /* Enable IP clock */
    CLK->AHBCLK  |= CLK_AHBCLK_CRPTCKEN_Msk | \
                    CLK_AHBCLK_SRAM0CKEN_Msk | CLK_AHBCLK_SRAM1CKEN_Msk | CLK_AHBCLK_SRAM2CKEN_Msk | \
                    CLK_AHBCLK_GPACKEN_Msk | CLK_AHBCLK_GPBCKEN_Msk | CLK_AHBCLK_GPCCKEN_Msk | CLK_AHBCLK_GPDCKEN_Msk | \
                    CLK_AHBCLK_GPECKEN_Msk | CLK_AHBCLK_GPFCKEN_Msk | CLK_AHBCLK_GPGCKEN_Msk | CLK_AHBCLK_GPHCKEN_Msk;

    CLK->APBCLK0 |= CLK_APBCLK0_UART0CKEN_Msk;

    /* Enable Crypto power */
    SYS->PSWCTL = SYS_PSWCTL_CRPTPWREN_Msk;

    /* Update System Core Clock */
    SystemCoreClockUpdate();

    /*---------------------------------------------------------------------------------------------------------*/
    /* Init I/O Multi-function                                                                                 */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Set multi-function pins for UART0 RXD and TXD */
    //SYS->GPA_MFPL = (SYS->GPA_MFPL & (~(UART0_RXD_PA6_Msk | UART0_TXD_PA7_Msk))) | UART0_RXD_PA6 | UART0_TXD_PA7;
    SET_UART0_RXD_PB12();
    SET_UART0_TXD_PB13();

}

void DEBUG_PORT_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART                                                                                               */
    /*---------------------------------------------------------------------------------------------------------*/
    DEBUG_PORT->LINE = UART_PARITY_NONE | UART_STOP_BIT_1 | UART_WORD_LEN_8;
    DEBUG_PORT->BAUD = UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(__HIRC, 115200);

}

/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
RSA_BUF_NORMAL rsaBuf;
int32_t main(void)
{
    char    OutputResult[RSA_KBUF_HLEN];
    uint32_t len;
    char *p;

    SYS_UnlockReg();

    /* Init System, IP clock and multi-function I/O */
    SYS_Init();

    /* Init UART0 for printf */
    DEBUG_PORT_Init();

    printf("\n\n+---------------------------------------------+\n");
    printf("|   Crypto RSA sample                         |\n");
    printf("+---------------------------------------------+\n");

    NVIC_EnableIRQ(CRPT_IRQn);

    RSA_ENABLE_INT(CRPT);

    g_RSA_done = 0;
    g_RSA_error = 0;

    printf("Private key (N,d) -\n");
    printf("    N = %s\n", N);
    printf("    d = %s\n", d);
    printf("Public key (N,e) -\n");
    printf("    E = %s\n", E);
    
    
    /* Text Input */
    printf("Enter Message length: ");
    len = GetNumber();
    printf("\n");

    if(len > RSA_BIT_LEN/8)
    {
        printf("Input length is larger than %d\n", RSA_BIT_LEN/8);
        while(1);
    }

    printf("Waiting for data ...\n");
    len = GetUartData(Msg, len);
    printf("\n");
    
    
    /*---------------------------------------
     *  RSA sign
     *---------------------------------------*/
    /* Configure RSA operation mode and key length */
    RSA_Open(CRPT, RSA_MODE_NORMAL, RSA_KEY_SIZE_IDX, &rsaBuf, sizeof(rsaBuf), 0);
    /* Set RSA private key */
    RSA_SetKey(CRPT, d);
    RSA_SetDMATransfer(CRPT, Msg, N, 0, 0);
    RSA_Start(CRPT);

    /* Waiting for RSA operation done */
    while(!g_RSA_done);

    /* Check error flag */
    if(g_RSA_error)
    {
        printf("\nRSA has error!!\n");
        while(1);
    }

    /* Get RSA output result */
    RSA_Read(CRPT, OutputResult);
    printf("\nRSA sign: %s\n", OutputResult);

    /*---------------------------------------
     *  RSA verify
     *---------------------------------------*/
    g_RSA_done = 0;
    g_RSA_error = 0;

    /* Configure RSA operation mode and key length */
    RSA_Open(CRPT, RSA_MODE_NORMAL, RSA_KEY_SIZE_IDX, &rsaBuf, sizeof(rsaBuf), 0);
    /* Set RSA public key */
    RSA_SetKey(CRPT, E);
    RSA_SetDMATransfer(CRPT, OutputResult, N, 0, 0);
    RSA_Start(CRPT);

    /* Waiting for RSA operation done */
    while(!g_RSA_done);

    /* Check error flag */
    if(g_RSA_error)
    {
        printf("\nRSA has error!!\n");
        while(1);
    }

    /* Get RSA output result */
    RSA_Read(CRPT, OutputResult);
    printf("\nRSA Output: %s\n", &OutputResult[RSA_BIT_LEN/4-len]);
    p = &OutputResult[RSA_BIT_LEN/4-len];
    
    if(strncmp(Msg, p, len) != 0)
    {
        printf("Verify FAIL!\n");
    }
    else
    {
        printf("Verify PASS!\n");
    }
    
    
    printf("\nDone.\n");
    while(1);
}
