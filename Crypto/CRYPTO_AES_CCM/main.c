/**************************************************************************//**
 * @file     main.c
 * @version  V1.10
 * @brief    Mbedtls AES test suite
 *
 * @copyright (C) 2018 Nuvoton Technology Corp. All rights reserved.
*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include "NuMicro.h"

#define _SWAP


#define MAX_GCM_BUF     4096
__ALIGNED(4) uint8_t g_au8Buf[MAX_GCM_BUF];
__ALIGNED(4) uint8_t g_au8Out[MAX_GCM_BUF];
__ALIGNED(4) uint8_t g_au8Out2[MAX_GCM_BUF];

__ALIGNED(4) uint8_t g_key[32] = { 0 };
__ALIGNED(4) uint8_t g_iv[32] = { 0 };
__ALIGNED(4) uint8_t g_A[265] = { 0 };
__ALIGNED(4) uint8_t g_P[256] = { 0 };
__ALIGNED(4) uint8_t g_C[256] = { 0 };
__ALIGNED(4) uint8_t g_T[256] = { 0 };

__ALIGNED(4) uint8_t g_au8Tmpbuf[32] = { 0 };


typedef struct {
    char* pchKey;   /* The block cipher key */
    char* pchIV;    /* The initialization vector */
    char* pchA;     /* The additional authenticated data */
    char* pchP;     /* The plaintext */
    char* pchC;     /* The ciphertext */
    uint8_t u8Tlen;
} CCM_TEST_T;



/* Test items */
const CCM_TEST_T sElements[] = {
    {
        "404142434445464748494A4B4C4D4E4F",
        "10111213141516",
        "0001020304050607",
        "20212223",
        "7162015B4DAC255D",
        32,
    },
    {
        "404142434445464748494A4B4C4D4E4F",
        "1011121314151617",
        "000102030405060708090A0B0C0D0E0F",
        "202122232425262728292A2B2C2D2E2F",
        "D2A1F0E051EA5F62081A7792073D593D1FC64FBFACCD",
        48,
    },
    {
        "404142434445464748494A4B4C4D4E4F",
        "101112131415161718191A1B",
        "000102030405060708090A0B0C0D0E0F10111213",
        "202122232425262728292A2B2C2D2E2F3031323334353637",
        "E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA5484392FBC1B09951",
        64,
    },
    {
        "404142434445464748494A4B4C4D4E4F",
        "10111213141516",
        "",
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        "7162015BC051951E5918AEAF3C11F3D4AC363F8D5B6AF3D369603B04F24CAE29964E2F2BF9D31143F72527CE2DB402EAB7660E4A10B08E82266517CDF60267F9C66B655C",
        32,
    },
    {
        "404142434445464748494A4B4C4D4E4F5051525354555657",
        "1011121314151617",
        "000102030405060708090A0B0C0D0E0F",
        "202122232425262728292A2B2C2D2E2F",
        "2232B6E0924148AE7239BCBD1A0F7ECB56E9CC28AA67",
        48,
    },
    {
        "404142434445464748494A4B4C4D4E4F5051525354555657",
        "10111213141516",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "",
        "F1FB2A57",
        32,
    },
    {
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        "10111213141516",
        "0001020304050607",
        "20212223",
        "8AB1A87495FC0820",
        32,
    },
    {
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        "101112131415161718191A1B",
        "000102030405060708090A0B0C0D0E0F10111213",
        "202122232425262728292A2B2C2D2E2F3031323334353637",
        "04F883AEB3BD0730EAF50BB6DE4FA2212034E4E41B0E75E52B48C8766F7E7649",
        64,
    },
    {
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        "10111213141516",
        "",
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        "8AB1A874F6853F2443A59500F78D17272D6D39DFA6D0E65107B10700C2CE9EE8663D3E2A01C2E12C32E9377442231920BE53278F4F60A972B709BB16932936BA3FBD0FAE",
        32,
    },
    {
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        "10111213141516",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "",
        "A6CF8230",
        32,
    },
};



void DumpBuffHex(uint8_t *pucBuff, int nBytes)
{
    int32_t i32Idx, i, len;


    i32Idx = 0;
    while(nBytes > 0)
    {
        printf("0x%04X  ", i32Idx);

        len = (nBytes < 16)?nBytes:16;
        for(i = 0; i < len; i++)
            printf("%02x ", pucBuff[i32Idx + i]);
        for(; i < 16; i++)
        {
            printf("   ");
        }
        printf("  ");
        for(i = 0; i < len; i++)
        {
            if((pucBuff[i32Idx + i] >= 0x20) && (pucBuff[i32Idx + i] < 127))
                printf("%c", pucBuff[i32Idx + i]);
            else
                printf(".");
            nBytes--;
        }
        i32Idx += len;
        printf("\n");
    }
    printf("\n");
}


void DumpBuffHex2(uint8_t *pucBuff, int nBytes)
{
    int32_t i32Idx, i;

    i32Idx = 0;
    while(nBytes > 0)
    {
        printf("0x%04X  ", i32Idx);
        for(i = 0; i < 16; i+=4)
            printf("%08x ", *((uint32_t *)&pucBuff[i32Idx + i]));
        i32Idx += 16;
        nBytes -= 16;
        printf("\n");
    }
    printf("\n");
}



void SYS_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init System Clock                                                                                       */
    /*---------------------------------------------------------------------------------------------------------*/

    /* Enable HIRC clock */
    CLK_EnableXtalRC(CLK_PWRCTL_HIRCEN_Msk);

    /* Wait for HIRC clock ready */
    CLK_WaitClockReady(CLK_STATUS_HIRCSTB_Msk);

    /* Set core clock to 96MHz */
    CLK_SetCoreClock(96000000);

    /* Enable UART0 module clock */
    CLK_EnableModuleClock(UART0_MODULE);

    /* Select UART0 module clock source as HIRC and UART0 module clock divider as 1 */
    CLK_SetModuleClock(UART0_MODULE, CLK_CLKSEL2_UART0SEL_HIRC, CLK_CLKDIV0_UART0(1));

    /* Enable ACMP01 peripheral clock */
    CLK_EnableModuleClock(CRPT_MODULE);

    /* Update System Core Clock */
    SystemCoreClockUpdate();

    /*---------------------------------------------------------------------------------------------------------*/
    /* Init I/O Multi-function                                                                                 */
    /*---------------------------------------------------------------------------------------------------------*/

    /* Set multi-function pins for UART0 RXD and TXD */
    SYS->GPA_MFPL = (SYS->GPA_MFPL & (~(UART0_RXD_PA6_Msk | UART0_TXD_PA7_Msk))) | UART0_RXD_PA6 | UART0_TXD_PA7;

}

void UART0_Init(void)
{

    /* Configure UART0 and set UART0 baud rate */
    UART_Open(UART0, 115200);
}


volatile int  g_Crypto_Int_done = 0;

void CRPT_IRQHandler()
{
    if(AES_GET_INT_FLAG(CRPT))
    {
        g_Crypto_Int_done = 1;
        AES_CLR_INT_FLAG(CRPT);
    }
}


void str2bin(const char *pstr, uint8_t *buf, uint32_t size)
{
    uint32_t i, len;
    uint8_t u8Ch;
    char c;

    for(i = 0; i < size; i++)
    {
        c = *pstr++;
        if(c == NULL)
            break;

        if((c >= 'a') && (c <= 'f'))
            c -= ('a' - 10);
        else if((c >= 'A') && (c <= 'F'))
            c -= ('A' - 10);
        else if((c >= '0') && (c <= '9'))
            c -= '0';
        u8Ch = (uint8_t)c << 4;

        c = *pstr++;
        if(c == NULL)
        {
            buf[i] = u8Ch;
            break;
        }

        if((c >= 'a') && (c <= 'f'))
            c -= ('a' - 10);
        else if((c >= 'A') && (c <= 'F'))
            c -= ('A' - 10);
        else if((c >= '0') && (c <= '9'))
            c -= '0';
        u8Ch += (uint8_t)c;

        buf[i] = u8Ch;
    }

}

void bin2str(uint8_t *buf, uint32_t size, char *pstr)
{
    int32_t i;
    uint8_t c;
    
    for(i=size-1;i >= 0;i--)
    {
        c = buf[i] >> 4;
        *pstr++ = (c >= 10)?c-10+'a':c+'0';
        c = buf[i] & 0xf;
        *pstr++ = (c >= 10)?c-10+'a':c+'0';
    }
    
    *pstr = '\0';
}

/* The length is fixed to be 16 bytes for little to big endian trasform. */
int32_t ToBigEndian16(uint8_t *pbuf, uint32_t size)
{
    int32_t i;
    uint8_t u8Tmp;

    // size must be 16 bytes alignment
    if(size & 0xf)
        return -1;

    while(size > 0)
    {
        for(i = 0; i < 8; i++)
        {
            u8Tmp = pbuf[i];
            pbuf[i] = pbuf[15 - i];
            pbuf[15 - i] = u8Tmp;
        }

        size -= 16;
        pbuf += 16;
    }
    return 0;
}

int32_t ToBigEndian(uint8_t *pbuf, uint32_t u32Size)
{
    uint32_t i;
    uint8_t u8Tmp;
    uint32_t u32Tmp;

    /* pbuf must be word alignment */
    if((uint32_t)pbuf & 0x3)
    {
        printf("The buffer must be 32-bit alignment.");
        return -1;
    }

    while(u32Size >= 4)
    {
        u8Tmp = *pbuf;
        *(pbuf) = *(pbuf + 3);
        *(pbuf + 3) = u8Tmp;

        u8Tmp = *(pbuf + 1);
        *(pbuf + 1) = *(pbuf + 2);
        *(pbuf + 2) = u8Tmp;

        u32Size -= 4;
        pbuf += 4;
    }

    if(u32Size > 0)
    {
        u32Tmp = 0;
        for(i = 0; i < u32Size; i++)
        {
            u32Tmp |= *(pbuf + i) << (24 - i * 8);
        }

        *((uint32_t *)pbuf) = u32Tmp;
    }
    
    return 0;
}



int32_t ToLittleEndian(uint8_t *pbuf, uint32_t u32Size)
{
    uint32_t i;
    uint8_t u8Tmp;
    uint32_t u32Tmp;

    /* pbuf must be word alignment */
    if((uint32_t)pbuf & 0x3)
    {
        printf("The buffer must be 32-bit alignment.");
        return -1;
    }

    while(u32Size >= 4)
    {
        u8Tmp = *pbuf;
        *(pbuf) = *(pbuf + 3);
        *(pbuf + 3) = u8Tmp;

        u8Tmp = *(pbuf + 1);
        *(pbuf + 1) = *(pbuf + 2);
        *(pbuf + 2) = u8Tmp;

        u32Size -= 4;
        pbuf += 4;
    }

    if(u32Size > 0)
    {
        u32Tmp = 0;
        for(i = 0; i < u32Size; i++)
        {
            u32Tmp |= *(pbuf + i) << (24 - i * 8);
        }

        *((uint32_t *)pbuf) = u32Tmp;
    }

    return 0;
}



/*
    CCM input format must be block alignment. The block size is 16 bytes.
    
    ----------------------------------------------------------------------
     Block B0                                                             
          Formatting of the Control Information and the Nonce             
    ----------------------------------------------------------------------
    First block B_0:
    0        .. 0        flags
    1        .. iv_len   nonce (aka iv)
    iv_len+1 .. 15       length
    

    flags:
    With flags as (bits):
    7        0
    6        add present?
    5 .. 3   (t - 2) / 2
    2 .. 0   q - 1
    





*/

int32_t CcmPacker(uint8_t *iv, uint32_t ivlen, uint8_t *A, uint32_t alen, uint8_t *P, uint32_t plen, uint8_t *pbuf, uint32_t *psize, uint32_t tlen)
{
    uint32_t i, j;
    uint32_t ivlen_aligned, alen_aligned, plen_aligned;
    uint32_t u32Offset = 0;
    uint32_t *pu32;
    uint8_t u8Tmp;
    uint32_t q;


    /* Flags in B0
    *With flags as(bits) :
        7        0
        6        add present ?
        5 .. 3   (t - 2) / 2
        2 .. 0   q - 1, q = 15 - nlen
    */

    q = 15 - ivlen;
    u8Tmp = (q - 1) | ((tlen - 2) / 2 << 3) | ((alen > 0) ? 0x40 : 0);
    pbuf[0] = u8Tmp;            // flags
    
    for(i = 0; i < ivlen; i++)  // N 
        pbuf[i + 1] = iv[i];
    for(i = ivlen + 1, j = q - 1; i < 16; i++, j--)    // Q
    {
        if(j >= 4)
            pbuf[i] = 0;
        else
        {
            pbuf[i] = (plen >> j * 8) & 0xfful;
        }
    }

    u32Offset = 16;
    /* Formatting addition data */
    // alen. It is limited to be smaller than 2^16-2^8
    if(alen > 0)
    {
        pbuf[u32Offset] = (alen >> 8) & 0xfful;
        pbuf[u32Offset + 1] = alen & 0xfful;

        for(i = 0; i < alen; i++)
            pbuf[u32Offset + i + 2] = A[i];

        alen_aligned = ((alen + 2 + 15) / 16) * 16;
        for(i = u32Offset + 2 + alen; i < alen_aligned; i++)
        {
            pbuf[i] = 0; // padding zero
        }
        
        u32Offset += alen_aligned;
    }

    /* Formatting payload */
    if(plen > 0)
    {
        plen_aligned = ((plen + 15) / 16) * 16;
        for(i = 0; i < plen; i++)
        {
            pbuf[u32Offset + i] = P[i];
        }
        for(; i < plen_aligned; i++)
        {
            pbuf[u32Offset + i] = 0; // padding zero
        }
        
        u32Offset += plen_aligned;
    }


    /* Formatting Ctr0 */
    pbuf[u32Offset] = q - 1; // Flags
    for(i = 0; i < ivlen; i++) // N
    {
        pbuf[u32Offset + 1 + i] = iv[i];
    }
    for(; i < 16; i++)
    {
        pbuf[u32Offset + 1 + i] = 0; // padding zero to block alignment
    }

    //u32Offset += 16;

    
    *psize = u32Offset;

    return 0;
}





int32_t ccm_enc(int32_t enc, uint8_t *key, uint32_t klen, uint8_t *iv, uint32_t ivlen, uint8_t *A, uint32_t alen, uint8_t *P, uint32_t plen, uint8_t *buf, uint32_t *size, uint32_t *plen_aligned, uint32_t tlen)
{
    __ALIGNED(4) uint8_t au8TmpBuf[32] = { 0 };

    printf("\n");

    printf("key (%d):\n", klen);
    DumpBuffHex(key, klen);

    printf("N (%d):\n",ivlen);
    DumpBuffHex(iv, ivlen);

    printf("A (%d):\n", alen);
    DumpBuffHex(A, alen);

    printf("P (%d):\n", plen);
    DumpBuffHex(P, plen);

    printf("T len = %d\n", tlen);

    /* Prepare the blocked buffer for GCM */
    CcmPacker(iv, ivlen, A, alen, P, plen, g_au8Buf, size, tlen);
    //printf("input blocks (%d) little endian:\n", *size);
    //DumpBuffHex(g_au8Buf, *size);
    
    ToBigEndian(g_au8Buf, *size+16);

    //g_au8Buf[30] = 0;
    //g_au8Buf[31] = 8;

    printf("input blocks (%d):\n", *size);
    DumpBuffHex2(g_au8Buf, *size);
    
    
    *plen_aligned = (plen & 0xful) ? ((plen + 15) / 16 * 16) : plen;


    memcpy(au8TmpBuf, key, klen);
    ToBigEndian(au8TmpBuf, klen);
    //ToBigEndian16(au8TmpBuf, klen);
    printf("input key (%d):\n", *size);
    DumpBuffHex2(au8TmpBuf, klen);


    if(klen == 16)
    {
        //printf("key length is 128\n");
        AES_Open(CRPT, 0, enc, AES_MODE_CCM, AES_KEY_SIZE_128, AES_OUT_SWAP);
        AES_SetKey(CRPT, 0, (uint32_t *)au8TmpBuf, AES_KEY_SIZE_128);
    }
    else if(klen == 24)
    {
        AES_Open(CRPT, 0, enc, AES_MODE_CCM, AES_KEY_SIZE_192, AES_OUT_SWAP);
        AES_SetKey(CRPT, 0, (uint32_t *)au8TmpBuf, AES_KEY_SIZE_192);
    }
    else
    {
        //printf("key size 256\n");
        AES_Open(CRPT, 0, enc, AES_MODE_CCM, AES_KEY_SIZE_256, AES_OUT_SWAP);
        AES_SetKey(CRPT, 0, (uint32_t *)au8TmpBuf, AES_KEY_SIZE_256);
    }

    printf("input Ctr0:\n");
    DumpBuffHex2(&g_au8Buf[*size], 16);

    AES_SetInitVect(CRPT, 0, (uint32_t *)&g_au8Buf[*size]);


    /* Set byte count of IV */
    //CRPT->AES_GCM_IVCNT[0] = ivlen;
    //CRPT->AES_GCM_IVCNT[1] = 0;

    /* Set bytes count of A */
    CRPT->AES_GCM_ACNT[0] = *size - *plen_aligned;
    CRPT->AES_GCM_ACNT[1] = 0;
    CRPT->AES_GCM_PCNT[0] = *plen_aligned;
    CRPT->AES_GCM_PCNT[1] = 0;

    //printf("alen=%d, plen=%d\n", CRPT->AES_GCM_ACNT[0], CRPT->AES_GCM_PCNT[0]);


    AES_SetDMATransfer(CRPT, 0, (uint32_t)g_au8Buf, (uint32_t)buf, *size);
    //AES_SetDMATransfer(CRPT, 0, (uint32_t)au8InputData, (uint32_t)au8OutputData, 0);
    //CRPT->AES_FBADDR = (uint32_t)g_au32FbBuf;

    g_Crypto_Int_done = 0;
    /* Start AES Eecrypt */
    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);
    /* Waiting for AES calculation */
    while(!g_Crypto_Int_done);


    printf("output blocks (%d):\n", *size);
    DumpBuffHex2(buf, *size);

    return 0;
}


/*-----------------------------------------------------------------------------*/
int main(void)
{
    int i;
    char  *params[50];
    int   cnt, vector_no;
    int   is_eof;
    uint32_t size, klen, plen, clen, tlen, plen_aligned, alen, ivlen;

    const char *key_str = "404142434445464748494a4b4c4d4e4f";
    const char *ct_str = "";
    const char *iv_str = "101112131415161718191A1B";
    const char *a_str = "000102030405060708090A0B0C0D0E0F10111213";
    const char *pt_str = "202122232425262728292A2B2C2D2E2F3031323334353637";
    const char *c_str = "E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA5484392FBC1B09951";
    tlen = 4;
    char strbuf[65] = {0};

    SYS_Init();                        /* Init System, IP clock and multi-function I/O */

    UART0_Init();                      /* Initialize UART0 */


    printf("+---------------------------------------+\n");
    printf("|     Crypto mbedtls CCM test suit      |\n");
    printf("+---------------------------------------+\n");

    NVIC_EnableIRQ(CRPT_IRQn);

    for(i=0;i<sizeof(sElements)/ sizeof(CCM_TEST_T);i++)
    {
        
        
        SYS->IPRST0 |= SYS_IPRST0_CRPTRST_Msk;
        SYS->IPRST0 ^= SYS_IPRST0_CRPTRST_Msk;
        
        memset(g_au8Buf, 0, sizeof(g_au8Buf));
        
        AES_ENABLE_INT(CRPT);
        
        
        printf("\n====================================================================\n");
        printf("Iter %d\n\n", i);
        
        key_str = sElements[i].pchKey;
        iv_str  = sElements[i].pchIV;
        a_str   = sElements[i].pchA;
        pt_str  = sElements[i].pchP;
        c_str   = sElements[i].pchC;
        tlen    = sElements[i].u8Tlen/8;
        
        printf("key = %s\n", key_str);
        printf("n   = %s\n", iv_str);
        printf("A   = %s\n", a_str);
        printf("P   = %s\n", pt_str);

        klen = strlen(key_str) / 2;
        ivlen = strlen(iv_str) / 2;
        alen = strlen(a_str) / 2;
        plen = strlen(pt_str) / 2;
        clen = plen + tlen;

        str2bin(key_str, g_key, klen);
        str2bin(iv_str, g_iv, ivlen);
        str2bin(a_str, g_A, alen);
        str2bin(pt_str, g_P, plen);
        str2bin(c_str, g_C, clen);
        
        ccm_enc(1, g_key, klen, g_iv, ivlen, g_A, alen, g_P, plen, g_au8Out, &size, &plen_aligned, tlen);

    #ifndef _SWAP
        ToLittleEndian(g_au8Out, size);
    #endif

        //while(1){}

        printf("C=%s\n", c_str);

        str2bin(c_str, g_C, plen);
        
        printf("g_C:\n");
        DumpBuffHex(g_C, plen);
        
        printf("g_au8Out:\n");
        DumpBuffHex(g_au8Out, plen);


        if(memcmp(g_C, g_au8Out, plen))
        {

            printf("ERR: Encrypted data fail!\n");
            printf("g_C:\n");
            DumpBuffHex(g_C, plen);
            printf("g_au8Out:\n");
            DumpBuffHex(g_au8Out, plen);
            while(1){}
        }

        if(memcmp(&g_C[plen], &g_au8Out[plen_aligned], tlen))
        {
            printf("ERR: Encrypted data fail!\n");
            while(1) {}
        }

        ccm_enc(0, g_key, klen, g_iv, ivlen, g_A, alen, g_C, plen, g_au8Out2, &size, &plen_aligned, tlen);


        if(memcmp(g_P, g_au8Out2, plen))
        {
            printf("ERR: Encrypted data fail!\n");
            while(1) {}
        }

        printf("Test PASS!\n");
    }

    while(1){}
}
