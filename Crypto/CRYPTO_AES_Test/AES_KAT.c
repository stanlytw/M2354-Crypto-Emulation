/*---------------------------------------------------------------------------------------------------------*/
/*                                                                                                         */
/* Copyright(c) 2015 Nuvoton Technology Corp. All rights reserved.                                         */
/*                                                                                                         */
/*---------------------------------------------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "NuMicro.h"
#include "crypto.h"

#define TEXT_MAX_LEN        68

typedef struct kat_t
{
    uint32_t    ctrl;
    int         keylen;
    char        key[64 + 2];
    char        iv[32 + 2];
    char        plainT[TEXT_MAX_LEN];
    char        cipherT[TEXT_MAX_LEN];
} KAT_T;

#include "test_vectors.c"

extern void  dump_buff_hex(uint8_t *pucBuff, int nBytes);

extern uint8_t  au8InputData[];
extern uint8_t  au8OutputData[];
extern uint8_t  au8CascadeOut[];

uint8_t  *pPlainText, *pCipherText, *pOutput;

extern volatile int g_AES_done;

static uint8_t  g_hex[256];

uint8_t  char_to_hex(uint8_t c)
{
    if((c >= '0') && (c <= '9'))
        return c - '0';
    if((c >= 'a') && (c <= 'f'))
        return c - 'a' + 10;
    if((c >= 'A') && (c <= 'F'))
        return c - 'A' + 10;
    return 0;
}

int  str2hex(char *str, uint8_t *hex)
{
    int  val8, count = 0;

    while(*str)
    {
        val8 = char_to_hex(*str);
        str++;
        val8 = (val8 << 4) | char_to_hex(*str);
        str++;

        hex[count] = val8;
        count++;
    }
    return count;
}

void  word_swap_hex(uint8_t *hex, int len)
{
    int      i;
    uint8_t  val8;

    len = (len + 3) & 0xfffffffc;

    for(i = 0; i < len; i += 4)
    {
        val8 = hex[i];
        hex[i] = hex[i + 3];
        hex[i + 3] = val8;

        val8 = hex[i + 1];
        hex[i + 1] = hex[i + 2];
        hex[i + 2] = val8;
    }
}


int  read_test_vector(KAT_T *t)
{
    int         i, count;
    uint32_t    *key_ptr;

    /*
     *  read AES key
     */
    if(str2hex(t->key, g_hex) != t->keylen)
        return -1;

    key_ptr = (uint32_t *) & (CRPT->AES_KEY[0]);

    for(i = 0; i < t->keylen; i += 4, key_ptr++)
    {
        *key_ptr = (g_hex[i] << 24) | (g_hex[i + 1] << 16) | (g_hex[i + 2] << 8) | g_hex[i + 3];
        //printf("Key %d = 0x%x\n", i/4, *key_ptr);
    }

    /*
     *  read AES initial vector
     */
    if(str2hex(t->iv, g_hex) != 16)
        return -1;

    key_ptr = (uint32_t *) & (CRPT->AES_IV[0]);

    for(i = 0; i < 16; i += 4, key_ptr++)
    {
        *key_ptr = (g_hex[i] << 24) | (g_hex[i + 1] << 16) | (g_hex[i + 2] << 8) | g_hex[i + 3];
        //printf("IV %d = 0x%x\n", i/4, *key_ptr);
    }

    /*
     *  read plain text
     */
    count = str2hex(t->plainT, pPlainText);

    /*
     *  read cipher text
     */
    str2hex(t->cipherT, pCipherText);

    return count;
}


int  AES_KAT_test()
{
    int     i, len;

    pPlainText = (uint8_t *)&au8InputData[0];
    pCipherText = (uint8_t *)&au8OutputData[0];
    pOutput = (uint8_t *)&au8CascadeOut[0];

    for(i = 0; i < sizeof(g_test_vector) / sizeof(KAT_T); i++)
    {
        printf("KAT test vecotr %d...\n", i);
        printf("IV: %s\n", g_test_vector[i].iv);

        len = read_test_vector((KAT_T *)&g_test_vector[i]);
        if(len < 0)
        {
            printf("Failed to read test vector!\n");
            return -1;
        }

        /*-------------------------------------------------
         *   Encode test
         *-------------------------------------------------*/

        CRPT->AES_SADDR = (uint32_t)pPlainText;
        CRPT->AES_DADDR = (uint32_t)pOutput;
        CRPT->AES_CNT = len;
        memset(pOutput, 0, len);

        g_AES_done = 0;

        CRPT->AES_CTL = g_test_vector[i].ctrl | CRPT_AES_CTL_ENCRPT_Msk |
                        CRPT_AES_CTL_INSWAP_Msk | CRPT_AES_CTL_OUTSWAP_Msk |
                        CRPT_AES_CTL_DMAEN_Msk | CRPT_AES_CTL_DMALAST_Msk | CRPT_AES_CTL_START_Msk;

        while(!g_AES_done);

        if(memcmp(pCipherText, pOutput, len) != 0)
        {
            printf("AES test vector encode failed at =>\n");
            printf("KEY        = %s\n", g_test_vector[i].key);
            printf("IV         = %s\n", g_test_vector[i].iv);
            printf("PLAINTEXT  = %s\n", g_test_vector[i].plainT);
            printf("CIPHERTEXT = %s\n", g_test_vector[i].cipherT);
            printf("Encode output:\n");
            dump_buff_hex(pOutput, len);
            return -1;
        }

        /*-------------------------------------------------
         *   Decode test
         *-------------------------------------------------*/

        CRPT->AES_SADDR = (uint32_t)pCipherText;
        CRPT->AES_DADDR = (uint32_t)pOutput;
        CRPT->AES_CNT = len;
        memset(pOutput, 0, len);

        g_AES_done = 0;

        CRPT->AES_CTL = g_test_vector[i].ctrl |
                        CRPT_AES_CTL_INSWAP_Msk | CRPT_AES_CTL_OUTSWAP_Msk |
                        CRPT_AES_CTL_DMAEN_Msk | CRPT_AES_CTL_DMALAST_Msk | CRPT_AES_CTL_START_Msk;

        while(!g_AES_done);

        if(memcmp(pPlainText, pOutput, len) != 0)
        {
            printf("AES test vector decode failed at =>\n");
            printf("KEY        = %s\n", g_test_vector[i].key);
            printf("IV         = %s\n", g_test_vector[i].iv);
            printf("PLAINTEXT  = %s\n", g_test_vector[i].plainT);
            printf("CIPHERTEXT = %s\n", g_test_vector[i].cipherT);

            printf("Encode output:\n");
            dump_buff_hex(pOutput, len);
            return -1;
        }

        /*-------------------------------------------------
         *   Encode test output swap test
         *-------------------------------------------------*/
        CRPT->AES_SADDR = (uint32_t)pPlainText;
        CRPT->AES_DADDR = (uint32_t)pOutput;
        CRPT->AES_CNT = len;
        memset(pOutput, 0, len);

        g_AES_done = 0;

        CRPT->AES_CTL = g_test_vector[i].ctrl | CRPT_AES_CTL_ENCRPT_Msk |
                        CRPT_AES_CTL_INSWAP_Msk |
                        CRPT_AES_CTL_DMAEN_Msk | CRPT_AES_CTL_DMALAST_Msk | CRPT_AES_CTL_START_Msk;

        while(!g_AES_done);

        word_swap_hex(pOutput, len);

        if(memcmp(pCipherText, pOutput, len) != 0)
        {
            printf("AES test vector encode input swap failed at =>\n");
            printf("KEY        = %s\n", g_test_vector[i].key);
            printf("IV         = %s\n", g_test_vector[i].iv);
            printf("PLAINTEXT  = %s\n", g_test_vector[i].plainT);
            printf("CIPHERTEXT = %s\n", g_test_vector[i].cipherT);

            printf("Encode output:\n");
            dump_buff_hex(pOutput, len);
            return -1;
        }

        /*-------------------------------------------------
         *   Encode test input swap test
         *-------------------------------------------------*/
        CRPT->AES_SADDR = (uint32_t)pPlainText;
        CRPT->AES_DADDR = (uint32_t)pOutput;
        CRPT->AES_CNT = len;
        memset(pOutput, 0, len);

        word_swap_hex(pPlainText, len);

        g_AES_done = 0;

        CRPT->AES_CTL = g_test_vector[i].ctrl | CRPT_AES_CTL_ENCRPT_Msk |
                        CRPT_AES_CTL_OUTSWAP_Msk |
                        CRPT_AES_CTL_DMAEN_Msk | CRPT_AES_CTL_DMALAST_Msk | CRPT_AES_CTL_START_Msk;

        while(!g_AES_done);

        if(memcmp(pCipherText, pOutput, len) != 0)
        {
            printf("AES test vector encode input swap failed at =>\n");
            printf("KEY        = %s\n", g_test_vector[i].key);
            printf("IV         = %s\n", g_test_vector[i].iv);
            printf("PLAINTEXT  = %s\n", g_test_vector[i].plainT);
            printf("CIPHERTEXT = %s\n", g_test_vector[i].cipherT);

            printf("Encode output:\n");
            dump_buff_hex(pOutput, len);
            return -1;
        }
    }

    printf("All test vector passed.\n");
    return 0;
}



