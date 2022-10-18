/**************************************************************************//**
 * @file     main.c
 * @version  V1.10
 * $Revision: 1 $
 * $Date: 16/07/28 3:38p $
 * @brief    Generate random numbers using Crypto IP PRNG
 *
 * @note
 * Copyright (C) 2013 Nuvoton Technology Corp. All rights reserved.
*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "NuMicro.h"
#include "crypto.h"
#include "ecc.h"

bool     binary_temp[572];
char     temp_hex_x[160], temp_hex_y[160];

const char* Hex = "0123456789abcdef"; //for processing string


char * my_alloc(int size)
{
    char  * ptr;

    ptr = (char *)malloc(size);
    if(ptr == NULL)
    {
        printf("malloc() %d failed!\n", size);
        while(1);
    }
    memset((char *)ptr, 0, size);
    //printf("malloc() %d OK.\n", size);
    return ptr;
}


void dump_ecc_reg(char *str, uint32_t *regs, int count)
{
    int  i;
    printf("%s => ", str);
    for(i = 0; i < count; i++)
        printf("0x%08x ", regs[i]);
    printf("\n");
}


void dump_hex_buff(uint32_t addr, uint32_t *wbuff, int word_cnt)
{
    int  i, j;

    for(i = 0; i < word_cnt; i += 8)
    {
        printf("0x%04x:  ", addr + i * 4);
        for(j = 0; j < 8; j++)
            printf("%08x ", wbuff[i + j]);
        printf("\n");
    }
    printf("\n");
}


void Hex2Reg(char *input, uint32_t *reg)
{
    int       i, si;
    uint32_t  val32;

    si = strlen(input) - 1;
    while(si >= 0)
    {
        val32 = 0;
        for(i = 0; (i < 8) && (si >= 0); i++)
        {
            if(input[si] <= '9')
                val32 |= (input[si] - '0') << (i * 4);
            else if((input[si] <= 'z') && (input[si] >= 'a'))
                val32 |= (input[si] - 'a' + 10) << (i * 4);
            else
                val32 |= (input[si] - 'A' + 10) << (i * 4);
            si--;
        }
        *reg++ = val32;
    }
}

void Reg2Hex(int count, uint32_t *reg, char *output)
{
    int  idx, i, ri, n;

    output[count] = 0;
    idx = count - 1;

    for(ri = 0; ; ri++)
    {
        for(i = 0; i <= 28; i += 4)
        {
            n = (reg[ri] >> i) & 0xf;

            if(n >= 10)
                output[idx] = n + 'a' - 10;
            else
                output[idx] = n + '0';

            idx --;

            if(idx < 0)
                return;
        }
    }
}


void Hex2Binary(const char * input1, bool *output)
{
    int  i, j, n, slen;

    slen = strlen(input1);

    if(slen * 4 > pCurve2->key_len + 4)
    {
        printf("Hex2Binary overflow!!  %d > %d\n", slen * 4, pCurve2->key_len);
    }

    memset(output, 0, pCurve2->Echar * 4 + 1);

    for(i = slen - 1; i >= 0; i--)  //  from lowest weight to the highest weight
    {
        if(input1[i] <= '9')
            n = input1[i] - '0';
        else if(input1[i] >= 'a')
            n = input1[i] - 'a' + 10;
        else
            n = input1[i] - 'A' + 10;

        for(j = 0; j < 4; j++)
            output[(slen - 1 - i) * 4 + j] = (n >> j) & 0x1;
    }
}


//----------------------------------------------------------------------------
//function: change a decimal(i.e.,data) into the binary form
//input: char* input
//       int length
//output: array
//----------------------------------------------------------------------------
void Decimal2Binary(int length, const char * input1, bool*output)
{
    static char PP[256];
    int     i, p, remainder, total;
    bool    run = 1;
    bool    *binary;
    bool    *temp;

    memset(PP, 0, sizeof(PP));

    binary = my_alloc(pCurve2->key_len * 2);
    temp = my_alloc(pCurve2->key_len + 4);

    memset(binary, 0, pCurve2->key_len + 4);

    // char to int
    for(i = length - 1; i >= 0; i--) //from lowest weight to the highest weight
    {
        PP[i] = input1[i] - '0';
    }

    // Decimal to binary
    p = 0;
    while(run)
    {
        // div 2
        remainder = 0;
        for(i = 0; i < length; i++)
        {
            total = remainder * 10 + PP[i];
            remainder = total % 2;
            PP[i] = (int)((double)total / 2.0);
        }
        binary[p] = remainder;
        p++;
        run = 0;

        for(i = 0; i < length; i++)
        {
            if(PP[i] != 0)
            {
                run = 1;
                break;
            }
        }
        if(!run)
            break;
    }
    //printf("p: %d\n", p);

    for(i = 0; i < pCurve2->key_len + 1; i++)
        output[i] = binary[i];

    free(temp);
    free(binary);
    return;
}


void int2array(int data, bool*output)
{
    int  i;

    for(i = 0; i < 8; i++, data >>= 1)
    {
        if(data & 0x1)
            output[i] = 1;
        else
            output[i] = 0;
    }
}



//===========================================================================functions
//-----------------------------------------------------------------------------
//function : show the binary form of array "input1"
//input: length = the length of input1
//       input1 = the neme of array
//output: void
//-----------------------------------------------------------------------------
void show_array(int length, bool*input1)
{
    int i;

    length = (length + 3) & ~0x3;

    // normal binary print
    //for (i = 0; i < length; i++)
    //  printf("%d", (int)input1[i]);
    //printf("\n");

    // inverse binary print
    //for (i = 0; i < length; i++)
    //  printf("%d", (int)input1[length-1 -i]);
    //printf("\n");

    //printf("show_array=");
    for(i = 0; i < length; i += 4)
        printf("%x", ((input1[length - 1 - i]) << 3) | ((input1[length - 1 - i - 1]) << 2) | ((input1[length - 1 - i - 2]) << 1) | (input1[length - 1 - i - 3]));
    printf("\n");
}


//----------------------------------------------------------------------------
//function : check if the value of input1 is equal to zero (length = key_length)
//input: length = the length of input1
//       input1 = the first input data
//output: true: input1=0
//----------------------------------------------------------------------------
bool poly_equal_zero(int length, bool*input1)
{
    int   i;

    for(i = 0; i < length; i++)
    {
        if(input1[i] == 1)
            return 0;
    }
    return 1;
}


//----------------------------------------------------------------------------
//function : check if polynomial input1 is equal to inputs
//input: length = the length of input1
//       input1 = the first input data
//       input2 = the second input data
//output: true: input1=1
//----------------------------------------------------------------------------
bool poly_equals(int length, bool*input1, bool*input2)
{
    int   i;
    for(i = 0; i < length; i++)
    {
        if(input1[i] != input2[i])
            return 0;
    }
    return 1;
}

//----------------------------------------------------------------------------
//function : check if the value of input1 is equal to one (length = key_length)
//input: length = the length of input1
//       input1 = the first input data
//output: true: input1=1
//----------------------------------------------------------------------------
bool poly_equal_one(int length, bool*input1)
{
    int  i;

    if(input1[0] == 0)
        return 0;

    for(i = 1; i < length; i++)
    {
        if(input1[i] == 1)
            return 0;
    }
    return 1;
}

//-----------------------------------------------------------------------------
//function : find the leading one location of input1
//input: length = the length of input1
//       input1 = the neme of array
//output: the leading one location
//-----------------------------------------------------------------------------
int Leading_one(int length, bool*input1)
{
    int   i;
    for(i = length - 1; i >= 0; i--)
        if(input1[i] == 1)
            return i;
    printf("Leading_one error!\n");
    return 0;
}


//-----------------------------------------------------------------------------
//function : randomly generate the value of some elements in an array
//input: length = the length of an array
//output: output array
//-----------------------------------------------------------------------------
void random_generate(int length, bool*output)
{
    int    i;

    for(i = 0; i < length; i++)
        output[i] = rand() % 2;

    while(poly_equal_zero(length, output))  //if zero
    {
        for(i = 0; i < length; i++)
            output[i] = rand() % 2;
    }
}




