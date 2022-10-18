#ifndef __ECC_H__
#define __ECC_H__


#define USE_DMA


#define bool    char

enum {
		CURVE_GF_P,
		CURVE_GF_2M,
};

/*-----------------------------------------------------*/
/*  Define elliptic curve (EC):                        */
/*-----------------------------------------------------*/

typedef struct e_curve_t2
{
		char  name[8];
		int   Echar;
		char  Ea[144];
		char  Eb[144];
		char  Px[144];
		char  Py[144];
		int   Epl;
		char  Pp[176];
		int   Eol;
		char  Eorder[176];
		int   key_len;
		int   irreducible_k1;
		int   irreducible_k2;
		int   irreducible_k3;
		int   GF;
}  ECC_CURVE2;


//For sha1
#define NMAX 			128    // 1000020

#define ECCOP_POINT_MUL		(0x0 << CRPT_ECC_CTL_ECCOP_Pos)
#define ECCOP_MODULE		(0x1 << CRPT_ECC_CTL_ECCOP_Pos)
#define ECCOP_POINT_ADD		(0x2 << CRPT_ECC_CTL_ECCOP_Pos)
#define ECCOP_POINT_DOUBLE	(0x0 << CRPT_ECC_CTL_ECCOP_Pos)

#define MODOP_DIV			(0x0 << CRPT_ECC_CTL_MODOP_Pos)
#define MODOP_MUL			(0x1 << CRPT_ECC_CTL_MODOP_Pos)
#define MODOP_ADD			(0x2 << CRPT_ECC_CTL_MODOP_Pos)
#define MODOP_SUB			(0x3 << CRPT_ECC_CTL_MODOP_Pos)


extern volatile CRPT_T  *crpt,*crpt2;

extern volatile int g_ECC_done, g_ECCERR_done;
extern const ECC_CURVE2  _Curve2[];
extern ECC_CURVE2  *pCurve2;
extern char       temp_hex_x[160], temp_hex_y[160];
extern bool       binary_temp[572];

extern bool* EC_Ea_binary;		//for a of EC
extern bool* EC_Eb_binary;		//for b of EC 
extern bool* EC_Ep_binary;		//for prime of EC in prime field
extern bool* EC_Ei_binary;		//for irreducible polynomial in binary field
extern bool* EC_Eo_binary;		//for order of EC 
extern bool* EC_Px_binary;		//for x of point(x,y)
extern bool* EC_Py_binary;		//for y of poiny(x,y) 

extern uint32_t  get_cur_ticks(void);

extern int  ecc_init_curve2(char *curve);
extern ECC_CURVE2 * get_curve2(char *curve_name);
extern char * my_alloc(int size);
extern void dump_ecc_reg(char *str, uint32_t *regs, int count);
extern int  key_pair_test(void);
extern int  sig_gen_test(void);

extern void Hex2Reg(char *input, uint32_t *reg);
extern void Reg2Hex(int count, uint32_t *reg, char *output);

extern void Hex2Binary(const char * input1, bool *output);
extern void Decimal2Binary(int length, const char * input1, bool*output);
//extern void int2array(int data, bool*output);//trandfer integer data to binary format
extern void show_array(int length, bool*input1);
//extern bool poly_equal_zero(int length, bool*input1);
//extern bool poly_equals(int length, bool*input1, bool*input2);
//extern bool poly_equal_one(int length, bool*input1);
//extern int Leading_one(int length, bool*input1);
extern void random_generate(int length, bool*output);
extern void dump_hex_buff(uint32_t addr, uint32_t *wbuff, int word_cnt);


#endif  // __ECC_H__

