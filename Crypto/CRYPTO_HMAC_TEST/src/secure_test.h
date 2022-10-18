#ifndef _SECURE_TEST_H_
#define _SECURE_TEST_H_

#include "nuc970_reg.h"

//#define sysprintf(...)


/*================================================*/
/*                                                */
/*  Exported variables and functions              */
/*                                                */
/*================================================*/
extern int  g_do_encrypt;
extern uint8_t	g_key[];	
extern uint8_t	g_iv[64];	
extern uint8_t	g_cipher_text[];	
extern uint8_t	g_plain_text[];	
extern int  g_key_len;
extern int  g_plain_text_len;

extern int  open_test_file(char *filename);
extern int  close_test_file(void);
extern int  get_next_pattern(void);



#endif	// _SECURE_TEST_H_

