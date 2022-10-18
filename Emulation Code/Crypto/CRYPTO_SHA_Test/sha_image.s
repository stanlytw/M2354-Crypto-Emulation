;/*---------------------------------------------------------------------------------------------------------*/
;/*                                                                                                         */
;/* Copyright(c) 2010 Nuvoton Technology Corp. All rights reserved.                                         */
;/*                                                                                                         */
;/*---------------------------------------------------------------------------------------------------------*/


    AREA _image, DATA, READONLY

    EXPORT  VectorDataBase
    EXPORT  VectorDataLimit

    ALIGN   4
        
VectorDataBase

 IF :DEF:SHA1_TEST
	INCBIN .\SHA\SHA1LongMsg.rsp
 ENDIF
     IF :DEF: SHA1_TEST_SHORT
   INCBIN .\SHA\SHA1ShortMsg.rsp
       ENDIF

 IF :DEF:SHA224_TEST_SHORT
   INCBIN .\SHA\SHA224ShortMsg.rsp
 ENDIF
 IF :DEF: SHA224_TEST
   INCBIN .\SHA\SHA224LongMsg.rsp
 ENDIF
    
 IF :DEF: SHA256_TEST_SHORT
   INCBIN .\SHA\SHA256ShortMsg.rsp
 ENDIF
 IF :DEF: SHA256_TEST
   INCBIN .\SHA\SHA256LongMsg.rsp
 ENDIF
 IF :DEF: SHA384_TEST_SHORT
 	INCBIN .\SHA\SHA384ShortMsg.rsp
 ENDIF

 IF :DEF:SHA384_TEST1
   INCBIN .\SHA\SHA384LongMsg_1.rsp
 ENDIF
 IF :DEF:SHA384_TEST2
   INCBIN .\SHA\SHA384LongMsg_2.rsp
 ENDIF
 IF :DEF:SHA384_TEST3
 	INCBIN .\SHA\SHA384LongMsg_3.rsp
 ENDIF
 IF :DEF:SHA384_TEST4
	INCBIN .\SHA\SHA384LongMsg_4.rsp
 ENDIF

;    INCBIN .\SHA\SHA512ShortMsg.rsp
 IF :DEF:SHA512_TEST1
   INCBIN .\SHA\SHA512LongMsg_1.rsp
 ENDIF      
 IF :DEF:SHA512_TEST2
    INCBIN .\SHA\SHA512LongMsg_2.rsp
 ENDIF
 IF :DEF:SHA512_TEST3
 	INCBIN .\SHA\SHA512LongMsg_3.rsp
 ENDIF
 IF :DEF:SHA512_TEST4
	INCBIN .\SHA\SHA512LongMsg_4.rsp
 ENDIF

VectorDataLimit

    END