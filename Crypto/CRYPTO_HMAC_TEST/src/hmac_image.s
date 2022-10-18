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
    INCBIN .\HMAC_fips198a.rsp
;    INCBIN .\HMAC_NIST_p1.rsp
;    INCBIN .\HMAC_NIST_p2.rsp
;    INCBIN .\HMAC_NIST_p3.rsp
VectorDataLimit

    END