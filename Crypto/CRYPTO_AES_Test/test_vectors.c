/*---------------------------------------------------------------------------------------------------------*/
/*                                                                                                         */
/* Copyright(c) 2015 Nuvoton Technology Corp. All rights reserved.                                         */
/*                                                                                                         */
/*---------------------------------------------------------------------------------------------------------*/


#define AES_128_ECB     ((AES_MODE_ECB << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_128 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_128_CBC     ((AES_MODE_CBC << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_128 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_128_CFB     ((AES_MODE_CFB << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_128 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_128_OFB     ((AES_MODE_OFB << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_128 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_192_ECB     ((AES_MODE_ECB << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_192 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_192_CBC     ((AES_MODE_CBC << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_192 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_192_CFB     ((AES_MODE_CFB << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_192 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_192_OFB     ((AES_MODE_OFB << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_192 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_256_ECB     ((AES_MODE_ECB << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_256 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_256_CBC     ((AES_MODE_CBC << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_256 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_256_CFB     ((AES_MODE_CFB << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_256 << CRPT_AES_CTL_KEYSZ_Pos))
#define AES_256_OFB     ((AES_MODE_OFB << CRPT_AES_CTL_OPMODE_Pos) | (AES_KEY_SIZE_256 << CRPT_AES_CTL_KEYSZ_Pos))


static const KAT_T  g_test_vector[] =
{
    {
        AES_128_CBC, 16,
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "0336763e966d92595a567cc9ce537f5e",
    },
    {
        AES_128_CBC, 16,
        "10a58869d74be5a374cf867cfb473859",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "6d251e6944b051e04eaa6fb4dbf78465"
    },
    {
        AES_128_CBC, 16,
        "80000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0edd33d3c621e546455bd8ba1418bec8",
    },
    {
        AES_128_CBC, 16,
        "ff800000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "42ffb34c743de4d88ca38011c990890b"
    },
    {
        AES_128_CBC, 16,
        "ffff8000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "c6a0b3e998d05068a5399778405200b4"
    },
    {
        AES_128_CBC, 16,
        "ffffffff800000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "ed62e16363638360fdd6ad62112794f0"
    },
    {
        AES_128_CBC, 16,
        "fffffffffffffffffffffffffffffffe",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "9ba4a9143f4e5d4048521c4f8877d88e"
    },
    {
        AES_128_CBC, 16,
        "ffffffffffffffffffffffffffffffff",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "a1f6258c877d5fcd8964484538bfc92c"
    },
    {
        AES_128_CBC, 16,
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
        "3ad78e726c1ec02b7ebfe92b23d9ec34"
    },
    {
        AES_128_CBC, 16,
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "ffc00000000000000000000000000000",
        "77e2b508db7fd89234caf7939ee5621a"
    },
    {
        AES_128_CBC, 16,
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffe0",
        "8568261797de176bf0b43becc6285afb"
    },
    {
        AES_128_CBC, 16,
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffffff0",
        "f9b0fda0c4a898f5b9e6f661c4ce4d07"
    },
    {
        AES_128_CFB, 16,
        "00000000000000000000000000000000",
        "cb9fceec81286ca3e989bd979b0cb284",
        "00",
        "92"
    },
    {
        AES_128_CFB, 16,
        "10a58869d74be5a374cf867cfb473859",
        "00000000000000000000000000000000",
        "00",
        "6d"
    },
    {
        AES_128_ECB, 16,
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "0336763e966d92595a567cc9ce537f5e"
    },
    {
        AES_128_ECB, 16,
        "10a58869d74be5a374cf867cfb473859",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "6d251e6944b051e04eaa6fb4dbf78465"
    },
    {
        AES_128_OFB, 16,
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "00000000000000000000000000000000",
        "0336763e966d92595a567cc9ce537f5e"
    },
    {
        AES_192_CBC, 24,
        "000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "275cfc0413d8ccb70513c3859b1d0f72"
    },
    {
        AES_192_CBC, 24,
        "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0956259c9cd5cfd0181cca53380cde06"
    },
    {
        AES_192_CBC, 24,
        "800000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "de885dc87f5a92594082d02cc1e1b42c"
    },
    {
        AES_192_CBC, 24,
        "ff8000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "eba83ff200cff9318a92f8691a06b09f"
    },
    {
        AES_192_CBC, 24,
        "fffffffff800000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "cc4ba8a8e029f8b26d8afff9df133bb6"
    },
    {
        AES_192_CBC, 24,
        "fffffffffffffffffffffffffffffffffffffffffffffffe",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "018596e15e78e2c064159defce5f3085"
    },
    {
        AES_192_CBC, 24,
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "dd8a493514231cbf56eccee4c40889fb"
    },
    {
        AES_192_CBC, 24,
        "000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
        "6cd02513e8d4dc986b4afe087a60bd0c"
    },
    {
        AES_192_CBC, 24,
        "000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffe",
        "cef41d16d266bdfe46938ad7884cc0cf"
    },
    {
        AES_192_CBC, 24,
        "000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "b13db4da1f718bc6904797c82bcf2d32"
    },
    {
        AES_192_CFB, 24,
        "000000000000000000000000000000000000000000000000",
        "9c2d8842e5f48f57648205d39a239af1",
        "00",
        "c9"
    },
    {
        AES_192_CFB, 24,
        "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd",
        "00000000000000000000000000000000",
        "00",
        "09"
    },
    {
        AES_192_ECB, 24,
        "000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "275cfc0413d8ccb70513c3859b1d0f72"
    },
    {
        AES_192_ECB, 24,
        "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0956259c9cd5cfd0181cca53380cde06"
    },
    {
        AES_192_OFB, 24,
        "000000000000000000000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "00000000000000000000000000000000",
        "275cfc0413d8ccb70513c3859b1d0f72"
    },
    {
        AES_256_CBC, 32,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "761c1fe41a18acf20d241650611d90f1",
        "623a52fcea5d443e48d9181ab32c7421"
    },
    {
        AES_256_CBC, 32,
        "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "46f2fb342d6f0ab477476fc501242c5f"
    },
    {
        AES_256_CBC, 32,
        "8000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "e35a6dcb19b201a01ebcfa8aa22b5759"
    },
    {
        AES_256_CBC, 32,
        "ffff800000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "610b71dfc688e150d8152c5b35ebc14d"
    },
    {
        AES_256_CBC, 32,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "cf78618f74f6f3696e0a4779b90b5a77"
    },
    {
        AES_256_CBC, 32,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "b07d4f3e2cd2ef2eb545980754dfea0f"
    },
    {
        AES_256_CBC, 32,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "4bf85f1b5d54adbc307b0a048389adcb"
    },
    {
        AES_256_CBC, 32,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
        "ddc6bf790c15760d8d9aeb6f9a75fd4e"
    },
    {
        AES_256_CBC, 32,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffe",
        "7bfe9d876c6d63c1d035da8fe21c409d"
    },
    {
        AES_256_CBC, 32,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "acdace8078a32b1a182bfa4987ca1347"
    },
    {
        AES_256_CFB, 32,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "00",
        "5c"
    },
    {
        AES_256_CFB, 32,
        "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
        "00000000000000000000000000000000",
        "00",
        "46"
    },
    {
        AES_256_ECB, 32,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "5c9d844ed46f9885085e5d6a4f94c7d7"
    },
    {
        AES_256_ECB, 32,
        "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "46f2fb342d6f0ab477476fc501242c5f"
    },
    {
        AES_256_CFB, 32,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "00000000000000000000000000000000",
        "5c9d844ed46f9885085e5d6a4f94c7d7"
    },
};



