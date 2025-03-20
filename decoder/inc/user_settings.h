/*
 * user_settings.h
 */

 #ifndef __USER_SETTINGS_H__
 #define __USER_SETTINGS_H__

 #define NO_WOLFSSL_DIR
 #define WOLFSSL_AES_DIRECT
 #define SINGLE_THREADED
 #define HAVE_PK_CALLBACKS
 #define WOLFSSL_USER_IO
 #define NO_WRITEV
 #define TIME_T_NOT_64BIT

 #define WOLFSSL_USER_SETTINGS
 #define NO_FILESYSTEM
 #define WOLFCRYPT_ONLY
 #define NO_CRYPT_TEST
 #define NO_CRYPT_BENCHMARK
 #define USE_FAST_MATH
 #define TFM_TIMING_RESISTANT
 #define ECC_TIMING_RESISTANT
 #define WC_RSA_BLINDING
 
 /* AES Settings */
 #define WOLFSSL_AES_SMALL_TABLES
 #define WOLFSSL_AES_COUNTER
 
 #endif /* __USER_SETTINGS_H__ */