#ifndef __NXL_FORMAT_H__
#define __NXL_FORMAT_H__

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

#define NXL_SIGNATURE_HIGH      '\0@TM'                 /* NXL Signatrue (HighPart) */
#define NXL_SIGNATURE_LOW       'FLXN'                  /* NXL Signatrue (LowPart) */
#define NXL_VERSION_10          0x00010000              /* NXL Format Version 1.0 */
#define NXL_VERSION_30          0x00030000              /* NXL Format Version 3.0 */

#define NXL_PAGE_SIZE           0x1000                  /* NXL Format Page Size */
#define NXL_CBC_SIZE            0x200                   /* NXL Format CBC Size */
#define NXL_MIN_SIZE			0x4000                  /* NXL Format Minimum File Size */



#define NXL_FLAGS_NONE          0x00000000              /* NXL Format File Flag: None */
#define NXL_CRYPTO_FLAGS_NONE   0x00000000              /* NXL Format Crypto Flag: None */

#define NXL_DEFAULT_MSG         "Protected by RMC IOS"  /* NXL Format default message */




enum _NXLALGORITHM {
    NXL_ALGORITHM_NONE      = 0,    /* No algorithm (No encrypted) */
    NXL_ALGORITHM_AES128    = 1,    /* AES 128 bits */
    NXL_ALGORITHM_AES256    = 2,    /* AES 256 bits (Default content encryption algorithm) */
    NXL_ALGORITHM_RSA1024   = 3,    /* RSA 1024 bits */
    NXL_ALGORITHM_RSA2048   = 4,    /* RSA 2048 bits */
    NXL_ALGORITHM_SHA1      = 5,    /* SHA1 (Default hash algorithm) */
    NXL_ALGORITHM_SHA256    = 6,    /* SHA256 */
    NXL_ALGORITHM_MD5       = 7     /* MD5 */
};

typedef enum _NXLALGORITHM  NXLALGORITHM;   
#define  NXL_ALGORITHM      NXLALGORITHM    
  




union _SIGNATURE_CODE {
    struct {
        uint32_t LowPart;      
        uint32_t HighPart;    
    };
    struct {
        uint32_t LowPart;      
        uint32_t HighPart;     
    } u;
    uint64_t QuadPart;      
};
typedef union _SIGNATURE_CODE   SIGNATURE_CODE; 



struct _NXL_SIGNATURE {
    SIGNATURE_CODE		Code;
    uint32_t            Version;
    uint16_t			Message[122];
};
typedef struct _NXL_SIGNATURE   NXL_SIGNATURE;      
typedef struct _NXL_SIGNATURE*  PNXL_SIGNATURE;     
typedef const NXL_SIGNATURE*    PCNXL_SIGNATURE;    



struct _NXL_BASIC_INFORMATION {
    unsigned char   UDID[16];           /* Thumbprint, which is unique for each NXL file */
    uint32_t   Flags;					/* NXL file flags */
    uint32_t   Alignment;				/* NXL file alignment (should be NXL_PAGE_SIZE) */
    uint32_t   Algorithm;               /* The algorithm to encrypt content */
    uint32_t   CipherBlockSize;         /* The cypher block size, default is 512 bytes */
    uint32_t   ContentOffset;           /* The offset to content */
    unsigned char OwnerId[256];         /* Owner's member id(UTF-8 string) */
    uint32_t   ExtendedDataOffset;      /* The offset of extended data */
};
typedef struct _NXL_BASIC_INFORMATION   NXL_BASIC_INFORMATION;      
typedef struct _NXL_BASIC_INFORMATION*  PNXL_BASIC_INFORMATION;     
typedef const NXL_BASIC_INFORMATION*    PCNXL_BASIC_INFORMATION;    

struct _NXL_CRYPTO_TOKEN{
    unsigned char PublicKey[256];
    unsigned char PublicKeyWithiCA[256];
    uint32_t      ml;           /* token's maintenance level */
    unsigned char otp[32];
    unsigned char UDID[32];     /* UDID, unique document id HEX string */
    unsigned char Token[64];    /* token, used to encrypt cek or decrypt cek HEX string*/
};
typedef struct _NXL_CRYPTO_TOKEN NXL_CRYPTO_TOKEN;
    
struct _NXL_SECTION_RECORD{
    unsigned char   Name[16];
    uint32_t        Flags;
    uint32_t        StartOffset;
    uint32_t        SectionSize;
    uint16_t        OriginalDataSize;
    uint16_t        CompressedDataSize;
    unsigned char   Checksum[32];   /* Section data checksum: HMAC_SHA256(DataLength, Data)  */
};
typedef _NXL_SECTION_RECORD NXL_SECTION_RECORD;
    
struct _NXL_SECTION_HEADER{
    uint32_t                Map;               /* A bits map indicating which sections are valid */
    NXL_SECTION_RECORD      records[32];
};
typedef _NXL_SECTION_HEADER NXL_SECTION_HEADER;
    
struct _NXL_RESERVED_DATA{
    unsigned char data[784];
};
typedef _NXL_RESERVED_DATA NXL_RESERVED_DATA;
    
struct _NXL_DYNAMIC_HEADER{
    unsigned char   HeaderHash[32];           /* Hash of fixed header (File/Key/Section/Extended) HMAC_SHA256(Token, Header) */
    uint64_t        ContentLength;              /* Length of content */
    
};
typedef _NXL_DYNAMIC_HEADER NXL_DYNAMIC_HEADER;
 

struct _NXL_CRYPTO_INFORMATION {
    uint32_t        Flags;          /* Highest Byte: protect mode (client token mode 0x01, server token mode 0x02, split tokent mode 0x03), Lower 3 bytes: Flags* KF_RECOVERTY_KEY_ENABLED 0x00000001 */
    unsigned char   IVSeed[16];
    unsigned char   TPCEK[64];      /* token protected cek. 0 - 31 bytes: CEK encrypted by token. 32 - 63 bytes: HMAC_SHA256(Token, CEK) */
    unsigned char   RPPCEK[64];     /* Recovery password protected cek. 0 - 31 bytes: cek encrypted by recovery password. 32 - 63 bytes: HMAC_SHA256(Recovery password, cek) */
    unsigned char   PublicKey1[256]; /* The public key between member and Root CA */
    unsigned char   PublicKey2[256]; /* The public key between member and iCA */
    uint32_t        TokenLevel;     /* Token's maintenance level */
    uint32_t        ExtendedDataOffset; /* The offset of extended data */
    
};
typedef struct _NXL_CRYPTO_INFORMATION   NXL_CRYPTO_INFORMATION;      
typedef struct _NXL_CRYPTO_INFORMATION*  PNXL_CRYPTO_INFORMATION;     
typedef const NXL_CRYPTO_INFORMATION*    PCNXL_CRYPTO_INFORMATION;    





/**
 * \struct _NXL_HEADER
 * Whole NXL Header Struct (W/O Section Data).
 * Size is 2048 bytes.
 */
struct _NXL_HEADER {
    NXL_SIGNATURE           Signature;      /* Signature Header */
    NXL_BASIC_INFORMATION   Basic;          /* Basic Header */
    NXL_CRYPTO_INFORMATION  Crypto;         /* Crypto Header */
    NXL_SECTION_HEADER      SectionHeader;
    NXL_RESERVED_DATA       ReservedData;
    NXL_DYNAMIC_HEADER      DynamicHeader;
};
typedef struct _NXL_HEADER   NXL_HEADER;      
typedef struct _NXL_HEADER*  PNXL_HEADER;     
typedef const NXL_HEADER*    PCNXL_HEADER;    


#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field)    ((intptr_t )(intptr_t*)&(((type *)0)->field))
#endif


#define NXL_BASICINFO_OFFSET    ((uint32_t)FIELD_OFFSET(NXL_HEADER, Basic))        /**< Offset to BasicInformation Header */
#define NXL_CRYPTOINFO_OFFSET   ((uint32_t)FIELD_OFFSET(NXL_HEADER, Crypto))       /**< Offset to CryptoInformation Header */
#define NXL_SCNINFO_OFFSET      ((uint32_t)FIELD_OFFSET(NXL_HEADER, Sections))     /**< Offset to Section Table Header */
#define NXL_SCNDATA_OFFSET      ((uint32_t)(sizeof(NXL_HEADER)))                   /**< Offset to beginning of Section Data */



static_assert(0x100 == sizeof(NXL_SIGNATURE), "incorrect NXL_SIGNATURE size");
static_assert(0x128 == sizeof(NXL_BASIC_INFORMATION), "incorrect NXL_BASIC_INFORMATION size");
static_assert(0x29C == sizeof(NXL_CRYPTO_INFORMATION), "incorrect NXL_CRYPTO_INFORMATION size");
static_assert(0x40 == sizeof(NXL_SECTION_RECORD), "incorrect NXL_SECTION_RECORD size");
static_assert(0x804 == sizeof(NXL_SECTION_HEADER), "incorrect NXL_SECTION_HEADER size");
static_assert(0x28 == sizeof(NXL_DYNAMIC_HEADER), "incorrect NXL_DYNAMIC_HEADER size");
//static_assert(0x90 == NXL_BASICINFO_OFFSET, "incorrect NXL_BASICINFO_OFFSET");
//static_assert(0xB0 == NXL_CRYPTOINFO_OFFSET, "incorrect NXL_CRYPTOINFO_OFFSET");
//static_assert(0x368 == NXL_SCNINFO_OFFSET, "incorrect NXL_SCNINFO_OFFSET");
static_assert(0x1000 == NXL_SCNDATA_OFFSET, "incorrect size");

#ifdef __cplusplus
}
#endif



#endif
