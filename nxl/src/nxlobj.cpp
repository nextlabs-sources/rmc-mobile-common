#include "nxlbasic.hpp"
#include "nxlobj.h"

#include <cctype>

#include "utils.h"

#ifdef IOS_ENV
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

#elif  (defined(ANDROID_ENV_FIPS_MODE))

#include "openssl/aes.h"
#include "openssl/evp.h"
#include "aes.h"
#include "sha.h"
#include "boost/cstdint.hpp"

#else

extern "C" {
#include "rijndael-alg-fst.h"
}
#include "cryptlite/hmac.h"
#include "cryptlite/sha256.h"
#endif

namespace {
    int char2int(char input) {
        if (input >= '0' && input <= '9')
            return input - '0';
        if (input >= 'A' && input <= 'F')
            return input - 'A' + 10;
        if (input >= 'a' && input <= 'f')
            return input - 'a' + 10;
        return -1;
    }

    // This function assumes src to be a zero terminated sanitized string with
    // an even number of [0-9a-f] characters, and target to be sufficiently large
    void hex2bin(const char *src, int srclen, char *target) {
        int i = 0;
        while (*src && src[1] && i < srclen) {
            *(target++) = char2int(*src) * 16 + char2int(src[1]);
            src += 2;
            i += 2;
        }
    }

#ifdef IOS_ENV

    void aes_encrypt_cbc(const char *key, int keylen, char *data, int datalen, const unsigned char *ivec,
                         int iveclen) {
        if (iveclen != 16) {
            return;
        }
        // check nxl CBC block equals how much AES256 block
        int numBlocks = datalen / 16; // a blocks equals 128bits, 16Byte
        const unsigned char *piv = ivec;
        size_t bufferSize = datalen + kCCBlockSizeAES128;
        void *buffer = malloc(bufferSize);
        size_t numBytesEnecrypted = 0;

        for (int i = numBlocks; i > 0; --i) {
            CCCrypt(kCCEncrypt, kCCAlgorithmAES128,
                    kCCOptionPKCS7Padding,
                    key, kCCKeySizeAES256,
                    piv,
                    data, 16, /* input */
                    buffer, bufferSize, /* output */
                    &numBytesEnecrypted);
            memcpy(data, buffer, 16);
            data += 16;
            piv = (unsigned char *) buffer;
        }
    }


    void aes_decrypt_cbc(const char *key, int keylen, char *data, int datalen, const unsigned char *ivec,
                         int iveclen) {
        if (iveclen != 16) {
            return;
        }
        int keyBits = keylen * 8;
        int numBlocks = datalen / 16; // a blocks equals 128bits, 16Byte
        unsigned char IV[16] = {0}; /* initialize vector for aes cbc mode*/
        // sanity check
        if ((keyBits != 128) && (keyBits != 192) && (keyBits != 256)) {
            throw new NXEXCEPTION("incorrect length of AES key");
        }
        // prepare
        memcpy(IV, ivec, sizeof(IV));
        size_t bufferSize = datalen + kCCBlockSizeAES128;
        void *buffer = malloc(bufferSize);
        for (int i = numBlocks; i > 0; i--) {
            size_t numBytesDecrypted = 0;
            CCCrypt(kCCDecrypt, kCCAlgorithmAES128, 0,
                    key, kCCKeySizeAES256,
                    IV /* initialization vector (optional) */,
                    data, 16, /* input */
                    buffer, bufferSize, /* output */
                    &numBytesDecrypted);
            memcpy(IV, data, 16);
            memcpy(data, buffer, 16);
            data += 16;
        }
    }

#elif (defined(ANDROID_ENV_FIPS_MODE))

    void aes_encrypt_cbc(const char *key, unsigned int keylen, char *data, unsigned int datalen,
                         boost::uint8_t *ivec,
                         int iveclen) {
        boost::uint32_t returnedLen;
        AesEncrypt(key, keylen, data, datalen, ivec, 0, NXL_CBC_SIZE, data, datalen, &returnedLen);
    }

    void aes_encrypt_cbc(const char *key, uint32_t keylen,
                         const void *indata, uint32_t indatalen,
                         const uint8_t *ivec, uint64_t offset, uint32_t blocksize,
                         void *outdata, uint32_t outdatalen, uint32_t *returnedlen) {
        AesEncrypt(key, keylen, indata, indatalen, ivec, offset, blocksize, outdata, outdatalen,
                   returnedlen);
    }

    void aes_decrypt_cbc(const char *key, unsigned int keylen, char *data, unsigned int datalen,
                         boost::uint8_t *ivec,
                         int iveclen) {
        boost::uint32_t returnedLen;
        AesDecrypt(key, keylen, data, datalen, ivec, 0, NXL_CBC_SIZE, data, datalen, &returnedLen);
    }

    void aes_decrypt_cbc(const char *key, uint32_t keylen,
                         void *indata, uint32_t indatalen,
                         const uint8_t *ivec, uint64_t offset, uint32_t blocksize,
                         char *outdata, uint32_t outdatalen, uint32_t *returnedlen) {
        AesDecrypt(key, keylen, indata, indatalen, ivec, offset, blocksize, outdata, outdatalen,
                   returnedlen);
    }

#else

    void aes_encrypt_cbc(const char* key, int keylen, char* data, int datalen, const u8* ivec, int iveclen) {

        if (iveclen != 16) {
            return;
        }

        int keyBits = keylen * 8;
        int numBlocks = datalen / 16; // a blocks equals 128bits, 16Byte

        int Nr = 0; /* key-length-dependent number of rounds */
        u32 rk[4 * (MAXNR + 1)]; /* key schedule */



        // sanity check
        if ((keyBits != 128) && (keyBits != 192) && (keyBits != 256)) {
            throw new NXEXCEPTION("incorrect length of AES key");
        }
        // config AES key
        Nr = rijndaelKeySetupEnc(rk, (const u8*) key, keyBits);
        // prepare
        u8 outBuffer[16] = {0};
        u8 block[16] = {0};
        const u8* piv = ivec;
        // encrypt with CBC mode
        for (int i = numBlocks; i > 0; --i) {
            //standard duty of CBC mode
            ((u32*) block)[0] = ((u32*) data)[0] ^ ((u32*) piv)[0];
            ((u32*) block)[1] = ((u32*) data)[1] ^ ((u32*) piv)[1];
            ((u32*) block)[2] = ((u32*) data)[2] ^ ((u32*) piv)[2];
            ((u32*) block)[3] = ((u32*) data)[3] ^ ((u32*) piv)[3];
            // API
            rijndaelEncrypt(rk, Nr, (const u8*) block, outBuffer);
            memcpy(data, outBuffer, 16);
            // amend params
            piv = outBuffer;
            data += 16;
        }
    }

    void aes_decrypt_cbc(const char* key, int keylen, char* data, int datalen, const u8* ivec, int iveclen) {
        if (iveclen != 16) {
            return;
        }

        int keyBits = keylen * 8;
        int numBlocks = datalen / 16; // a blocks equals 128bits, 16Byte

        int Nr = 0; /* key-length-dependent number of rounds */
        u32 rk[4 * (MAXNR + 1)]; /* key schedule */
        u8 IV[16] = {0}; /* initialize vector for aes cbc mode*/
        // sanity check
        if ((keyBits != 128) && (keyBits != 192) && (keyBits != 256)) {
            throw new NXEXCEPTION("incorrect length of AES key");
        }
        // config AES key
        Nr = rijndaelKeySetupDec(rk, (const u8*) key, keyBits);
        // prepare
        memcpy(IV, ivec, sizeof (IV));

        u8 block[16] = {0};
        u8* piv = IV;

        for (int i = numBlocks; i > 0; i--) {
            rijndaelDecrypt(rk, Nr, (const u8*) data, block);
            ((u32*) block)[0] ^= ((u32*) piv)[0];
            ((u32*) block)[1] ^= ((u32*) piv)[1];
            ((u32*) block)[2] ^= ((u32*) piv)[2];
            ((u32*) block)[3] ^= ((u32*) piv)[3];
            memcpy(IV, data, 16);
            memcpy(data, block, 16);
            data += 16;
        }
    }
#endif

/*
    inline bool icasecmp(const std::u16string& s1, const std::u16string & s2) {
        if (s1.size() != s2.size())
            return false;
        for (std::u16string::const_iterator c1 = s1.begin(), c2 = s2.begin();
                c1 != s1.end();
                ++c1, ++c2) {
            if (tolower(*c1) != tolower(*c2))
                return false;
        }
        return true;
    }*/

    inline bool icasecmp(const std::string &s1, const std::string &s2) {
        if (s1.size() != s2.size())
            return false;
        for (std::string::const_iterator c1 = s1.begin(), c2 = s2.begin();
             c1 != s1.end();
             ++c1, ++c2) {
            if (tolower(*c1) != tolower(*c2))
                return false;
        }
        return true;
    }


}

#ifdef IOS_ENV

void nxl::hmac_sha256_token(const char *token, int tokenlen, const char *content, int contentlen,
                            char *hash) {
    char *key = new char[tokenlen / 2];
    hex2bin(token, tokenlen, key);
    //
    //    // combined data
    char *combined = new char[4 + contentlen];
    memcpy(combined, &contentlen, 4);
    memcpy(combined + 4, content, contentlen);
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key, tokenlen / 2, combined, contentlen + 4, cHMAC);
    delete[]key;
    delete[]combined;
    memcpy(hash, cHMAC, CC_SHA256_DIGEST_LENGTH);
}

#elif(defined(ANDROID_ENV_FIPS_MODE))

void nxl::hmac_sha256_token(const char *token, int tokenlen, const char *content, int contentlen,
                            char *hash) {
    uint8_t digest[32];

    char *key = new char[tokenlen / 2];
    hex2bin(token, tokenlen, key);

    // combined data
    char *combined = new char[4 + contentlen];
    memcpy(combined, &contentlen, 4);
    memcpy(combined + 4, content, contentlen);

    CreateSha256Hmac(combined, contentlen + 4, key, tokenlen / 2, digest);

    delete[]key;
    delete[]combined;

    memcpy(hash, digest, 32);
}

#else
void nxl::hmac_sha256_token(const char* token, int tokenlen, const char* content, int contentlen, char* hash)
{
    boost::uint8_t digest[32];

    char* key = new char[tokenlen / 2];
    hex2bin(token, tokenlen, key);

    // combined data
    char *combined = new char[4 + contentlen];
    memcpy(combined, &contentlen, 4);
    memcpy(combined + 4, content, contentlen);
    cryptlite::hmac<cryptlite::sha256>::calc(combined, contentlen + 4, key, tokenlen / 2, digest);

    delete []key;
    delete []combined;

    memcpy(hash, digest, 32);
}
#endif

//*********************************************************
//*
//* class FmtHeader
//*
//*********************************************************

void nxl::FmtHeader::valid_signature(const char *path) {
    static const SIGNATURE_CODE desired_sig = {NXL_SIGNATURE_LOW, NXL_SIGNATURE_HIGH};

    std::ifstream ifs(path, std::ifstream::in | std::ifstream::binary);
    if (!ifs.is_open()) {
        throw NXEXCEPTION("file can not be open");
    }
    NXL_HEADER header = {0};

    ifs.read((char *) &header, sizeof(NXL_HEADER));
    if (sizeof(NXL_HEADER) != ifs.gcount()) {
        throw NXEXCEPTION("mismatch expected size of reading");
    }

    FmtHeader fmtHeader;
    fmtHeader.set(&header);

    if (desired_sig.QuadPart != fmtHeader.get_sig_code()) {
        throw NXEXCEPTION("mismatch signature code ");
    }
}

void nxl::FmtHeader::valid_signature(const char *buf, int bufLen) {
    static const SIGNATURE_CODE desired_sig = {NXL_SIGNATURE_LOW, NXL_SIGNATURE_HIGH};

    if (sizeof(NXL_HEADER) != bufLen) {
        throw NXEXCEPTION("mismatch expected size of reading");
    }

    FmtHeader fmtHeader;
    fmtHeader.set((const NXL_HEADER *) buf);

    if (desired_sig.QuadPart != fmtHeader.get_sig_code()) {
        throw NXEXCEPTION("mismatch signature code ");
    }
}

void nxl::FmtHeader::valid_format(const char *path) {
    std::ifstream ifs(path, std::ifstream::in | std::ifstream::binary);
    if (!ifs.is_open()) {
        throw NXEXCEPTION("file can not be open");
    }
    NXL_HEADER header = {0};

    ifs.read((char *) &header, sizeof(NXL_HEADER));
    if (sizeof(NXL_HEADER) != ifs.gcount()) {
        throw NXEXCEPTION("mismatch expected size of reading");
    }

    FmtHeader fmtHeader;
    fmtHeader.set(&header);

    fmtHeader.validate();
}

void nxl::FmtHeader::validate() {
    static const SIGNATURE_CODE DesiredCode = {NXL_SIGNATURE_LOW, NXL_SIGNATURE_HIGH};

    // check signature
    if (DesiredCode.QuadPart != get_sig_code()) {
        throw NXEXCEPTION(" invalid signature");
    }

    // check version
    if (get_sig_version() < NXL_VERSION_30) {
        throw NXEXCEPTION(" This version nxl was not supported!");
    }

    // check alignment
    if (NXL_PAGE_SIZE != get_bsc_alignment()) {
        throw NXEXCEPTION(" invalid alignment");

    }

    // check data offset
    if (get_bsc_ptofcontent() < NXL_MIN_SIZE) {
        throw NXEXCEPTION(" invalid content offset");
    }

    // Check Algorithm
    if (NXL_ALGORITHM_AES128 != header_.Basic.Algorithm &&
        NXL_ALGORITHM_AES256 != header_.Basic.Algorithm) {
        throw NXEXCEPTION(" invalid encrypt algorithm");
    }


}

void nxl::FmtHeader::create(const unsigned char *owner_id, const NXL_CRYPTO_TOKEN *crypto_token,
                            const void *recovery_token) {
    // sanity check
    if (!owner_id || strlen((char *) owner_id) > 255) {
        throw NXEXCEPTION("owner id is null or too long (length can't exceed 255)");
    }

    if (NULL == crypto_token) {
        throw NXEXCEPTION("crypto token is null");
    }


    clear();

    create_cekey();  // create a random key to encrypt file content.


    // signature
    header_.Signature.Code.HighPart = NXL_SIGNATURE_HIGH;
    header_.Signature.Code.LowPart = NXL_SIGNATURE_LOW;

    header_.Signature.Version = NXL_VERSION_30;

//    const char *pMsg = NXL_DEFAULT_MSG;
//    for (int i = 0; i < strlen(NXL_DEFAULT_MSG); i++) {
//        header_.Signature.Message[i] = pMsg[i];
//    }
// If you add this message, after encryption, Apple Files can not get the complete file information, so Files will be stuck.(bug 61398)
    // FILE HEADER
    char udid[16] = {0};
    hex2bin((char *) crypto_token->UDID, sizeof(crypto_token->UDID), udid);
    memcpy(header_.Basic.UDID, udid, sizeof(header_.Basic.UDID));

    header_.Basic.Flags = 0;
    header_.Basic.Alignment = NXL_PAGE_SIZE;
    header_.Basic.Algorithm = NXL_ALGORITHM_AES256;
    header_.Basic.CipherBlockSize = NXL_CBC_SIZE;
    header_.Basic.ContentOffset = NXL_MIN_SIZE;
    memcpy(header_.Basic.OwnerId, owner_id, strlen((char *) owner_id));

    // crypto
    header_.Crypto.Flags = 0x02000000;

    // create random IVseed
    srand((unsigned int) time(NULL));
    int times = sizeof(header_.Crypto.IVSeed) / sizeof(int);
    for (int i = 0; i < times; i++) {
        int rd = rand();
        memcpy(header_.Crypto.IVSeed + i * sizeof(rd), &rd, sizeof(rd));
    }


    // encrypt CEK
    unsigned char cek[32] = {0};
    memcpy(cek, cekey_, sizeof(cek));
    // convert hex strint token to bin
    char kek[32] = {0};
    hex2bin((char *) crypto_token->Token, sizeof(crypto_token->Token), kek);
    // use token in cyrpto_token to encrypt cek.

    aes_encrypt_cbc(kek, 32, (char *) cek, 32, header_.Crypto.IVSeed,
                    sizeof(header_.Crypto.IVSeed));
    memcpy(header_.Crypto.TPCEK, cek, 32);

    // do hmac_sha256
    char hashcek[32] = {0};
    hmac_sha256_token((char *) crypto_token->Token, sizeof(crypto_token->Token), (char *) cekey_,
                      sizeof(cekey_), hashcek);
    memcpy(header_.Crypto.TPCEK + 32, hashcek, sizeof(hashcek));

    // store Public key between member and Root CA
    memcpy(header_.Crypto.PublicKey1, crypto_token->PublicKey, sizeof(crypto_token->PublicKey));

    // store public key between member and iCA
    memcpy(header_.Crypto.PublicKey2, crypto_token->PublicKeyWithiCA,
           sizeof(crypto_token->PublicKeyWithiCA));

    header_.Crypto.TokenLevel = crypto_token->ml;

    // section header

    // checksum for empty section
    char hashEmptySection[32] = {0};
    hmac_sha256_token((char *) crypto_token->Token, sizeof(crypto_token->Token), nullptr, 0,
                      hashEmptySection);

    // .FileInfo section record
    memcpy(header_.SectionHeader.records[0].Name, BUILDINSECTIONINFO, strlen(BUILDINSECTIONINFO));
    header_.SectionHeader.records[0].Flags = 0;
    header_.SectionHeader.records[0].StartOffset = 0x1000;
    header_.SectionHeader.records[0].SectionSize = 0x1000;
    header_.SectionHeader.records[0].OriginalDataSize = 0;
    header_.SectionHeader.records[0].CompressedDataSize = 0;
    memcpy(header_.SectionHeader.records[0].Checksum, hashEmptySection, sizeof(hashEmptySection));

    // .Policy
    memcpy(header_.SectionHeader.records[1].Name, BUILDINSECTIONPOLICY,
           strlen(BUILDINSECTIONPOLICY));
    header_.SectionHeader.records[1].Flags = 0;
    header_.SectionHeader.records[1].StartOffset = 0x2000;
    header_.SectionHeader.records[1].SectionSize = 0x1000;
    header_.SectionHeader.records[2].OriginalDataSize = 0;
    header_.SectionHeader.records[2].CompressedDataSize = 0;
    memcpy(header_.SectionHeader.records[1].Checksum, hashEmptySection, sizeof(hashEmptySection));

    // .FileTag
    memcpy(header_.SectionHeader.records[2].Name, BUILDINSECTIONTAG, strlen(BUILDINSECTIONTAG));
    header_.SectionHeader.records[2].Flags = 0;
    header_.SectionHeader.records[2].StartOffset = 0x3000;
    header_.SectionHeader.records[2].SectionSize = 0x1000;
    header_.SectionHeader.records[2].OriginalDataSize = 0;
    header_.SectionHeader.records[2].CompressedDataSize = 0;
    memcpy(header_.SectionHeader.records[2].Checksum, hashEmptySection, sizeof(hashEmptySection));

    // turn on indication in map for sections
    uint32_t mask = 1 << 0 | 1 << 1 | 1 << 2;
    header_.SectionHeader.Map = mask;

    // dynamic header
    update_header_hash(crypto_token);
    header_.DynamicHeader.ContentLength = 0;  // will fill after encryt content.


}

void nxl::FmtHeader::update_header_hash(const NXL_CRYPTO_TOKEN *cryptotoken) {
    char hashheader[32] = {0};
    char *pstart = (char *) &(header_.Signature);
    long len = (char *) &(header_.DynamicHeader) - pstart;
    hmac_sha256_token((char *) cryptotoken->Token, sizeof(cryptotoken->Token), pstart, (int) len,
                      hashheader);
    memcpy(header_.DynamicHeader.HeaderHash, hashheader, sizeof(hashheader));
}

void nxl::FmtHeader::create_cekey() {
    uint64_t *p = (uint64_t *) cekey_;
    for (size_t i = 0; i < 4; i++) {
        p[i] = rand64();
    }
    bcekey_ = true;
}

void nxl::FmtHeader::validate_nxl_header(const NXL_CRYPTO_TOKEN *cryptotoken) {
    // calulate checksum
    char hashheader[32] = {0};
    char *pstart = (char *) &(header_.Signature);
    long len = (char *) &(header_.DynamicHeader) - pstart;
    hmac_sha256_token((char *) cryptotoken->Token, sizeof(cryptotoken->Token), pstart, (int) len,
                      hashheader);

    // compare with dynamic header
    if (memcmp(header_.DynamicHeader.HeaderHash, hashheader, sizeof(hashheader)) != 0) {
        throw NXEXCEPTION("Didn't pass header hash check");
    }

}

void nxl::FmtHeader::update_token(const unsigned char *owner_id,
                                  const NXL_CRYPTO_TOKEN *crypto_token) {
    // sanity check
    if (!owner_id || strlen((char *) owner_id) > 255) {
        throw NXEXCEPTION("Owner id is null or too long (length can't exceed 255).");
    }

    if (!crypto_token) {
        throw NXEXCEPTION("Crypto token is null.");
    }
    //Update owner id.
    memset(header_.Basic.OwnerId, 0, 256);
    memcpy(header_.Basic.OwnerId, owner_id, strlen((char *) owner_id));

    //Update duid.
    char udid[16] = {0};
    hex2bin((char *) crypto_token->UDID, sizeof(crypto_token->UDID), udid);
    memset(header_.Basic.UDID, 0, 16);
    memcpy(header_.Basic.UDID, udid, sizeof(header_.Basic.UDID));

    // Update CEK cipher.
    unsigned char cek[32] = {0};
    memcpy(cek, cekey_, sizeof(cek));
    char kek[32] = {0};
    hex2bin((char *) crypto_token->Token, sizeof(crypto_token->Token), kek);
    aes_encrypt_cbc(kek, 32, (char *) cek, 32, header_.Crypto.IVSeed,
                    sizeof(header_.Crypto.IVSeed));
    memset(header_.Crypto.TPCEK, 0, 32);
    memcpy(header_.Crypto.TPCEK, cek, 32);

    // Update checksum of CEK.
    char hashcek[32] = {0};
    hmac_sha256_token((char *) crypto_token->Token, sizeof(crypto_token->Token), (char *) cekey_,
                      sizeof(cekey_), hashcek);
    memset(header_.Crypto.TPCEK + 32, 0, 32);
    memcpy(header_.Crypto.TPCEK + 32, hashcek, sizeof(hashcek));

    // Update Public key between member and Root CA
    memset(header_.Crypto.PublicKey1, 0, 256);
    memcpy(header_.Crypto.PublicKey1, crypto_token->PublicKey, sizeof(crypto_token->PublicKey));

    // Update public key between member and iCA
    memset(header_.Crypto.PublicKey2, 0, 256);
    memcpy(header_.Crypto.PublicKey2, crypto_token->PublicKeyWithiCA,
           sizeof(crypto_token->PublicKeyWithiCA));

    header_.Crypto.TokenLevel = crypto_token->ml;
}

void nxl::FmtHeader::decrypt_cekey(const NXL_CRYPTO_TOKEN *crypto_token) {
    validate_nxl_header(crypto_token);

    if (bcekey_) {
        return; // avoid duplicate decryption
    }

    char cek[32] = {0};
    memcpy(cek, header_.Crypto.TPCEK, 32);  // get CEK from header, this was encrypted by token.

    // get binary from token hex string
    char kek[32] = {0};
    hex2bin((char *) crypto_token->Token, sizeof(crypto_token->Token), kek);

    // decrypt CEK
    aes_decrypt_cbc(kek, 32, cek, 32, header_.Crypto.IVSeed, sizeof(header_.Crypto.IVSeed));


    // calculate checksum with CEK (after decrypted CEK)
    char hash[32] = {0};
    hmac_sha256_token((char *) crypto_token->Token, sizeof(crypto_token->Token), cek, 32, hash);

    // get checksum from nxl header
    char hmac[32] = {0};
    memcpy(hmac, header_.Crypto.TPCEK + 32, 32);

    // compare if CEK was correct?
    if (memcmp(hmac, hash, 32) != 0) {
        throw NXEXCEPTION("check TP CEK failed");
    }

    // set ceky
    memcpy(cekey_, cek, 32);
    bcekey_ = true;

}

int nxl::FmtHeader::get_scn_index(const char *name) const throw() {
    for (int i = 0; i < (int) get_scns_count(); ++i) {
        if (icasecmp(std::string(name),
                     std::string((char *) header_.SectionHeader.records[i].Name))) {

            return i;
        }
    }

    return -1;
}

void nxl::FmtHeader::set_crt_contentsize(uint64_t size) {
    header_.DynamicHeader.ContentLength = size;
}

void nxl::FmtHeader::update_section(int index, const char *data, uint16_t datalen,
                                    uint16_t original_len,
                                    uint16_t compressed_len, uint32_t flag,
                                    const NXL_CRYPTO_TOKEN *cryptotoken) {
    if (index < 0 ||
        index >= (sizeof(header_.SectionHeader.records) / sizeof(NXL_SECTION_RECORD))) {
        return;
    }


    // calculate hash for section
    char hash[32] = {0};
    hmac_sha256_token((char *) cryptotoken->Token, sizeof(cryptotoken->Token), data, datalen, hash);
    memcpy(header_.SectionHeader.records[index].Checksum, hash, sizeof(hash));

    // update data size
    header_.SectionHeader.records[index].OriginalDataSize = original_len;
    header_.SectionHeader.records[index].CompressedDataSize = compressed_len;
    header_.SectionHeader.records[index].Flags = flag;


    // since we changed section, then have to update header hash
    update_header_hash(cryptotoken);
}

//*********************************************************
//*
//* class FileStream
//*
//*********************************************************

void nxl::FileStream::open(const char *path, Purpose purpose) {

    if (NULL == path) {
        throw NXEXCEPTION("path is null");
    }
    path_ = path;
    purpose_ = purpose;

    //for encrypt
    if (purpose_ == kEncrypt) {

        fs_.open(path, std::fstream::out | std::fstream::binary | std::fstream::trunc);

        if (!fs_.is_open()) {
            throw NXEXCEPTION("can not open file");
        }
        // header will be initialized by providing kekey
        return;
    }

    //for decrypt
    if (purpose_ == kDecrypt) {
        fs_.open(path, std::fstream::in | std::fstream::out | std::fstream::binary);

        if (!fs_.is_open()) {
            throw NXEXCEPTION("can not open file");
        }

        // for decrypt, it must make sure that source file is a legal nxl file
        // if yes use the header to build nxlfileobj
        // check if a legal nxl
        uint64_t fsize = getfilesize(path);
        if (-1 == fsize) {
            throw NXEXCEPTION("error to get file size");
        }

        if (fsize < NXL_MIN_SIZE) {
            throw NXEXCEPTION("invalid nxl file size");
        }

        NXL_HEADER header = {0};
        fs_.seekg(0).read((char *) &header, sizeof(header));

        if (!fs_) {
            throw NXEXCEPTION("ifs is broken");
        }

        header_.set(&header);


        header_.validate();

        return;
    }

    if (purpose_ == kSectionOperations) {
        fs_.open(path, std::fstream::in | std::fstream::out | std::fstream::binary);

        if (!fs_.is_open()) {
            throw NXEXCEPTION("can not open file");
        }

        uint64_t fsize = getfilesize(path);
        if (-1 == fsize) {
            throw NXEXCEPTION("error to get file size");
        }

        if (fsize < NXL_MIN_SIZE) {
            throw NXEXCEPTION("invalid nxl file size");
        }

        NXL_HEADER header = {0};
        fs_.seekg(0).read((char *) &header, sizeof(header));

        if (!fs_) {
            throw NXEXCEPTION("ifs is broken");
        }

        header_.set(&header);


        header_.validate();

        return;

    }

    if (purpose_ == kGetInfo) {
        fs_.open(path, std::fstream::in | std::fstream::binary);

        if (!fs_.is_open()) {
            throw NXEXCEPTION("can not open file");
        }


        uint64_t fsize = getfilesize(path);
        if (-1 == fsize) {
            throw NXEXCEPTION("error to get file size");
        }

        if (fsize < NXL_MIN_SIZE) {
            throw NXEXCEPTION("invalid nxl file size < NXL_MIN_SIZE");
        }

        NXL_HEADER header = {0};
        fs_.seekg(0).read((char *) &header, sizeof(header));

        if (!fs_) {
            throw NXEXCEPTION("ifs is broken");
        }

        header_.set(&header);


        header_.validate();

        return;
    }

    throw NXEXCEPTION("should never reach here");
}

void nxl::FileStream::prepare_for_decrypt(const NXL_CRYPTO_TOKEN *crypto_token) {
    header_.decrypt_cekey(crypto_token);
}

void nxl::FileStream::prepare_for_encrypt(const unsigned char *owner_id,
                                          const NXL_CRYPTO_TOKEN *crypto_token,
                                          const void *recovery_token) {
    if (!is_open()) {
        throw NXEXCEPTION("file is not opened");
    }
    header_.create(owner_id, crypto_token, recovery_token);

    fs_.seekp(0);
    fs_.write((const char *) (header_.header()), header_.size());
    if (!fs_.good()) {
        throw NXEXCEPTION("failed:write header to file");
    }
}

void nxl::FileStream::encrypt(const char *sourcepath) {
    // open source file
    std::ifstream ifs(sourcepath, std::fstream::in | std::fstream::binary);


    // sanity check
    if (!ifs.is_open()) {
        throw NXEXCEPTION("source file can not open");
    }

    // get file size
    uint64_t srcfilesize = getfilesize(sourcepath);


    char *buf = NULL;
    uint32_t datacb = 0; // actually retrived count

    buf = new(std::nothrow) char[NXL_PAGE_SIZE];
    if (NULL == buf) {
        throw NXEXCEPTION("fail to allocate buf to store data from source file");
    }


    // move file pointer
    fs_.seekp(header_.get_bsc_ptofcontent(), std::fstream::beg);
    // encrypt
    try {
        if (srcfilesize == 0) {
            memset(buf, 0, NXL_PAGE_SIZE);
            aes_cbc_operator(true, buf, NXL_PAGE_SIZE, 0);
            fs_.write(buf, NXL_PAGE_SIZE);
        } else {
            uint64_t index = 0;
            do {
                memset(buf, 0, NXL_PAGE_SIZE);
                ifs.read((char *) buf, NXL_PAGE_SIZE);
                datacb = (uint32_t) ifs.gcount();
                if (0 == datacb) {
                    // reach file end
                    break;
                }

                aes_cbc_operator(true, buf, NXL_PAGE_SIZE, index * NXL_PAGE_SIZE);
                fs_.write(buf, NXL_PAGE_SIZE);

                ++index;
            } while (ifs.good());
        }
        // modify header
        header_.set_crt_contentsize(srcfilesize);
        // write header
        save_header();
    } catch (...) {
        // cleanup
        delete[]buf;
        buf = NULL;
        ifs.close();

    }

    // cleanup
    delete[]buf;
    buf = NULL;
    ifs.close();
}

void nxl::FileStream::decrypt(const char *outputpath) {

    std::ofstream ofs(outputpath, std::fstream::out | std::fstream::binary | std::fstream::trunc);

    if (!ofs.is_open()) {
        throw NXEXCEPTION("outputpath file can not open");
    }

    char *buf = NULL;
    uint32_t datacb = 0; // actually retrived count

    buf = new(std::nothrow) char[NXL_PAGE_SIZE];
    if (NULL == buf) {
        throw NXEXCEPTION("fail to allocate buf to store data from source file");
    }

    // move file pointer to content point
    fs_.seekg(header_.get_bsc_ptofcontent(), std::fstream::beg);
    try {
        uint64_t fsize = header_.get_crt_contentsize();
        uint64_t had_write = 0;
        do {
            // prepare block
            memset(buf, 0, NXL_PAGE_SIZE);
            fs_.read(buf, NXL_PAGE_SIZE);
            datacb = (uint32_t) fs_.gcount();
            if (0 == datacb) {
                // reach file end
                break;
            }
            // decrypte
            //aes_decrypt_cbc((char*) header_.get_cekey(), 32, buf, NXL_PAGE_SIZE, ivec);
            aes_cbc_operator(false, buf, NXL_PAGE_SIZE, had_write);
            // write to disk
            if (fsize - had_write >= datacb) {
                ofs.write(buf, datacb);
            } else {
                ofs.write(buf, fsize - had_write);
            }
            // amend params
            had_write += NXL_PAGE_SIZE;
        } while (fs_.good());
    } catch (...) {
        // clean up
        delete[]buf;
        buf = NULL;
        ofs.close();
    }

    // clean up
    delete[]buf;
    buf = NULL;
    ofs.close();
}

void nxl::FileStream::update_token(const unsigned char *owner_id,
                                   const NXL_CRYPTO_TOKEN *token) {
    //Sanity check.
    if (!owner_id || !token) {
        throw NXEXCEPTION("Invalid parameter.");
    }
    if (strlen((char *) owner_id) > 255) {
        throw NXEXCEPTION("Owner id is too long (length can't exceed 255).");
    }
    if (!is_open()) {
        throw NXEXCEPTION("File is not opened.");
    }
    header_.update_token(owner_id, token);

    //Update section.
    for (int i = 0; i < header_.get_scns_count(); i++) {
        const NXL_SECTION_RECORD &section = header_.header()->SectionHeader.records[i];
        if (section.Name[0] == 0) {
            break;
        }
        uint32_t size = section.SectionSize;
        uint32_t flags = section.Flags;
        std::vector<uint8_t> data(size);

        std::fstream::pos_type newpos = section.StartOffset;
        fs_.seekg(newpos);
        if (!fs_.good()) {
            throw NXEXCEPTION("Can not move fp.");
        }
        fs_.read((char *) data.data(), size);

        //Calc checksum.
        header_.update_section(i, (const char *) data.data(), size,
                               section.OriginalDataSize, 0, flags,
                               token);
    }

    //Save header.
    save_header();
}

void nxl::FileStream::read_token(const char *name, NXL_CRYPTO_TOKEN *token) {
    if (!name || !token) {
        throw NXEXCEPTION("parameter is NULL");
    }

    token->ml = header_.get_crypto_ml();
    memcpy(token->PublicKey, header_.get_crypto_publickey1(), header_.get_crypto_publickey1_size());
    memcpy(token->UDID, header_.get_bsc_duid(), header_.get_bsc_duid_size());
}

void nxl::FileStream::read_ownerid(const char *name, void *pb, uint32_t *pcb, bool validate,
                                   const NXL_CRYPTO_TOKEN *cryptotoken) {
    if (!name || !pb || !pcb) {
        throw NXEXCEPTION("invalid parameters");
    }

    if (*pcb < header_.get_bsc_ownerid_size()) {
        throw NXEXCEPTION("buffer is too small");
    }

    if (validate && cryptotoken) {
        header_.validate_nxl_header(cryptotoken);
    }


    *pcb = (uint32_t) header_.get_bsc_ownerid_size();
    memcpy(pb, header_.get_bsc_ownerid(), *pcb);
}

void nxl::FileStream::read_section(const char *name, void *pb, uint32_t *pcb, uint32_t *flag,
                                   bool validate, const NXL_CRYPTO_TOKEN *cryptotoken) {

    header_.validate_nxl_header(
            cryptotoken);  // if nxl file was changed unexpectly, then just throw exception and stop

    int index = header_.get_scn_index(name);
    if (index == -1) {
        throw NXEXCEPTION("not find the section");
    }

    const NXL_SECTION_RECORD &section = header_.header()->SectionHeader.records[index];

    uint32_t datasize = section.OriginalDataSize;
    if (datasize == 0) {
        throw NXEXCEPTION("this section doesn't have any data");
    }

    if (NULL == pb) {
        *pcb = datasize;
        throw NXEXCEPTION("Need a buffer to retrieve data in this section");
    }


    if (*pcb < datasize) {
        *pcb = datasize;
        throw NXEXCEPTION("buffer is too small");
    }

    if (*pcb > datasize) {
        *pcb = datasize;
    }

    if (flag) {
        *flag = section.Flags;
    }


    // read
    std::fstream::pos_type oldpos = fs_.tellg();
    if (-1 == oldpos) {
        throw NXEXCEPTION("can not get fp");
    }
    std::fstream::pos_type newpos = section.StartOffset;
    fs_.seekg(newpos);
    if (!fs_.good()) {
        throw NXEXCEPTION("can not move fp");
    }

    char *buf = new char[section.SectionSize];
    fs_.read(buf, section.SectionSize);
    if (section.SectionSize != fs_.gcount()) {
        throw NXEXCEPTION("mismatch expected count");
    }

    /*   if (validate)
       {
           int padding = 0;
           if (section.Flags & 1) {  // encryption flag was set, then data length was aligned by 16.
               int mod = datasize % 16;
               padding = (mod == 0 ? 0 : (16 - mod));
           }


           // check hash
           char hash[32] = {0};

           hmac_sha256_token((char*)cryptotoken->Token, sizeof(cryptotoken->Token), buf, datasize + padding, hash);

           if (memcmp(hash, section.Checksum, sizeof(hash)) != 0) {
               throw NXEXCEPTION("this section data was broken");
           }
       }*/

    // check if need decrypt
    if (section.Flags & 1) {
        const int blocks = section.SectionSize / NXL_CBC_SIZE;
        char *tmp = buf;

        char binKey[32] = {0};
        hex2bin((char *) cryptotoken->Token, sizeof(cryptotoken->Token), binKey);

        uint64_t offset = 0;
        for (int i = 0; i < blocks; i++) {
            unsigned char ivec[16] = {0};
            gen_ivec(offset, ivec);

            aes_decrypt_cbc(binKey, 32, tmp, NXL_CBC_SIZE, ivec, sizeof(ivec));

            tmp += NXL_CBC_SIZE;
            offset += NXL_CBC_SIZE;
        }
    }

    memcpy(pb, buf, datasize);

    delete[]buf;
    buf = nullptr;

}

void nxl::FileStream::read_section(const char *name, void *pb, uint32_t *pcb, uint32_t *flag,
                                   bool validate) {
    int index = header_.get_scn_index(name);
    if (index == -1) {
        throw NXEXCEPTION("not find the section");
    }

    const NXL_SECTION_RECORD &section = header_.header()->SectionHeader.records[index];

    uint32_t datasize = section.OriginalDataSize;
    if (datasize == 0) {
        throw NXEXCEPTION("this section doesn't have any data");
    }

    if (NULL == pb) {
        *pcb = datasize;
        throw NXEXCEPTION("Need a buffer to retrieve data in this section");
    }


    if (*pcb < datasize) {
        *pcb = datasize;
        throw NXEXCEPTION("buffer is too small");
    }

    if (*pcb > datasize) {
        *pcb = datasize;
    }

    if (flag) {
        *flag = section.Flags;
    }


    // read
    std::fstream::pos_type oldpos = fs_.tellg();
    if (-1 == oldpos) {
        throw NXEXCEPTION("can not get fp");
    }
    std::fstream::pos_type newpos = section.StartOffset;
    fs_.seekg(newpos);
    if (!fs_.good()) {
        throw NXEXCEPTION("can not move fp");
    }

    char *buf = new char[section.SectionSize];
    fs_.read(buf, section.SectionSize);
    if (section.SectionSize != fs_.gcount()) {
        throw NXEXCEPTION("mismatch expected count");
    }
    memcpy(pb, buf, datasize);
    delete[]buf;
    buf = nullptr;
}

void nxl::FileStream::write_section(const char *name, const void *pb, uint32_t cb, uint32_t flag,
                                    const NXL_CRYPTO_TOKEN *cryptotoken) {
    header_.validate_nxl_header(cryptotoken);

    int index = header_.get_scn_index(name);
    if (index == -1) {
        throw NXEXCEPTION("not find the section");
    }

    const NXL_SECTION_RECORD &section = header_.header()->SectionHeader.records[index];

    uint32_t size = section.SectionSize;  // section size

    std::fstream::pos_type newpos = section.StartOffset;

    if (NULL == pb && 0 == cb) // reset this seciton
    {
        char *zerodata = NULL;

        std::fstream::pos_type oldpos = fs_.tellp();
        if (-1 == oldpos)
            throw NXEXCEPTION("can not get fp");

        fs_.seekp(newpos);
        if (!fs_.good())
            throw NXEXCEPTION("can not move fp");

        zerodata = new(std::nothrow) char[size];
        if (NULL == zerodata)
            throw NXEXCEPTION("fail to alloc temp buffer");

        memset(zerodata, 0, size);

        fs_.write(zerodata, size);
        delete[] zerodata;
        zerodata = NULL;

        if (!fs_.good()) {
            fs_.seekp(oldpos);
            throw NXEXCEPTION("fail to write zero data");
        }

        fs_.seekp(oldpos);

        // set section checksum
        header_.update_section(index, nullptr, 0, 0, 0, flag, cryptotoken);


    } else {
        if (NULL == pb)
            throw NXEXCEPTION("inavlid buf pointer");

        if (0 == cb)
            throw NXEXCEPTION("inavlid buf size");

        if (cb > size)
            throw NXEXCEPTION("buf size is too big");

        //prepare data to write
        char *data = NULL;
        data = new(std::nothrow) char[size];
        if (NULL == data)
            throw NXEXCEPTION("fail to alloc temp buffer");

        memset(data, 0, size);
        memcpy(data, pb, cb);

        // if need to do compression, compression should before encrytion, for this release, we don't support compression
        // do possible compression here...

        // check if need encryption, AES256 CBC
        int encryptionlen = cb;
        if (flag & 1) {
            const int blocks = cb / NXL_CBC_SIZE;

            // extract binary from hex string
            char binKey[32] = {0};
            hex2bin((char *) cryptotoken->Token, sizeof(cryptotoken->Token), binKey);

            char *buf = data;
            uint64_t offset = 0;
            for (int i = 0; i < blocks; i++) {
                unsigned char ivec[16] = {0};
                gen_ivec(offset, ivec);

                aes_encrypt_cbc(binKey, 32, buf, NXL_CBC_SIZE, ivec, sizeof(ivec));


                buf += NXL_CBC_SIZE;
                offset += NXL_CBC_SIZE;
            }

            encryptionlen = offset;
            // check last block
            const int lastBlockSize = cb % NXL_CBC_SIZE;
            if (lastBlockSize != 0) {  // need to handle last block, make sure round to 16 bytes.
                const int temp = lastBlockSize % 16;
                int padding = temp == 0 ? 0 : (16 - temp);

                unsigned char ivec[16] = {0};
                gen_ivec(offset, ivec);

                aes_encrypt_cbc(binKey, 32, buf, lastBlockSize + padding, ivec, sizeof(ivec));

                encryptionlen += padding;
            }
        }


        //move fp
        std::fstream::pos_type oldpos = fs_.tellp();
        if (-1 == oldpos)
            throw NXEXCEPTION("can not get fp");

        fs_.seekp(newpos);
        if (!fs_.good())
            throw NXEXCEPTION("can not move fp");


        fs_.write((char *) data, size);


        if (!fs_.good()) {
            fs_.seekp(oldpos);
            throw NXEXCEPTION("fail to write zero data");
        }

        fs_.seekp(oldpos);

        // calc checksum
        header_.update_section(index, data, encryptionlen, cb, 0, flag, cryptotoken);

        delete[]data;
        data = NULL;

    }

    save_header();
}

void nxl::FileStream::gen_ivec(uint64_t offset, unsigned char *ivec) {
    if (nullptr == ivec) {
        return;
    }

    //   offset = header_.get_bsc_ptofcontent() + offset;
    if (offset) {
        offset = (offset - 1) * 31;
    }

    memcpy(ivec, header_.get_crypto_ivseed(), header_.get_crypto_ivseed_size());
    ((uint64_t *) ivec)[0] ^= offset;
    ((uint64_t *) ivec)[1] ^= offset;
}

void nxl::FileStream::aes_cbc_operator(bool encrypt, char *buf, int buflen, uint64_t offset) {
    const int blocks = buflen / NXL_CBC_SIZE;
    uint64_t blockOffset = offset;
    for (int i = 0; i < blocks; i++) {

        unsigned char ivec[16] = {0};
        gen_ivec(blockOffset, ivec);

        if (encrypt) {
            aes_encrypt_cbc((char *) header_.get_cekey(), 32, buf, NXL_CBC_SIZE, ivec,
                            sizeof(ivec));
        } else {
            aes_decrypt_cbc((char *) header_.get_cekey(), 32, buf, NXL_CBC_SIZE, ivec,
                            sizeof(ivec));
        }

        // amend param
        buf += NXL_CBC_SIZE;
        blockOffset += NXL_CBC_SIZE;
    }
}

void nxl::FileStream::save_header() {

    std::fstream::pos_type oldpos = fs_.tellp();
    fs_.seekp(0);
    fs_.write((const char *) header_.header(), header_.size());
    fs_.seekp(oldpos);
}

#ifdef ANDROID_ENV_FIPS_MODE

uint32_t nxl::FileStream::read(uint64_t offset, char *buf, uint32_t buflen) {
    //Sanity check first.
    if (0 != (offset % NXL_CBC_SIZE)) {
        throw NXEXCEPTION("Invalid alignment.");
    }
    if (0 != (buflen % 16)) {
        throw NXEXCEPTION("Invalid alignment.");
    }
    if (offset >= header_.get_crt_contentsize()) {
        throw NXEXCEPTION("Invalid offset.");
    }
    fs_.seekg(header_.get_bsc_ptofcontent() + offset, std::fstream::beg);
    if (!fs_.good()) {
        throw NXEXCEPTION("File io error.");
    }
    //Amend buf length.
    if ((offset + buflen) > header_.get_crt_contentsize()) {
        uint32_t nblocksleft = ((header_.get_crt_contentsize() - offset - 1) / NXL_CBC_SIZE) + 1;
        if (buflen > nblocksleft * NXL_CBC_SIZE) {
            buflen = nblocksleft * NXL_CBC_SIZE;
        }
    }
    fs_.read(buf, buflen);
    if (!fs_.good()) {
        throw NXEXCEPTION("File io error.");
    }

    aes_decrypt_cbc((char *) header_.get_cekey(), 32,
                    buf, buflen,
                    header_.get_crypto_ivseed(),
                    offset, NXL_CBC_SIZE,
                    buf, buflen, &buflen);
    if ((offset + buflen) > header_.get_crt_contentsize()) {
        buflen = header_.get_crt_contentsize() - offset;
    }
    return buflen;
}

uint32_t nxl::FileStream::write(uint64_t offset, const char *buf, uint32_t buflen,
                                uint32_t bytesValid) {
    //Sanity check.
    if (0 != (offset % NXL_CBC_SIZE)) {
        throw NXEXCEPTION("Invalid alignment.");
    }
    if (0 != (buflen % NXL_CBC_SIZE)) {
        throw NXEXCEPTION("Invalid alignment.");
    }
    if (offset > header_.get_crt_contentsize()) {
        throw NXEXCEPTION("Invalid offset.");
    }
    if (bytesValid > buflen) {
        throw NXEXCEPTION("Invalid valid bytes.");
    }
    if (nullptr == buf) {
        throw NXEXCEPTION("Invalid buffer.");
    }
    fs_.seekg(header_.get_bsc_ptofcontent() + offset, std::fstream::beg);
    if (!fs_.good()) {
        throw NXEXCEPTION("File io error.");
    }
    std::vector<uint8_t> cipher(buf, buf + buflen);
    aes_encrypt_cbc((char *) header_.get_cekey(), 32,
                    cipher.data(), buflen,
                    header_.get_crypto_ivseed(),
                    offset, NXL_CBC_SIZE,
                    cipher.data(), buflen, &buflen);
    fs_.write((const char *) cipher.data(), buflen);
    if (!fs_.good()) {
        throw NXEXCEPTION("File io error.");
    }

    // modify header
    // TBD: Need to handle content size update.
    if (offset + bytesValid > header_.get_crt_contentsize()) {
        header_.set_crt_contentsize(offset + bytesValid);
        // write header
        save_header();
    }

    return buflen;
}

#endif

uint64_t nxl::FileStream::getContentLength() {
    return header_.get_crt_contentsize();
}
