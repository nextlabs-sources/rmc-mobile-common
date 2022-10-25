#ifndef __NXL_NXLUTIL_H__
#define __NXL_NXLUTIL_H__

#include "nxlfmt.h"
#include "nxlobj.h"

#define BUILDINSECTIONINFO          ".FileInfo"
#define BUILDINSECTIONPOLICY        ".FilePolicy"
#define BUILDINSECTIONTAG           ".FileTag"


#define FILETYPEKEY                 "fileExtension"
#define FILENAMEKEY                 "fileName"
#define FILEMODIFIEDBYKEY           "modifiedBy"
#define FILEMODIFIEDDATEKEY         "dateModified"
#define FILECREATEDBYKEY            "createdBy"
#define FILECREATEDDATEKEY          "dateCreated"

namespace nxl {

    namespace util {
        /**
         * check if the given file is NXL file
         * @param path
         * @return
         */
        bool checkNXL(const char *path) throw();

        /**
         * check if the given file's first bytes match the signature header of NXL
         * @param path
         * @return
         */
        bool simplecheck(const char *path) throw();

        bool simplecheck(const char *buf, int bufLen) throw();

        /**
         * convert an existing normal file to NXL file
         * @param owner_id
         * @param source
         * @param target
         * @param crypto_token
         * @param recovery_token
         * @param overwrite
         */
        void convert(const char *owner_id, const char *source, const char *target,
                     const NXL_CRYPTO_TOKEN *crypto_token, const void *recovery_token,
                     bool overwrite);

        /**
         * convert an existing normal file to NXL file(Include modified info)
         * @param owner_id
         * @param modifiedBy
         * @param modifiedDate
         * @param createdDate
         * @param source
         * @param target
         * @param crypto_token
         * @param recovery_token
         * @param overwrite
         */
        void convert(const char *owner_id, const char *modifiedBy, const long long modifiedDate,
                     const long long createdDate, const char *source, const char *target,
                     const NXL_CRYPTO_TOKEN *crypto_token, const void *recovery_token,
                     bool overwrite);

        /**
         * decrypt an existing NXL file
         * @param source
         * @param target
         * @param crypto_token
         * @param overwrite
         */
        void decrypt(const char *source, const char *target, const NXL_CRYPTO_TOKEN *crypto_token,
                     bool overwrite);

        void write_section_in_nxl(const char *path, const char *section_name, const char *data,
                                  const int datalen, const uint32_t flag,
                                  const NXL_CRYPTO_TOKEN *crypto_token);

        void read_section_in_nxl(const char *path, const char *section_name,
                                 char *data, int *datalen,
                                 int *flag, const NXL_CRYPTO_TOKEN *crypto_token);

        void read_section_in_nxl(const char *path, const char *section_name,
                                 char *data, int *datalen, int *flag);

        /**
         * Get DUID in nxl file
         * @param path
         * @param token
         */
        void read_token_info_from_nxl(const char *path, NXL_CRYPTO_TOKEN *token);

        void read_ownerid_from_nxl(const char *path, char *data, int *datalen);

        /**
         * Calculate HMAC
         * @param src
         * @param len
         * @param hex_token
         * @param hash
         * @param hashlen
         */
        void hmac_sha256(const char *src, int len, const char *hex_token, char *hash, int *hashlen);
		
#ifdef ANDROID_ENV_FIPS_MODE
        uint64_t open(const char *source, const NXL_CRYPTO_TOKEN *crypto_token);

        uint32_t read(uint64_t ptr, uint64_t offset, char *buf, uint32_t buflen);

        void close(uint64_t ptr);
#endif

        /**
         * Get content length of NXL file.
         * @param path
         * @return
         */
        uint64_t get_content_length(const char *path);

        void update_token(const char *source, const NXL_CRYPTO_TOKEN *original_crypto_token,
                          const char *ownerId, const NXL_CRYPTO_TOKEN *update_crypto_token);
    }   // namespace util

}   // namespace nxl


#endif  // #ifndef __NXL_NXLUTIL_H__
