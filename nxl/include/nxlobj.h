#ifndef __NXL_NXLOBJ_H__
#define __NXL_NXLOBJ_H__

#include "nxlfmt.h"
#include <string>
#include <cstring>  // want to use memset memcpy ...
#include <fstream>
#include <vector>
#include <utility>

namespace nxl{

	class FmtHeader
	{
	public:
		FmtHeader():bcekey_(false){
			memset(&header_, 0, sizeof(NXL_HEADER));
			memset(&cekey_, 0, sizeof(cekey_));
		}
	public:
		static void valid_signature(const char* path);
        static void valid_signature(const char* buf, int bufLen);
		static void valid_format(const char* path);

		inline const NXL_HEADER* header() const throw() { return &header_; }
		inline unsigned long size() const throw() { return sizeof(header_); }
		inline void clear() {
			memset(&header_, 0, sizeof(header_));
			memset(&cekey_, 0, sizeof(cekey_));
			bcekey_ = false;
		}
		inline void set(const NXL_HEADER* header) { memcpy(&header_, header, sizeof(header_)); }
        void create(const unsigned char* owner_id, const NXL_CRYPTO_TOKEN* crypto_token, const void* recovery_token);
		void update_token(const unsigned char* owner_id, const NXL_CRYPTO_TOKEN* crypto_token);
		void decrypt_cekey(const NXL_CRYPTO_TOKEN* crypto_token);
		void validate();

	public: //  Get NXL Header Information

		// SIGNATURE INFORMATION
		inline uint64_t get_sig_code() const throw() { return header_.Signature.Code.QuadPart; }
		inline std::u16string get_sig_message() const throw() { return std::u16string((char16_t*)header_.Signature.Message); }
        inline uint32_t get_sig_version() const throw() { return header_.Signature.Version; }

		// BASIC INFORMATION
		inline const unsigned char* get_bsc_duid() const throw() { return header_.Basic.UDID; }
		inline unsigned long get_bsc_duid_size() const throw() { return sizeof(header_.Basic.UDID); }
		inline unsigned long get_bsc_flags() const throw() { return header_.Basic.Flags; }
		inline unsigned long get_bsc_alignment() const throw() { return header_.Basic.Alignment; }
		inline unsigned long get_bsc_ptofcontent() const throw() { return header_.Basic.ContentOffset; }
        inline const unsigned char* get_bsc_ownerid() const throw() { return header_.Basic.OwnerId; }
        inline unsigned long get_bsc_ownerid_size() const throw() { return sizeof(header_.Basic.OwnerId);}


        // crypto section
        inline const unsigned char* get_crypto_ivseed() const { return header_.Crypto.IVSeed; }
        inline uint32_t get_crypto_ivseed_size() const { return sizeof(header_.Crypto.IVSeed); }
        inline uint32_t get_crypto_publickey1_size() const { return sizeof(header_.Crypto.PublicKey1); }
        inline const unsigned char* get_crypto_publickey1() const { return header_.Crypto.PublicKey1; }

        inline uint32_t get_crypto_publickey2_size() const { return sizeof(header_.Crypto.PublicKey2); }
        inline const unsigned char* get_crypto_publickey2() const { return header_.Crypto.PublicKey2; }
        inline uint32_t get_crypto_ml() const { return header_.Crypto.TokenLevel; }



        // SECTION INFORMATION

        inline unsigned long get_scns_count() const throw() { return sizeof(header_.SectionHeader.records) / sizeof(NXL_SECTION_RECORD); }

        int get_scn_index(const char* name) const throw();

	public:	//  Set NXL Header Information



		// CRYPTO INFORMATION
		inline void set_crt_contentsize(uint64_t size);
        inline uint64_t get_crt_contentsize() const throw() { return header_.DynamicHeader.ContentLength; }

        inline const unsigned char* get_cekey() const { return bcekey_ ? cekey_ : NULL; }

		// SECTION INFORMATION
		void update_section(int index, const char* data, uint16_t datalen, uint16_t original_len, uint16_t compressed_len, uint32_t flag, const NXL_CRYPTO_TOKEN* cryptotoken);

        void validate_nxl_header(const NXL_CRYPTO_TOKEN* cryptotoken);
    private:
		void create_cekey();

        void update_header_hash(const NXL_CRYPTO_TOKEN* cryptotoken);
	private:
		NXL_HEADER      header_;
		unsigned char   cekey_[32];
		bool            bcekey_;
	};


	class FileStream
	{
	public:
		enum Purpose{
			kEncrypt,
			kDecrypt,
			kSectionOperations,
			kGetInfo
		};
	public:
		FileStream(){}
		virtual ~FileStream() {}

	public:
		void open(const char* path, Purpose purpose);
		inline bool is_open() { return fs_.is_open(); }
		inline void close() { fs_.close(); }

		// encryption
		void prepare_for_encrypt(const unsigned char* owner_id, const NXL_CRYPTO_TOKEN* crypto_token, const void* recovery_token);
		void encrypt(const char* sourcepath);

		// decryption
		void prepare_for_decrypt(const NXL_CRYPTO_TOKEN* crypto_token);
		void decrypt(const char* outputpath);
		
#ifdef ANDROID_ENV_FIPS_MODE
		uint32_t read(uint64_t offset, char *buf, uint32_t buflen);
		uint32_t write(uint64_t offset, const char *buf, uint32_t buflen, uint32_t bytesValid);
#endif

		void update_token(const unsigned char* owner_id, const NXL_CRYPTO_TOKEN* token);

        void read_section( const char* name, void* pb, uint32_t* pcb,  uint32_t* flag, bool validate, const NXL_CRYPTO_TOKEN* cryptotoken);
        void read_section( const char* name, void* pb, uint32_t* pcb,  uint32_t* flag, bool validate);
        void write_section( const char* name, const void* pb,  uint32_t cb, uint32_t flag, const NXL_CRYPTO_TOKEN* cryptotoken);


        void read_token(const char* name, NXL_CRYPTO_TOKEN* token);
        void read_ownerid(const char* name, void* pb, uint32_t* pcb, bool validate, const NXL_CRYPTO_TOKEN* cryptotoken);

        uint64_t getContentLength();
	private:
        void gen_ivec(uint64_t offset, unsigned char* ivec);

		void aes_cbc_operator(bool encrypt,  char* buf, int buflen, uint64_t offset);

		// write nxl header to disk
		void save_header();
	private:
		FmtHeader		header_;
		std::fstream		fs_;
		std::string			path_;
		Purpose				purpose_;
	};


    void hmac_sha256_token(const char* token, int tokenlen, const char* content, int contentlen, char* hash);

} //namespace nxl



#endif //__NXL_NXLOBJ_H__
