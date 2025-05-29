#include "crypto_guard_ctx.h"

#include <array>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/err.h>

namespace CryptoGuard {

#define BUFFER_SIZE 4096

enum class COMMAND_TYPE {
    DECRYPT = 0,
    ENCRYPT = 1,
};

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};


class CryptoGuardCtx::Impl {
public:
    Impl();
    ~Impl();
    void Encrypt(std::istream &inStream, std::ostream &outStream, std::string_view password);
    void Decrypt(std::istream &inStream, std::ostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::istream &inStream);

private:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password, COMMAND_TYPE command);

    void AesCipher(std::istream &inStream, std::ostream &outStream, const AesCipherParams& params);

    void CheckInputStream(std::istream &inStream) const;
    void CheckOutputStream(std::ostream &outStream) const;

    std::string GetOpenSSLError() const;
};

// class CryptoGuardCtx::Impl
CryptoGuardCtx::Impl::Impl() {
    OpenSSL_add_all_algorithms();
}
CryptoGuardCtx::Impl::~Impl() {
    EVP_cleanup();
}

void CryptoGuardCtx::Impl::Encrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    CheckInputStream(inStream);
    CheckOutputStream(outStream);
    auto params = CreateChiperParamsFromPassword(password, COMMAND_TYPE::ENCRYPT);
    AesCipher(inStream, outStream, params);
}

void CryptoGuardCtx::Impl::Decrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    CheckInputStream(inStream);
    CheckOutputStream(outStream);
    auto params = CreateChiperParamsFromPassword(password, COMMAND_TYPE::DECRYPT);
    AesCipher(inStream, outStream, params);
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::istream &inStream) {
    CheckInputStream(inStream);
    auto ctx_deleter = [](EVP_MD_CTX* ctx) { EVP_MD_CTX_free(ctx); };
    std::unique_ptr<EVP_MD_CTX, decltype(ctx_deleter)> ctx(EVP_MD_CTX_new(), ctx_deleter);
    const EVP_MD* md = EVP_sha256();

    if (!ctx) {
        throw std::runtime_error{"Failed to create MD context" + GetOpenSSLError()};
    }

    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
        throw std::runtime_error{"Failed to initialize MD" + GetOpenSSLError()};
    }

    char buffer[BUFFER_SIZE];
    while (inStream.read(buffer, sizeof(buffer)) || inStream.gcount()) {
        if (EVP_DigestUpdate(ctx.get(), buffer, inStream.gcount()) != 1) {
            throw std::runtime_error{"Failed to update ctx" + GetOpenSSLError()};
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashSize;
    if (EVP_DigestFinal_ex(ctx.get(), hash, &hashSize) != 1 || hashSize != EVP_MD_size(md)) {
        throw std::runtime_error{"Failed to finalize hash" + GetOpenSSLError()};
    }

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < hashSize; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }
    return ss.str();
}
// private
AesCipherParams CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password, COMMAND_TYPE command) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());
    params.encrypt = static_cast<int>(command);

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password" + GetOpenSSLError()};
    }
    return params;
}

void CryptoGuardCtx::Impl::AesCipher(std::istream &inStream, std::ostream &outStream, const AesCipherParams& params) {
    auto ctx_deleter = [](EVP_CIPHER_CTX* ctx) { EVP_CIPHER_CTX_free(ctx); };
    std::unique_ptr<EVP_CIPHER_CTX, decltype(ctx_deleter)> ctx(EVP_CIPHER_CTX_new(), ctx_deleter);
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher ctx" + GetOpenSSLError());
    }

    if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) != 1) {
        throw std::runtime_error("Failed to initialize cipher" + GetOpenSSLError());
    }

    std::vector<unsigned char> inBuf(BUFFER_SIZE);
    std::vector<unsigned char> outBuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    int outLen;

    while (inStream.read(reinterpret_cast<char*>(inBuf.data()), inBuf.size()) || inStream.gcount()) {
        if (EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount()) != 1) {
            throw std::runtime_error("Failed to update cipher" + GetOpenSSLError());
        }
        outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
    }

    if (EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) != 1) {
        throw std::runtime_error("Failed to finalize cipher" + GetOpenSSLError());
    }
    outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);

    if (!outStream.good()) {
        throw std::runtime_error("Failed to write data");
    }
}

void CryptoGuardCtx::Impl::CheckInputStream(std::istream &inStream) const {
    if (!inStream.good()) {
        throw std::runtime_error("Failed input stream");
    }
}
void CryptoGuardCtx::Impl::CheckOutputStream(std::ostream &outStream) const {
    if (!outStream.good()) {
        throw std::runtime_error("Failed output stream");
    }
}

std::string CryptoGuardCtx::Impl::GetOpenSSLError() const {
    std::string result = "";
    unsigned long err_code = ERR_get_error();
    if (err_code != 0) {
        result += ". Details: ";
        result += ERR_reason_error_string(err_code);
    }
    return result;
}

// class CryptoGuardCtx
CryptoGuardCtx::CryptoGuardCtx() = default;
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::Encrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    return pImpl_->Encrypt(inStream, outStream, password);
}

void CryptoGuardCtx::Decrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    return pImpl_->Decrypt(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) {
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
