#pragma once

#include <memory>
#include <iostream>
#include <string>
#include <string_view>

#include <experimental/propagate_const>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept = default;

    // API
    void Encrypt(std::istream &inStream, std::ostream &outStream, std::string_view password);
    void Decrypt(std::istream &inStream, std::ostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::istream &inStream);

private:
    class Impl;
    std::experimental::propagate_const<std::unique_ptr<Impl>> pImpl_;
};

}  // namespace CryptoGuard
