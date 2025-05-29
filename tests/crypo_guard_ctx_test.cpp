#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <sstream>

const size_t CHECKSUM_SIZE = 64;

class EncryptTest : public ::testing::Test {
protected:
    void SetUp() override {
        iss << message;
    }
    CryptoGuard::CryptoGuardCtx ctx;
    const std::string message = "some message";
    const std::string password = "1234";
    std::stringstream iss, oss;
};

TEST_F(EncryptTest, SimpleTest) {
    ASSERT_NO_THROW(ctx.Encrypt(iss, oss, password));
    std::string result = oss.str();
    ASSERT_FALSE(result.empty());
    ASSERT_NE(message, result);
    ASSERT_NE(message.size(), result.size());
}

TEST_F(EncryptTest, InvalidInStreamTest) {
    iss.setstate(std::ios::failbit);
    ASSERT_THROW(ctx.Encrypt(iss, oss, password), std::runtime_error);
}

TEST_F(EncryptTest, InvalidOutStreamTest) {
    oss.setstate(std::ios::failbit);
    ASSERT_THROW(ctx.Encrypt(iss, oss, password), std::runtime_error);
}

TEST_F(EncryptTest, DifferentResultForDifferentInputTest) {
    ASSERT_NO_THROW(ctx.Encrypt(iss, oss, password));
    std::string result = oss.str();
    ASSERT_FALSE(result.empty());

    std::istringstream iss_other(message + " ");
    std::ostringstream oss_other;
    ASSERT_NO_THROW(ctx.Encrypt(iss_other, oss_other, password));
    std::string result_other = oss_other.str();
    ASSERT_FALSE(result_other.empty());

    ASSERT_NE(result, result_other);
}

TEST_F(EncryptTest, DifferentResultForDifferentPasswordTest) {
    ASSERT_NO_THROW(ctx.Encrypt(iss, oss, password));
    std::string result = oss.str();
    ASSERT_FALSE(result.empty());

    std::istringstream iss_other(message);
    std::ostringstream oss_other;
    std::string password_other = password;
    password_other[0] = static_cast<char>(password_other[0] + 1);
    ASSERT_NO_THROW(ctx.Encrypt(iss_other, oss_other, password_other));
    std::string result_other = oss_other.str();
    ASSERT_FALSE(result_other.empty());

    ASSERT_NE(result, result_other);
}

using DecryptTest = EncryptTest;

TEST_F(DecryptTest, DecryptNotEncryptedDataTest) {
    EXPECT_THROW(
    {
        try {
            ctx.Decrypt(iss, oss, password);
        } catch (const std::runtime_error& e) {
            EXPECT_THAT(e.what(), testing::HasSubstr("Failed to finalize cipher. Details:"));
            throw;
        }
    },
    std::runtime_error
);
}

TEST_F(DecryptTest, DecryptEncryptedDataTest) {
    std::string result;
    ASSERT_NO_THROW(ctx.Encrypt(iss, oss, password));
    std::istringstream iss_other(oss.str());
    std::ostringstream oss_other;
    ASSERT_NO_THROW(ctx.Decrypt(iss_other, oss_other, password));
    result = oss.str();
    ASSERT_NE(message, result);
    ASSERT_NE(message.size(), result.size());
}

TEST_F(DecryptTest, InvalidInStreamTest) {
    iss.setstate(std::ios::failbit);
    ASSERT_THROW(ctx.Decrypt(iss, oss, password), std::runtime_error);
}

TEST_F(DecryptTest, InvalidOutStreamTest) {
    oss.setstate(std::ios::failbit);
    ASSERT_THROW(ctx.Decrypt(iss, oss, password), std::runtime_error);
}

using ChecksumTest = EncryptTest;

TEST_F(ChecksumTest, SameChecksumForTheSameDataTest) {
    std::string checksum_expected;
    ASSERT_NO_THROW(checksum_expected = ctx.CalculateChecksum(iss));
    ASSERT_EQ(checksum_expected.size(), CHECKSUM_SIZE);

    std::istringstream other_iss(message);
    std::string checksum;
    ASSERT_NO_THROW(checksum = ctx.CalculateChecksum(other_iss));
    ASSERT_EQ(checksum.size(), CHECKSUM_SIZE);
    ASSERT_EQ(checksum, checksum_expected);
}

TEST_F(ChecksumTest, DifferentChecksumForDifferentDataTest) {
    std::string checksum_expected;
    ASSERT_NO_THROW(checksum_expected = ctx.CalculateChecksum(iss));
    ASSERT_EQ(checksum_expected.size(), CHECKSUM_SIZE);

    std::istringstream other_iss(message + " ");
    std::string checksum;
    ASSERT_NO_THROW(checksum = ctx.CalculateChecksum(other_iss));
    ASSERT_EQ(checksum.size(), CHECKSUM_SIZE);
    ASSERT_NE(checksum, checksum_expected);
}

TEST_F(ChecksumTest, InvalidStreamTest) {
    std::string checksum;
    iss.setstate(std::ios::failbit);
    ASSERT_THROW(checksum = ctx.CalculateChecksum(iss), std::runtime_error);
}

TEST(FullApiTest, SimpleTest) {
    CryptoGuard::CryptoGuardCtx ctx;

    const std::string expected_message = "Encryption and Decryption are successfully";
    const std::string password = "1234";

    std::stringstream in_checksum, out_checksum;
    std::stringstream iss_encrypt, oss_encrypt;
    std::stringstream iss_decrypt, oss_decrypt;

    iss_encrypt << expected_message;
    ASSERT_NO_THROW(ctx.Encrypt(iss_encrypt, oss_encrypt, password));
    iss_decrypt << oss_encrypt.str();
    ASSERT_NO_THROW(ctx.Decrypt(iss_decrypt, oss_decrypt, password));
    std::string result, checksum;
    result = oss_decrypt.str();

    std::string expected_checksum;
    in_checksum << expected_message;
    out_checksum << result;
    ASSERT_NO_THROW(expected_checksum = ctx.CalculateChecksum(in_checksum));
    ASSERT_NO_THROW(checksum = ctx.CalculateChecksum(out_checksum));

    ASSERT_EQ(expected_checksum.size(), CHECKSUM_SIZE);
    ASSERT_EQ(checksum.size(), CHECKSUM_SIZE);
    ASSERT_EQ(checksum, expected_checksum);
    ASSERT_EQ(result, expected_message);
}

