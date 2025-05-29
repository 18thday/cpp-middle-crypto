#include "cmd_options.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <iostream>
#include <sstream>
#include <string>

using namespace CryptoGuard;

class ProgramOptionsTest : public ::testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {
        cleanup();
    }

    std::pair<int, char**> prepareCommandLine(const std::vector<std::string>& args) {
        cleanup();
        argc = args.size();
        argv = new char*[argc];

        for (int i = 0; i < argc; ++i) {
            argv[i] = new char[args[i].size() + 1];
            strcpy(argv[i], args[i].c_str());
        }

        return {argc, argv};
    }

    void cleanup() {
        for (int i = 0; i < argc; ++i) {
            delete[] argv[i];
        }
        delete[] argv;
        argv = nullptr;
    }

    int argc = 0;
    char** argv = nullptr;
};

TEST_F(ProgramOptionsTest, DefaultConstructorTest) {
    ProgramOptions options;

    ASSERT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNKNOWN);
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST_F(ProgramOptionsTest, ParseEmptyCommandLineTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard"});
    ProgramOptions options;

    EXPECT_NO_THROW(options.Parse(argc, argv));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNKNOWN);
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST_F(ProgramOptionsTest, HelpOptionTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard", "--help"});
    ProgramOptions options;

    testing::internal::CaptureStdout();
    options.Parse(argc, argv);
    std::string output = testing::internal::GetCapturedStdout();

    ASSERT_FALSE(output.empty());
    EXPECT_THAT(output, testing::HasSubstr("Allowed options"));
    EXPECT_THAT(output, testing::HasSubstr("--help"));
    EXPECT_THAT(output, testing::HasSubstr("--command"));
    EXPECT_THAT(output, testing::HasSubstr("--input"));
    EXPECT_THAT(output, testing::HasSubstr("--output"));
    EXPECT_THAT(output, testing::HasSubstr("--password"));
}

TEST_F(ProgramOptionsTest, ParseEncryptCommandTest) {
    auto [argc, argv] = prepareCommandLine({"program", "--command=encrypt"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST_F(ProgramOptionsTest, ParseDecryptCommandTest) {
    auto [argc, argv] = prepareCommandLine({"program", "--command=decrypt"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST_F(ProgramOptionsTest, ParseChecksumCommandTest) {
    auto [argc, argv] = prepareCommandLine({"program", "--command=checksum"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST_F(ProgramOptionsTest, ParseFullOptionTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard", "--input=input.txt",
        "--output=output.txt", "--password=1234"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

TEST_F(ProgramOptionsTest, ParseShortOptionTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard", "-i", "input.txt",
        "-o", "output.txt", "-p", "1234"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

TEST_F(ProgramOptionsTest, ParseUnknownCommandTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard", "--command=invalid"});
    ProgramOptions options;

    testing::internal::CaptureStderr();
    EXPECT_NO_THROW(options.Parse(argc, argv));
    std::string output = testing::internal::GetCapturedStderr();

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNKNOWN);
    EXPECT_THAT(output, testing::HasSubstr("Error: Unsupported command: invalid"));
}

TEST_F(ProgramOptionsTest, ParseInvalidOptionTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard", "--invalid"});
    ProgramOptions options;

    testing::internal::CaptureStderr();
    EXPECT_NO_THROW(options.Parse(argc, argv));
    std::string output = testing::internal::GetCapturedStderr();

    EXPECT_THAT(output, testing::HasSubstr("Error"));
}

TEST_F(ProgramOptionsTest, ValidChecksumTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard", "--command=checksum",
        "--input=input.txt"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    bool result = false;
    EXPECT_NO_THROW(result = options.IsValid());
    EXPECT_TRUE(result);
}

TEST_F(ProgramOptionsTest, ValidEncryptTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard",
        "--command=encrypt",
        "--input=input.txt",
        "--output=output.txt",
        "--password=1234"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    bool result = false;
    EXPECT_NO_THROW(result = options.IsValid());
    EXPECT_TRUE(result);
}

TEST_F(ProgramOptionsTest, ValidDecryptTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard",
        "--command=decrypt",
        "--input=input.txt",
        "--output=output.txt",
        "--password=1234"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    bool result = false;
    EXPECT_NO_THROW(result = options.IsValid());
    EXPECT_TRUE(result);
}

TEST_F(ProgramOptionsTest, InvalidChecksumTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard", "--command=checksum",
        "--output=file.txt"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    ASSERT_THROW(options.IsValid(), std::runtime_error);
}

TEST_F(ProgramOptionsTest, InvalidEncryptTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard",
        "--command=encrypt",
        "--input=input.txt",
        "--output=output.txt"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    ASSERT_THROW(options.IsValid(), std::runtime_error);
}

TEST_F(ProgramOptionsTest, InvalidDecryptTest) {
    auto [argc, argv] = prepareCommandLine({"CryptoGuard",
        "--command=decrypt",
        "--input=input.txt",
        "--password=1234"});
    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    ASSERT_THROW(options.IsValid(), std::runtime_error);
}