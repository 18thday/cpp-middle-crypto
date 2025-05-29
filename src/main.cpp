#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        if (!options.IsValid()) {
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::ifstream ifs(options.GetInputFile());
            std::ofstream ofs(options.GetOutputFile());
            cryptoCtx.Encrypt(ifs, ofs, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::ifstream ifs(options.GetInputFile());
            std::ofstream ofs(options.GetOutputFile());
            cryptoCtx.Decrypt(ifs, ofs, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::ifstream ifs(options.GetInputFile());
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(ifs));
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    } catch(...) {
        std::cerr << "Exception of unknown type!\n";
        return 1;
    }
    return 0;
}