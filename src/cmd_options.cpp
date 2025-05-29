#include "cmd_options.h"

#include <iostream>

namespace CryptoGuard {
namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
        ("help,h", "список доступных опций")
        ("command", po::value<std::string>(), "команда encrypt, decrypt или checksum")
        ("input,i", po::value<std::string>(), "путь до входного файла")
        ("output,o", po::value<std::string>(), "путь до файла, в котором будет сохранён результат")
        ("password,p", po::value<std::string>(), "пароль для шифрования и дешифрования");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc_ << "\n";
            return;
        }

        if (vm.count("command")) {
            auto command = vm["command"].as<std::string>();
            auto it = commandMapping_.find(command);
            if (it != commandMapping_.end()) {
                command_ = it->second;
            } else {
                throw std::runtime_error{"Unsupported command: " + command};
            }
        }

        if (vm.count("input")) {
            inputFile_ = vm["input"].as<std::string>();
        }

        if (vm.count("output")) {
            outputFile_ = vm["output"].as<std::string>();
        }

        if (vm.count("password")) {
            password_ = vm["password"].as<std::string>();
        }
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
    } catch(...) {
        std::cerr << "Exception of unknown type!\n";
    }
}

bool ProgramOptions::ValidateOptions() const {
    if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
        CheckInputOutputPassword();
    } else if (command_ == COMMAND_TYPE::CHECKSUM) {
        CheckInputFile();
    }
    return command_ != COMMAND_TYPE::UNKNOWN;
}

void ProgramOptions::CheckInputOutputPassword() const {
    if (inputFile_.empty() || outputFile_.empty() || password_.empty()) {
        throw std::runtime_error{"command requires input, output file path and password"};
    }
}

void ProgramOptions::CheckInputFile() const {
    if (inputFile_.empty()) {
        throw std::runtime_error{"command requires input file path"};
    }
}

}  // namespace CryptoGuard
