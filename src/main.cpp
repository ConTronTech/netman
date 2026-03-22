#include "app.hpp"
#include <unistd.h>
#include <iostream>
#include <cstring>

int main(int argc, char* argv[]) {
    // Check if running as root
    if (geteuid() != 0) {
        std::cerr << "NetMan requires root privileges. Relaunching with pkexec...\n";
        
        // Build pkexec command
        std::vector<char*> args;
        args.push_back(const_cast<char*>("pkexec"));
        args.push_back(const_cast<char*>("--keep-cwd"));
        
        for (int i = 0; i < argc; i++) {
            args.push_back(argv[i]);
        }
        args.push_back(nullptr);
        
        // Replace current process with pkexec version
        execvp("pkexec", args.data());
        
        // If execvp fails
        std::cerr << "Failed to elevate privileges. Run with: sudo " << argv[0] << "\n";
        return 1;
    }
    
    auto app = NetManApp::create();
    return app->run(argc, argv);
}
