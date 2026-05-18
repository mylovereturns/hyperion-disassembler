#include "ui/app.h"
#include <spdlog/spdlog.h>

int main(int argc, char** argv) {
    (void)argv;
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%H:%M:%S.%e] [%l] %v");

    hype::App app;

    if (argc > 1) {
        // will be handled via command line in future
    }

    return app.run();
}
