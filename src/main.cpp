
#include "Config.hpp"
#include "Portal.hpp"

int main(int argc, char* argv[])
{
    const csocks::Config* config = csocks::Config::instance();
    csocks::Portal portal(config);
    portal.run();
    return 0;
}
