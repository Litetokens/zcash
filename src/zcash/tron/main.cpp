#include <iostream>
#include <libsnark/common/profiling.hpp>

#include "log.h"
#include "../util.h"
#include "GenerateProofServer.h"
#include "zcash/JoinSplit.hpp"

using namespace std;
using namespace libzcash;

int main(int argc, char** argv)
{
    // 这个初始化貌似没啥用，暂时先留着
    libsnark::start_profiling();

    OpenDebugLog();

    LogDebug("start proof server ....");
    std::string server_address("0.0.0.0:50053");
    GenerateProofServer service;

    if (!service.Init()) {
        LogError("Server init error");
        return -1;
    }

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    LogDebug("Server listening on %s", server_address.c_str());
    server->Wait();

    CloseDebugLog();

    return 0;
}
