
#include <libsnark/common/profiling.hpp>

#include "../util.h"
#include "zcash/JoinSplit.hpp"
#include "GenerateProofServer.h"


using namespace libzcash;

int main(int argc, char **argv)
{
    // 这个初始化貌似没啥用，暂时先留着
    libsnark::start_profiling();

    std::string server_address("0.0.0.0:50051");
    GenerateProofServer service( );

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    LogPrint("Server listening on %s \n", server_address.c_str() );
    server->Wait();

    return 0;
}