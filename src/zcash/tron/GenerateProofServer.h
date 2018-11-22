#ifndef _TRON_GENERATE_PROOF_SERVER_H_
#define _TRON_GENERATE_PROOF_SERVER_H_

#include <grpc/grpc.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <grpcpp/security/server_credentials.h>

#include "../util.h"
#include "primitives/transaction.h"
#include "zcash/JoinSplit.hpp"

#include "geneproof.pb.h"
#include "geneproof.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::ServerWriter;
using grpc::Status;

using protocol::ProofServer;

class GenerateProofServer final : public ProofServer::Service {
public:
    GenerateProofServer():params(NULL) {}

    ~GenerateProofServer() {
        if (NULL != params) {
            delete params;
        }
    }

    bool Init();

    ::grpc::Status proof(::grpc::ServerContext* context, 
                const ::protocol::ProofInputMsg* request, 
                ::protocol::ProofOutputMsg* response);
                
private:
    void GetJSInput(const ::protocol::ProofInputMsg* request, 
                    std::vector<libzcash::JSInput>& input,
                    ::protocol::Result& resultCode );

    void GetJSOutput(const ::protocol::ProofInputMsg* request, 
                    std::vector<libzcash::JSOutput>& output,
                    ::protocol::Result& resultCode );


    boost::optional<ZCIncrementalMerkleTree> GetIncrementalMerkleTree(
                    const ::protocol::IncrementalMerkleTreeMsg* merkleTreeMsg, 
                    ::protocol::Result& resultCode );


    inline bool GetVecStr(const std::string& str, std::vector<unsigned char>& vec ) {
        vec.clear();
        vec.resize(str.size());
        memcpy(&vec[0], str.c_str(), str.size());
        return true;
    }

    void DoWork(::grpc::ServerContext* context, 
                const ::protocol::ProofInputMsg* request, 
                ::protocol::ProofOutputMsg* response);

    //just for debug
    void showJSInput(const libzcash::JSInput& input);
    //just for debug
    void showJSoutput(const libzcash::JSOutput& output);

private:
    ZCJoinSplit*  params;
};

#endif //_TRON_GENERATE_PROOF_SERVER_H_
