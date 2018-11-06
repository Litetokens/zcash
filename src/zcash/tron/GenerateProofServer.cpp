#include <boost/array.hpp>
#include <boost/variant.hpp>
#include <iostream>

#include "amount.h"
#include "asyncrpcoperation.h"
#include "base58.h"
#include "consensus/consensus.h"
#include "paymentdisclosure.h"
#include "primitives/transaction.h"
#include "random.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "wallet/wallet.h"
#include "zcash/Address.hpp"
#include "zcash/JoinSplit.hpp"
#include "zcash/NoteEncryption.hpp"
#include "zcash/Proof.hpp"
#include "zcash/Zcash.h"
#include <libsnark/common/profiling.hpp>

#include "geneproof.grpc.pb.h"
#include "geneproof.pb.h"

#include "GenerateProofServer.h"

using ::protocol::ZeroProofConstant;
using namespace std;

#define TRACE_CMH_1 (printf("%s(%d)-<%s>: ", __FILE__, __LINE__, __FUNCTION__), printf)

const int CONST_32 = 32;

bool GenerateProofServer::Init()
{
    if (NULL != params) {
        delete params;
    }

    params = ZCJoinSplit::Prepared((ZC_GetParamsDir() / "sprout-verifying.key").string(),
                                   (ZC_GetParamsDir() / "sprout-proving.key").string());
    if (NULL == params) {
        return false;
    }
    return true;
}

::grpc::Status GenerateProofServer::proof(::grpc::ServerContext* context,
                                          const ::protocol::ProofInputMsg* request,
                                          ::protocol::ProofOutputMsg* response)
{
    // 定义返回参数
    ::protocol::Result ret;
    ret.set_result_code(0);
    ret.set_result_desc("success");

    boost::array<uint256, ZC_NUM_JS_INPUTS> nullifiers;

    boost::array<uint256, ZC_NUM_JS_OUTPUTS> commitments;

    // Ephemeral key
    uint256 ephemeralKey;

    boost::array<ZCNoteEncryption::Ciphertext, ZC_NUM_JS_OUTPUTS> ciphertexts = {{{{0}}}};

    uint256 randomSeed;

    boost::array<uint256, ZC_NUM_JS_INPUTS> macs;

    boost::variant<libzcash::ZCProof, libzcash::GrothProof> proof;

    uint256 esk; // payment disclosure

    boost::array<libzcash::SproutNote, ZC_NUM_JS_OUTPUTS> notes;

    do {
        // 参数的基本判断
        if (request == NULL) {
            printf("Invalid param. request = NULL");
            ret.set_result_code(1);
            ret.set_result_desc("Invalid param. request = NULL.");
            break;
        }

        // 仅判断输出参数的个数
        if (request->outputs_size() != ZC_NUM_JS_OUTPUTS) {
            printf("Invalid param size. outputs size should be 2.\n");
            ret.set_result_code(1);
            ret.set_result_desc("Invalid param size. outputs size should be 2");
            break;
        }

        if (!request->has_pubkeyhash() || !request->has_rt()) {
            printf("Invalid param. request.pubkeyhash:%d  request.rt:%d \n", request->has_pubkeyhash(), request->has_rt());
            ret.set_result_code(1);
            ret.set_result_desc("Invalid param. All param should be filled.");
            break;
        }

        // 获取传递进来的参数
        std::vector<libzcash::JSInput> vjsin;
        GetJSInput(request, vjsin, ret);

        std::vector<libzcash::JSOutput> vjsout;
        GetJSOutput(request, vjsout, ret);

        // Generate the proof, this can take over a minute.
        boost::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> inputs{vjsin[0], vjsin[1]};
        boost::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> outputs{vjsout[0], vjsout[1]};

        bool computeProof = request->compute_proof();

        // uint256 pubKeyHash(request->pubkeyhash().hash());
        if (request->pubkeyhash().hash().size() != CONST_32 ||
            request->rt().hash().size() != CONST_32) {
            TRACE_CMH_1("Invalid param. Uint256Msg.hash (%d)(%d) id not equal 32\n ",
                        request->pubkeyhash().hash().size(),
                        request->rt().hash().size());
            ret.set_result_code(1);
            ret.set_result_desc("Invalid param. Uint256Msg.hash size should be 32");
            break;
        }

        std::vector<unsigned char> vec(32);
        GetVecStr(request->pubkeyhash().hash(), vec);
        uint256 pubKeyHash(vec);

        CAmount vpub_old(request->vpub_old());
        CAmount vpub_new(request->vpub_new());

        GetVecStr(request->rt().hash(), vec);
        uint256 anchor(vec);

        printf("before proof...\n ");

        boost::array<size_t, ZC_NUM_JS_INPUTS> inputMap = {0, 1};
        boost::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap = {0, 1};
        // for (int i=0; i<2; i++) {
        // printf("aa 1 %s 2 %s \n",inputs[i].note.a_pk.GetHex().c_str(), inputs[i].key.address().a_pk.GetHex().c_str());
        // }

        MappedShuffle(inputs.begin(), inputMap.begin(), ZC_NUM_JS_INPUTS, GetRandInt);
        MappedShuffle(outputs.begin(), outputMap.begin(), ZC_NUM_JS_OUTPUTS, GetRandInt);
        // for (int i=0; i<2; i++) {
        // printf("aa 1 %s 2 %s \n",inputs[i].note.a_pk.GetHex().c_str(), inputs[i].key.address().a_pk.GetHex().c_str());
        // }

        /////  调用底层函数生成proof  ////////
        proof = params->prove(
            inputs,
            outputs,
            notes,
            ciphertexts,
            ephemeralKey,
            pubKeyHash,
            randomSeed,
            macs,
            nullifiers,
            commitments,
            vpub_old,
            vpub_new,
            anchor,
            computeProof,
            &esk // payment disclosure
        );

    } while (0);

    //// 返回值的格式化  /////
    printf("after proof generate...\n");

    if (response != NULL) {
        if (ret.result_code() == 0) {
            //boost::array<libzcash::SproutNote, ZC_NUM_JS_OUTPUTS> notes;
            for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
                ::protocol::SproutNoteMsg* sprouteNote = response->add_out_notes();
printf("1  %d\n", i);
                sprouteNote->set_value(notes[i].value());
printf("2  %d\n", i);
                ::protocol::Uint256Msg* uint256Msg = sprouteNote->mutable_a_pk();
                uint256Msg->set_hash(notes[i].a_pk.begin(), notes[i].a_pk.size());
printf("3 %d\n", i);
                uint256Msg = sprouteNote->mutable_rho();
                uint256Msg->set_hash(notes[i].rho.begin(), notes[i].rho.size());
printf("4  %d\n", i);
                uint256Msg = sprouteNote->mutable_r();
                uint256Msg->set_hash(notes[i].r.begin(), notes[i].r.size());
printf("5  %d\n", i);
            }

            //boost::array<ZCNoteEncryption::Ciphertext, ZC_NUM_JS_OUTPUTS> ciphertexts
            for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
                response->add_out_ciphertexts(ciphertexts[i].begin(), ciphertexts[i].size());
 printf("6  %d\n", i);
            }

            // uint256 ephemeralKey;
            ::protocol::Uint256Msg* uintMsg = response->mutable_out_ephemeralkey();
            uintMsg->set_hash(ephemeralKey.begin(), ephemeralKey.size());
printf("7 \n");
            // uint256 randomSeed;
            uintMsg = response->mutable_out_randomseed();
            uintMsg->set_hash(randomSeed.begin(), randomSeed.size());
printf("8 \n");
            // boost::array<uint256, ZC_NUM_JS_INPUTS> macs;
            for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
                //uintMsg = response->mutable_out_macs(i);
                uintMsg = response->add_out_macs();
                uintMsg->set_hash(macs[i].begin(), macs[i].size());
printf("8  %d\n", i);
            }

            // boost::array<uint256, ZC_NUM_JS_INPUTS> nullifiers;
            for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
                //uintMsg = response->mutable_out_nullifiers(i);
                uintMsg = response->add_out_nullifiers();
                uintMsg->set_hash(nullifiers[i].begin(), nullifiers[i].size());
                printf("9  %d\n", i);
            }

            // boost::array<uint256, ZC_NUM_JS_OUTPUTS> commitments;
            for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
                //uintMsg = response->mutable_out_commitments(i);
                uintMsg = response->add_out_commitments();
                uintMsg->set_hash(commitments[i].begin(), commitments[i].size());
printf("10  %i\n", i);
            }

            // uint256 esk;
            uintMsg = response->mutable_out_esk();
            uintMsg->set_hash(esk.begin(), esk.size());
printf("11 \n");
            // boost::variant<libzcash::ZCProof, libzcash::GrothProof> proof;
            // 先这样处理，TODO
            CDataStream ssProof(SER_NETWORK, PROTOCOL_VERSION);
printf("11   11\n");
            auto ps = SproutProofSerializer<CDataStream>(ssProof, false);
printf("12 \n");
            boost::apply_visitor(ps, proof);

            std::string s = HexStr(ssProof.begin(), ssProof.end());
            printf("proof size:%d data:%s\n", ssProof.size(), s.c_str());
printf("13 \n");
            response->set_proof(&(*ssProof.begin()), ssProof.size());
        }
printf("14\n");
        ::protocol::Result* result = response->mutable_ret();
        result->set_result_code(ret.result_code());
        result->set_result_desc(ret.result_desc());
    }

    printf("proof deal ok\n");

    return Status::OK;
}

// 未考虑参数的校验
void GenerateProofServer::GetJSInput(
    const ::protocol::ProofInputMsg* request,
    std::vector<libzcash::JSInput>& input,
    ::protocol::Result& resultCode)
{
    // 内部参数，到这里的话request不可能为空，暂不判断
    std::vector<unsigned char> vec(32);

    for (size_t i = 0; i < request->inputs_size(); i++) {
        const ::protocol::JSInputMsg& inputMsg = request->inputs(i);

        if (!inputMsg.has_witness() || !inputMsg.has_note() || !inputMsg.has_key()) {
            TRACE_CMH_1("Invalid param. inputs.witness:%d inputs.note:%d inputs.key:%d.\n",
                        inputMsg.has_witness(), inputMsg.has_note(), inputMsg.has_key());
            resultCode.set_result_code(1);
            resultCode.set_result_desc("Invalid param. All param should be filled.");
        }

        // ZCIncrementalWitness witness
        const ::protocol::IncrementalWitnessMsg& incrementalWitness = inputMsg.witness();

        ZCIncrementalMerkleTree tree = GetIncrementalMerkleTree(&incrementalWitness.tree(), resultCode);
        if (resultCode.result_code() != 0) {
            return;
        }

        ZCIncrementalMerkleTree cursor = GetIncrementalMerkleTree(&incrementalWitness.cursor(), resultCode);
        if (resultCode.result_code() != 0) {
            return;
        }

        size_t cursor_depth = incrementalWitness.cursor_depth();

        vector<libzcash::SHA256Compress> filled;
        for (int i = 0; i < incrementalWitness.filled_size(); i++) {
            if (incrementalWitness.filled(i).hash().size() == CONST_32) {
                GetVecStr(incrementalWitness.filled(i).hash(), vec);
                filled.push_back(uint256(vec));
            } else {
                TRACE_CMH_1("Invalid param. Uint256Msg.hash size(%d) id not equal 32\n ",
                            incrementalWitness.filled(i).hash().size());
                resultCode.set_result_code(1);
                resultCode.set_result_desc("Invalid param. Uint256Msg.hash size should be 32");
                return;
            }
        }

        ZCIncrementalWitness witness(tree, filled, cursor, cursor_depth);

        // SproutNote note;
        const ::protocol::SproutNoteMsg& sproutNote = inputMsg.note();

        uint64_t value = sproutNote.value();
        // uint256 a_pk(sproutNote.a_pk().hash());
        // uint256 rho(sproutNote.rho().hash());
        // uint256 r(sproutNote.r().hash());
        if (sproutNote.a_pk().hash().size() != CONST_32 ||
            sproutNote.rho().hash().size() != CONST_32 ||
            sproutNote.r().hash().size() != CONST_32) {
            TRACE_CMH_1("Invalid param. Uint256Msg.hash size is not equal 32\n ");
            resultCode.set_result_code(1);
            resultCode.set_result_desc("Invalid param. Uint256Msg.hash size should be 32");
            return;
        }

        GetVecStr(sproutNote.a_pk().hash(), vec);
        uint256 a_pk(vec);
        GetVecStr(sproutNote.rho().hash(), vec);
        uint256 rho(vec);
        GetVecStr(sproutNote.r().hash(), vec);
        uint256 r(vec);

        libzcash::SproutNote note(a_pk, value, rho, r);

        // SpendingKey key;
        const ::protocol::Uint256Msg& keyMsg = inputMsg.key();
        if (keyMsg.hash().size() != 32) {
            TRACE_CMH_1("Invalid param. Uint256Msg.hash size is not equal 32\n ");
            resultCode.set_result_code(1);
            resultCode.set_result_desc("Invalid param. Uint256Msg.hash size should be 32");
            return;
        }

        GetVecStr(keyMsg.hash(), vec);
        uint256 key256(vec);
        uint252 key252(key256);
        libzcash::SpendingKey key(key252);

        input.push_back(libzcash::JSInput(witness, note, key));
    }

    // 如果不足，则添加
    while (input.size() < ZC_NUM_JS_INPUTS) {
        input.push_back(libzcash::JSInput());
    }
    printf("GetJSInput deal ok\n");
}

void GenerateProofServer::GetJSOutput(
    const ::protocol::ProofInputMsg* request,
    std::vector<libzcash::JSOutput>& output,
    ::protocol::Result& resultCode)
{
    for (size_t i = 0; i < request->outputs_size(); i++) {
        const ::protocol::JSOutputMsg& outputMsg = request->outputs(i);

        if (!outputMsg.has_a_pk() || !outputMsg.has_pk_enc()) {
            TRACE_CMH_1("Invalid param. output.a_pk:%d  output.pk_enc:%d\n",
                        outputMsg.has_a_pk(), outputMsg.has_pk_enc());
            resultCode.set_result_code(1);
            resultCode.set_result_desc("Invalid param. JSOutputMsg all param should be filled");
            return;
        }

        if (outputMsg.a_pk().hash().size() != CONST_32 ||
            outputMsg.pk_enc().hash().size() != CONST_32) {
            TRACE_CMH_1("Invalid param. Uint256Msg.hash size is not equal 32\n ");
            resultCode.set_result_code(1);
            resultCode.set_result_desc("Invalid param. Uint256Msg.hash size should be 32");
            return;
        }

        //  PaymentAddress addr;
        std::vector<unsigned char> vec(32);
        GetVecStr(outputMsg.a_pk().hash(), vec);
        uint256 a_pk(vec);

        std::string str = outputMsg.pk_enc().hash();
        GetVecStr(outputMsg.pk_enc().hash(), vec);
        uint256 pk_enc(vec);

        std::string s = HexStr(str.begin(), str.end());

        printf("pk_enc(in):%s pk_enc(out):%s\n", s.c_str(), pk_enc.GetHex().c_str());

        libzcash::PaymentAddress addr(a_pk, pk_enc);

        // uint64_t value;
        uint64_t value = outputMsg.value();

        // boost::array<unsigned char, ZC_MEMO_SIZE> memo = {{0xF6}};
        boost::array<unsigned char, ZC_MEMO_SIZE> memo = {{0xF6}};
        // copy vector into boost array
        const string& strMomo = outputMsg.memo();
        int lenMemo = strMomo.size();
        for (int i = 0; i < ZC_MEMO_SIZE && i < lenMemo; i++) {
            memo[i] = strMomo[i];
        }

        libzcash::JSOutput jsoutput(addr, value);
        jsoutput.memo = memo;

        output.push_back(jsoutput);
    }

    printf("GetJSOutput deal ok\n");
}

ZCIncrementalMerkleTree GenerateProofServer::GetIncrementalMerkleTree(
    const ::protocol::IncrementalMerkleTreeMsg* merkleTreeMsg,
    ::protocol::Result& resultCode)
{
    ZCIncrementalMerkleTree emptytree;

    if (merkleTreeMsg == NULL) {
        TRACE_CMH_1("Invalid param. merkleTreeMsg = NULL");
        resultCode.set_result_code(1);
        resultCode.set_result_desc("Invalid param. IncrementalMerkleTreeMsg = NULL");
        return emptytree;
    }

    // parent 的大小不超过29
    if (merkleTreeMsg->parents_size() > ::protocol::TRON_INCREMENTAL_MERKLE_TREE_DEPTH) {
        TRACE_CMH_1("Invalid param. parents size(%d) shoule not big than %d .\n ",
                    merkleTreeMsg->parents_size(),
                    ::protocol::TRON_INCREMENTAL_MERKLE_TREE_DEPTH);
        resultCode.set_result_code(1);
        resultCode.set_result_desc("Invalid param. parents size should no more than 29");
        return emptytree;
    }

    std::vector<unsigned char> vec(32);
    std::vector<boost::optional<libzcash::SHA256Compress>> parents;
    if (merkleTreeMsg->parents_size() > 0) {
        for (int i = 0; i < merkleTreeMsg->parents_size(); i++) {
            if (merkleTreeMsg->parents(i).hash().size() == CONST_32) {
                GetVecStr(merkleTreeMsg->parents(i).hash(), vec);
                parents.push_back(libzcash::SHA256Compress(uint256(vec)));
            } else {
                TRACE_CMH_1("Invalid param. Uint256Msg.hash size(%d) id not equal 32\n ", merkleTreeMsg->parents(i).hash().size());
                resultCode.set_result_code(1);
                resultCode.set_result_desc("Invalid param. Uint256Msg.hash size should be 32");
                return emptytree;
            }
        }
    }

    boost::optional<libzcash::SHA256Compress> left = boost::none;
    boost::optional<libzcash::SHA256Compress> right = boost::none;
    if (merkleTreeMsg->has_left()) {
        if (merkleTreeMsg->left().hash().size() == CONST_32) {
            GetVecStr(merkleTreeMsg->left().hash(), vec);
            left = libzcash::SHA256Compress(uint256(vec));
        } else {
            TRACE_CMH_1("Invalid param. Uint256Msg.hash size(%d) id not equal 32\n ", merkleTreeMsg->left().hash().size());
            resultCode.set_result_code(1);
            resultCode.set_result_desc("Invalid param. Uint256Msg.hash size should be 32");
            return emptytree;
        }
    }
    if (merkleTreeMsg->has_right()) {
        if (merkleTreeMsg->right().hash().size() == CONST_32) {
            GetVecStr(merkleTreeMsg->right().hash(), vec);
            left = libzcash::SHA256Compress(uint256(vec));
        } else {
            TRACE_CMH_1("Invalid param. Uint256Msg.hash size(%d) id not equal 32.\n ", merkleTreeMsg->right().hash().size());
            resultCode.set_result_code(1);
            resultCode.set_result_desc("Invalid param. Uint256Msg.hash size should be 32.");
            return emptytree;
        }
    }

    ZCIncrementalMerkleTree merkleTree(left, right, parents);

    printf("Finish deal GetIncrementalMerkleTree OK\n");

    return merkleTree;
}

::grpc::Status GenerateProofServer::hello(::grpc::ServerContext* context,
                                          const ::protocol::Uint256Msg* request,
                                          ::protocol::Result* response)
{
    ::protocol::Result ret;
    ret.set_result_code(0);
    ret.set_result_desc("success");

    cout << "proofServer: Hello " << endl;
    if (request != NULL) {
        cout << request->hash() << endl;
    }

    if (request->hash().size() != 32) {
        cout << "hash size should be 32" << endl;
        ret.set_result_code(100);
        ret.set_result_desc("Invalid param.");
    } else {
        cout << "Invalid param, request = NULL " << endl;
    }
    cout << "hello deal ok" << endl;

    if (response != NULL) {
        // Result ret;
        response->set_result_code(ret.result_code());
        response->set_result_desc(ret.result_desc());
    }
    return Status::OK;
}
