#include <boost/array.hpp>
#include <boost/variant.hpp>

#include "amount.h"
#include "consensus/consensus.h"
#include "random.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "zcash/NoteEncryption.hpp"
#include "zcash/Proof.hpp"
#include "zcash/Zcash.h"
#include <libsnark/common/profiling.hpp>
#include "asyncrpcoperation.h"
#include "base58.h"
#include "paymentdisclosure.h"
#include "primitives/transaction.h"
#include "wallet.h"
#include "zcash/Address.hpp"
#include "zcash/JoinSplit.hpp"

#include "geneproof.grpc.pb.h"
#include "geneproof.pb.h"

#include "GenerateProofServer.h"

using ::protocol::ZeroProofConstant;

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
        /////// 需要再增加参数的合法性判断  TODO

        // 输入输出的参数必须是两个，考虑是否如果对象为空的话，可以由底层去创建
        if (request->inputs_size() != ZC_NUM_JS_INPUTS ||
            request->outputs_size() != ZC_NUM_JS_OUTPUTS) {
            //LogPrint("12");
            ret.set_result_code(1);
            ret.set_result_desc("Invalid prame num");
            break;
        }

        //////  参数转换  ////////

        std::vector<libzcash::JSInput> vjsin;
        std::vector<libzcash::JSOutput> vjsout;

        GetJSInput(request, vjsin, ret);
        GetJSOutput(request, vjsout, ret);

        // Generate the proof, this can take over a minute.
        boost::array<libzcash::JSInput, ZC_NUM_JS_INPUTS> inputs{vjsin[0], vjsin[1]};
        boost::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS> outputs{vjsout[0], vjsout[1]};

        bool computeProof = request->compute_proof();

        // uint256 pubKeyHash(request->pubkeyhash().hash());
        uint256 pubKeyHash = uint256S(request->pubkeyhash().hash());
        CAmount vpub_old(request->vpub_old());
        CAmount vpub_new(request->vpub_new());
        // uint256 anchor(request->rt().hash());
        uint256 anchor = uint256S(request->rt().hash());

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

    //boost::array<libzcash::SproutNote, ZC_NUM_JS_OUTPUTS> notes;
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        ::protocol::SproutNoteMsg* sprouteNote = response->add_out_notes();
        sprouteNote->set_value(notes[i].value());

        ::protocol::Uint256Msg* uint256Msg = sprouteNote->mutable_a_pk();
        uint256Msg->set_hash(notes[i].a_pk.begin(), notes[i].a_pk.size());

        uint256Msg = sprouteNote->mutable_rho();
        uint256Msg->set_hash(notes[i].rho.begin(), notes[i].rho.size());

        uint256Msg = sprouteNote->mutable_r();
        uint256Msg->set_hash(notes[i].r.begin(), notes[i].r.size());
    }

    //boost::array<ZCNoteEncryption::Ciphertext, ZC_NUM_JS_OUTPUTS> ciphertexts
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        response->add_out_ciphertexts(ciphertexts[i].begin(), ciphertexts[i].size());
    }

    // uint256 ephemeralKey;
    ::protocol::Uint256Msg* uintMsg = response->mutable_out_ephemeralkey();
    uintMsg->set_hash(ephemeralKey.begin(), ephemeralKey.size());

    // uint256 randomSeed;
    uintMsg = response->mutable_out_randomseed();
    uintMsg->set_hash(randomSeed.begin(), randomSeed.size());

    // boost::array<uint256, ZC_NUM_JS_INPUTS> macs;
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        uintMsg = response->mutable_out_macs(i);
        uintMsg->set_hash(macs[i].begin(), macs[i].size());
    }

    // boost::array<uint256, ZC_NUM_JS_INPUTS> nullifiers;
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        uintMsg = response->mutable_out_nullifiers(i);
        uintMsg->set_hash(nullifiers[i].begin(), nullifiers[i].size());
    }

    // boost::array<uint256, ZC_NUM_JS_OUTPUTS> commitments;
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++) {
        uintMsg = response->mutable_out_commitments(i);
        uintMsg->set_hash(commitments[i].begin(), commitments[i].size());
    }

    // uint256 esk;
    uintMsg = response->mutable_out_esk();
    uintMsg->set_hash(esk.begin(), esk.size());

    // boost::variant<libzcash::ZCProof, libzcash::GrothProof> proof;
    // 先这样处理，TODO
    CDataStream ssProof(SER_NETWORK, PROTOCOL_VERSION);
    auto ps = SproutProofSerializer<CDataStream>(ssProof, true);
    boost::apply_visitor(ps, proof);
    response->set_proof( &(*ssProof.begin()), ssProof.size() );
    
    ret.set_result_code(0);
    ret.set_result_desc("success");
    // Result ret;
    response->set_allocated_ret(&ret);

    return Status::OK;
}

// 未考虑参数的校验
void GenerateProofServer::GetJSInput(
    const ::protocol::ProofInputMsg* request,
    std::vector<libzcash::JSInput>& input,
    ::protocol::Result& resultCode)
{
    for (size_t i = 0; i < request->inputs_size(); i++) {
        const ::protocol::JSInputMsg& inputMsg = request->inputs(i);

        // ZCIncrementalWitness witness
        const ::protocol::IncrementalWitnessMsg& incrementalWitness = inputMsg.witness();

        ZCIncrementalMerkleTree tree = GetIncrementalMerkleTree(&incrementalWitness.tree(), resultCode);

        ZCIncrementalMerkleTree cursor = GetIncrementalMerkleTree(&incrementalWitness.cursor(), resultCode);

        size_t cursor_depth = incrementalWitness.cursor_depth();

        vector<libzcash::SHA256Compress> filled;

        for (int i = 0; i < incrementalWitness.filled_size(); i++) {
            filled.push_back(uint256S(incrementalWitness.filled(i).hash()));
        }

        ZCIncrementalWitness witness(tree, filled, cursor, cursor_depth);

        // SproutNote note;
        const ::protocol::SproutNoteMsg& sproutNote = inputMsg.note();

        uint64_t value = sproutNote.value();
        // uint256 a_pk(sproutNote.a_pk().hash());
        // uint256 rho(sproutNote.rho().hash());
        // uint256 r(sproutNote.r().hash());
        uint256 a_pk = uint256S(sproutNote.a_pk().hash());
        uint256 rho = uint256S(sproutNote.rho().hash());
        uint256 r = uint256S(sproutNote.r().hash());

        libzcash::SproutNote note(a_pk, value, rho, r);

        // SpendingKey key;
        const ::protocol::Uint256Msg& keyMsg = inputMsg.key();
        libzcash::SpendingKey key(uint252(keyMsg.hash()));

        input.push_back(libzcash::JSInput(witness, note, key));
    }
}

void GenerateProofServer::GetJSOutput(
    const ::protocol::ProofInputMsg* request,
    std::vector<libzcash::JSOutput>& output,
    ::protocol::Result& resultCode)
{
    for (size_t i = 0; i < request->outputs_size(); i++) {
        const ::protocol::JSOutputMsg& outputMsg = request->outputs(i);

        //  PaymentAddress addr;
        // uint256 a_pk(outputMsg.a_pk().hash());
        // uint256 pk_enc(outputMsg.pk_enc().hash());
        uint256 a_pk = uint256S(outputMsg.a_pk().hash());
        uint256 pk_enc= uint256S(outputMsg.pk_enc().hash());

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
}

ZCIncrementalMerkleTree& GenerateProofServer::GetIncrementalMerkleTree(
    const ::protocol::IncrementalMerkleTreeMsg* merkleTreeMsg,
    ::protocol::Result& resultCode)
{
    // 这里需考虑，如果没有传递对象时如何处理，返回错误还是默认给加上，TODO
    std::vector<boost::optional<libzcash::SHA256Compress>> parents;

    if (merkleTreeMsg->parents_size() > 0) {
        for (int i = 0; i < merkleTreeMsg->parents_size(); i++) {
            parents.push_back( uint256S( merkleTreeMsg->parents(i).hash()) );
        }
    }

    libzcash::SHA256Compress left(uint256S(merkleTreeMsg->left().hash()));
    libzcash::SHA256Compress right(uint256S(merkleTreeMsg->right().hash()));

    ZCIncrementalMerkleTree merkleTree(left, right, parents);

    // 设置结果0，成功
    resultCode.set_result_code(0);

    return merkleTree;
}