#include "JoinSplit.hpp"
#include "prf.h"
#include "sodium.h"

#include "zcash/util.h"

#include <memory>

#include <boost/foreach.hpp>
#include <boost/format.hpp>
#include <boost/optional.hpp>
#include <fstream>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include "tinyformat.h"
#include "sync.h"
#include "amount.h"

using namespace libsnark;

namespace libzcash {

#include "zcash/circuit/gadget.tcc"

CCriticalSection cs_ParamsIO;
CCriticalSection cs_LoadKeys;

template<typename T>
void saveToFile(const std::string path, T& obj) {
    LOCK(cs_ParamsIO);

    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename T>
void saveMulReduceToFile(const std::string path, T& obj) {
    LOCK(cs_ParamsIO);

    std::stringstream ss;
    getBinaryData(ss, obj);
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename T>
void loadFromFile(const std::string path, T& objIn) {
    LOCK(cs_ParamsIO);

    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    if(!fh.is_open()) {
        throw std::runtime_error(strprintf("could not load param file at %s", path));
    }

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    objIn = std::move(obj);
}

template<size_t NumInputs, size_t NumOutputs>
class JoinSplitCircuit : public JoinSplit<NumInputs, NumOutputs> {
public:
    typedef default_r1cs_ppzksnark_pp ppzksnark_ppT;
    //typedef class alt_bn128_pp   ppzksnark_ppT
    typedef Fr<ppzksnark_ppT> FieldT;
    //typedef alt_bn128_pp::Fp_type   FieldT;
    // Fp_model<4, bigint<4>>   =  FieldT;
 
    r1cs_ppzksnark_verification_key<ppzksnark_ppT> vk;
    r1cs_ppzksnark_processed_verification_key<ppzksnark_ppT> vk_precomp;
    std::string pkPath;

    JoinSplitCircuit(const std::string vkPath, const std::string pkPath) : pkPath(pkPath) {
        loadFromFile(vkPath, vk);
        vk.showData();
        vk_precomp = r1cs_ppzksnark_verifier_process_vk(vk);
    }
    ~JoinSplitCircuit() {}

    static void generate(const std::string r1csPath,
                         const std::string vkPath,
                         const std::string pkPath)
    {
        protoboard<FieldT> pb;

        joinsplit_gadget<FieldT, NumInputs, NumOutputs> g(pb);
        g.generate_r1cs_constraints();

        auto r1cs = pb.get_constraint_system();

        saveToFile(r1csPath, r1cs);

        r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_ppzksnark_generator<ppzksnark_ppT>(r1cs);

        saveToFile(vkPath, keypair.vk);
        saveMulReduceToFile(vkPath+"_tron", keypair.vk);
        saveToFile(pkPath, keypair.pk);
    }

    bool verify(
        const ZCProof& proof,
        ProofVerifier& verifier,
        const uint256& pubKeyHash,
        const uint256& randomSeed,
        const boost::array<uint256, NumInputs>& macs,
        const boost::array<uint256, NumInputs>& nullifiers,
        const boost::array<uint256, NumOutputs>& commitments,
        uint64_t vpub_old,
        uint64_t vpub_new,
        const uint256& rt
    ) {
        try {
            auto r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<ppzksnark_ppT>>();          

            uint256 h_sig = this->h_sig(randomSeed, nullifiers, pubKeyHash);

            printf(" verify h_sig:\n");
            printf("%s\n", h_sig.GetHex().c_str());

            auto witness = joinsplit_gadget<FieldT, NumInputs, NumOutputs>::witness_map(
                rt,
                h_sig,
                macs,
                nullifiers,
                commitments,
                vpub_old,
                vpub_new
            );

            return verifier.check(
                vk,
                vk_precomp,
                witness,
                r1cs_proof
            );
        } catch (...) {
            return false;
        }
    }

    ZCProof prove(
        const boost::array<JSInput, NumInputs>& inputs,
        const boost::array<JSOutput, NumOutputs>& outputs,
        boost::array<SproutNote, NumOutputs>& out_notes,
        boost::array<ZCNoteEncryption::Ciphertext, NumOutputs>& out_ciphertexts,
        uint256& out_ephemeralKey,
        const uint256& pubKeyHash,
        uint256& out_randomSeed,
        boost::array<uint256, NumInputs>& out_macs,
        boost::array<uint256, NumInputs>& out_nullifiers,
        boost::array<uint256, NumOutputs>& out_commitments,
        uint64_t vpub_old,
        uint64_t vpub_new,
        const uint256& rt,
        bool computeProof,
        uint256 *out_esk // Payment disclosure
    ) {
        printf("1\n");
        if (vpub_old > MAX_MONEY) {
            throw std::invalid_argument("nonsensical vpub_old value");
        }
        printf("2\n");
        if (vpub_new > MAX_MONEY) {
            throw std::invalid_argument("nonsensical vpub_new value");
        }

        printf("3\n");

        uint64_t lhs_value = vpub_old;
        uint64_t rhs_value = vpub_new;

        for (size_t i = 0; i < NumInputs; i++) {
            // Sanity checks of input
            {
                // If note has nonzero value
                if (inputs[i].note.value() != 0) {
                    // The witness root must equal the input root.
                    uint256 winroot = inputs[i].witness.root();
                    printf("inputs[i].witness.root():%s\n", winroot.GetHex().c_str());
                    printf("rt:%s\n\n", rt.GetHex().c_str());

                    if (winroot != rt) {
                        throw std::invalid_argument("joinsplit not anchored to the correct root");
                    }
                    printf("%lu   4\n", i);
                    // The tree must witness the correct element
                    if (inputs[i].note.cm() != inputs[i].witness.element()) {
                        throw std::invalid_argument("witness of wrong element for joinsplit input");
                    }
                }
                printf("%lu   5\n", i);
                // Ensure we have the key to this note.
                printf("note.a_pk:%s \n", inputs[i].note.a_pk.GetHex().c_str());
                printf("inputs[i].key.address().a_pk:%s \n", inputs[i].key.address().a_pk.GetHex().c_str());
                printf("inputs[i].key.address().pk_enc:%s \n", inputs[i].key.address().pk_enc.GetHex().c_str());
                printf("a_sk:%s \n", inputs[i].key.ToString().c_str());

                if (inputs[i].note.a_pk != inputs[i].key.address().a_pk) {
                    throw std::invalid_argument("input note not authorized to spend with given key");
                }
                printf("%lu   7\n", i);
                // Balance must be sensical
                if (inputs[i].note.value() > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical input note value");
                }
                printf("%lu   8\n", i);
                lhs_value += inputs[i].note.value();

                if (lhs_value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical left hand size of joinsplit balance");
                }
                printf("%lu   9\n", i);
            }

            // Compute nullifier of input
            out_nullifiers[i] = inputs[i].nullifier();
        }
 printf("10\n");
        // Sample randomSeed
        out_randomSeed = random_uint256();
 printf("11\n");
        // Compute h_sig
        uint256 h_sig = this->h_sig(out_randomSeed, out_nullifiers, pubKeyHash);
 printf("12\n");
        // Sample phi
        uint252 phi = random_uint252();

        // Compute notes for outputs
        for (size_t i = 0; i < NumOutputs; i++) {
            // Sanity checks of output
            {
                if (outputs[i].value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical output value");
                }
printf("%lu   13\n", i);
                rhs_value += outputs[i].value;

                if (rhs_value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical right hand side of joinsplit balance");
                }
printf("%lu   14\n", i);
            }

            // Sample r
            uint256 r = random_uint256();

            out_notes[i] = outputs[i].note(phi, r, i, h_sig);
printf("%lu   15\n", i);
        }

        if (lhs_value != rhs_value) {
            throw std::invalid_argument("invalid joinsplit balance");
        }
printf("16\n");
        // Compute the output commitments
        for (size_t i = 0; i < NumOutputs; i++) {
            out_commitments[i] = out_notes[i].cm();
        }
printf("17\n");
        // Encrypt the ciphertexts containing the note
        // plaintexts to the recipients of the value.
        {
            ZCNoteEncryption encryptor(h_sig);

            for (size_t i = 0; i < NumOutputs; i++) {
                SproutNotePlaintext pt(out_notes[i], outputs[i].memo);
printf("17 111\n");
                out_ciphertexts[i] = pt.encrypt(encryptor, outputs[i].addr.pk_enc);
printf("17 222\n");
            }
printf("18\n");
            out_ephemeralKey = encryptor.get_epk();
printf("19\n");
            // !!! Payment disclosure START
            if (out_esk != nullptr) {
                *out_esk = encryptor.get_esk();
            }
            // !!! Payment disclosure END
            printf("20\n");
        }

        // Authenticate h_sig with each of the input
        // spending keys, producing macs which protect
        // against malleability.
        for (size_t i = 0; i < NumInputs; i++) {
            out_macs[i] = PRF_pk(inputs[i].key, i, h_sig);
        }
            printf("21\n");
        if (!computeProof) {
            return ZCProof();
        }
 printf("22\n");
        protoboard<FieldT> pb;
        {
            joinsplit_gadget<FieldT, NumInputs, NumOutputs> g(pb);
            printf("22.0\n");
            g.generate_r1cs_constraints();
             printf("22.1\n");
            g.generate_r1cs_witness(
                phi,
                rt,
                h_sig,
                inputs,
                out_notes,
                vpub_old,
                vpub_new
            );
        }
printf("23\n");
        // The constraint system must be satisfied or there is an unimplemented
        // or incorrect sanity check above. Or the constraint system is broken!
        assert(pb.is_satisfied());
printf("24\n");
        // TODO: These are copies, which is not strictly necessary.
        std::vector<FieldT> primary_input = pb.primary_input();
        std::vector<FieldT> aux_input = pb.auxiliary_input();
printf("25\n");
        // Swap A and B if it's beneficial (less arithmetic in G2)
        // In our circuit, we already know that it's beneficial
        // to swap, but it takes so little time to perform this
        // estimate that it doesn't matter if we check every time.
        pb.constraint_system.swap_AB_if_beneficial();
printf("26\n");
        std::ifstream fh(pkPath, std::ios::binary);
printf("27\n");
        if(!fh.is_open()) {
            throw std::runtime_error(strprintf("could not load param file at %s", pkPath));
        }
printf("28\n");
        return ZCProof(r1cs_ppzksnark_prover_streaming<ppzksnark_ppT>(
            fh,
            primary_input,
            aux_input,
            pb.constraint_system
        ));
    }
};

template<size_t NumInputs, size_t NumOutputs>
void JoinSplit<NumInputs, NumOutputs>::Generate(const std::string r1csPath,
                                                const std::string vkPath,
                                                const std::string pkPath)
{
    initialize_curve_params();
    JoinSplitCircuit<NumInputs, NumOutputs>::generate(r1csPath, vkPath, pkPath);
}

template<size_t NumInputs, size_t NumOutputs>
JoinSplit<NumInputs, NumOutputs>* JoinSplit<NumInputs, NumOutputs>::Prepared(const std::string vkPath,
                                                                             const std::string pkPath)
{
    initialize_curve_params();
    return new JoinSplitCircuit<NumInputs, NumOutputs>(vkPath, pkPath);
}

template<size_t NumInputs, size_t NumOutputs>
uint256 JoinSplit<NumInputs, NumOutputs>::h_sig(
    const uint256& randomSeed,
    const boost::array<uint256, NumInputs>& nullifiers,
    const uint256& pubKeyHash
) {
    const unsigned char personalization[crypto_generichash_blake2b_PERSONALBYTES]
        = {'T','r','o','n','C','o','m','p','u','t','e','h','S','i','g','0'};

    std::vector<unsigned char> block(randomSeed.begin(), randomSeed.end());

    for (size_t i = 0; i < NumInputs; i++) {
        block.insert(block.end(), nullifiers[i].begin(), nullifiers[i].end());
    }

    block.insert(block.end(), pubKeyHash.begin(), pubKeyHash.end());

    uint256 output;

    if (crypto_generichash_blake2b_salt_personal(output.begin(), 32,
                                                 &block[0], block.size(),
                                                 NULL, 0, // No key.
                                                 NULL,    // No salt.
                                                 personalization
                                                ) != 0)
    {
        throw std::logic_error("hash function failure");
    }

    printf("randomSeed: %s\n", randomSeed.GetHex().c_str() );
    printf("nullifiers:\n");
    for (size_t i = 0; i < NumInputs; i++) {
        printf("%s ", nullifiers[i].GetHex().c_str());
    }
    printf("\npubKeyHash:%s\n\n", pubKeyHash.GetHex().c_str());


    return output;
}

SproutNote JSOutput::note(const uint252& phi, const uint256& r, size_t i, const uint256& h_sig) const {
    uint256 rho = PRF_rho(phi, i, h_sig);

    return SproutNote(addr.a_pk, value, rho, r);
}

JSOutput::JSOutput() : addr(uint256(), uint256()), value(0) {
    SpendingKey a_sk = SpendingKey::random();
    addr = a_sk.address();
}

JSInput::JSInput() : witness(ZCIncrementalMerkleTree().witness()),
                     key(SpendingKey::random()) {
    note = SproutNote(key.address().a_pk, 0, random_uint256(), random_uint256());
    ZCIncrementalMerkleTree dummy_tree;
    dummy_tree.append(note.cm());
    witness = dummy_tree.witness();
}

template class JoinSplit<ZC_NUM_JS_INPUTS,
                         ZC_NUM_JS_OUTPUTS>;

}
