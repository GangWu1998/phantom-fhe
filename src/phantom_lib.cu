#include "phantom.h"
#include "phantom_api.cuh"

using namespace phantom;
using namespace phantom::arith;
using namespace phantom::util;

typedef enum
{
    LIB_ANT,     //!< Using ANT in-house library
    LIB_SEAL,    //!< Using SEAL library
    LIB_OPENFHE, //!< Using OpenFHE library
    LIB_PHANTOM,
} LIB_PROV;
typedef struct
{
    LIB_PROV _provider;       //!< underlying library provider
    uint32_t _poly_degree;    //!< polynomial degree
    size_t _sec_level;        //!< security level of HE
    size_t _mul_depth;        //!< multiply depth
    size_t _input_level;      //!< level of input ciphertext
    size_t _first_mod_size;   //!< first prime size
    size_t _scaling_mod_size; //!< bits of scaling factor
    size_t _num_q_parts;      //!< number of parts of q primes
    size_t _hamming_weight;   //!< hamming weight of secret key
    size_t _num_rot_idx;      //!< number of rotation idx
    int32_t _rot_idxs[];      //!< array of rotation idxs
} CKKS_PARAMS;

class PHANTOM_CONTEXT
{
public:
    const PhantomSecretKey &Secret_key() const { return *_sk; }
    const PhantomPublicKey &Public_key() const { return *_pk; }
    const PhantomRelinKey &Relin_key() const { return *_rlk; }
    const PhantomGaloisKey &Rotate_key() const { return *_rtk; }

private:
    PHANTOM_CONTEXT(const PHANTOM_CONTEXT &) = delete;
    PHANTOM_CONTEXT &operator=(const PHANTOM_CONTEXT &) = delete;

    PHANTOM_CONTEXT();
    ~PHANTOM_CONTEXT();

    static PHANTOM_CONTEXT *Instance;

private:
    PhantomContext *_ctx;

    PhantomSecretKey *_sk;
    PhantomPublicKey *_pk;
    PhantomRelinKey *_rlk;
    PhantomGaloisKey *_rtk;
    PhantomCKKSEncoder *_encoder;

    uint64_t _scaling_mod_size;

}

PHANTOM_CONTEXT::PHANTOM_CONTEXT()
{
    // fhe-cmplr
    // CKKS_PARAMS* prog_param = Get_context_params();

    CKKS_PARAMS *prog_param = new CKKS_PARAMS{LIB_PHANTOM, 8192, 128, 0, 0, 60, 40, 2, 192, 3, 0};
    phantom::EncryptionParameters parms(phantom::scheme_type::ckks);

    uint32_t degree = prog_param->_poly_degree;
    parms.set_poly_modulus_degree(degree);
    std::vector<int> bits;
    bits.push_back(prog_param->_first_mod_size);
    for (uint32_t i = 1; i < prog_param->_mul_depth; ++i)
    {
        bits.push_back(prog_param->_scaling_mod_size);
    }
    bits.push_back(prog_param->_first_mod_size);
    parms.set_coeff_modulus(phantom::arith::CoeffModulus::Create(degree, bits));

    _ctx = new PhantomContext(parms);
    _sk = new PhantomSecretKey(*_ctx);
    _pk = &(_sk->gen_publickey(*_ctx));
    _rlk = &(_sk->gen_relinkey(*_ctx));
    _rtk = &(_sk->create_galois_keys(*_ctx));

    _encoder = &(PhantomCKKSEncoder(*_ctx));

    _scaling_mod_size = prog_param->_scaling_mod_size;
    printf(
        "ckks_param: _provider = %d, _poly_degree = %d, _sec_level = %ld, "
        "mul_depth = %ld, _first_mod_size = %ld, _scaling_mod_size = %ld, "
        "_num_q_parts = %ld, _num_rot_idx = %ld\n",
        prog_param->_provider, prog_param->_poly_degree, prog_param->_sec_level,
        prog_param->_mul_depth, prog_param->_first_mod_size,
        prog_param->_scaling_mod_size, prog_param->_num_q_parts,
        prog_param->_num_rot_idx);
}

PHANTOM_CONTEXT::~PHANTOM_CONTEXT()
{

    delete _encoder;
    delete _rtk;
    delete _rlk;
    delete _pk;
    // delete _sk;
    delete _ctx;
}
