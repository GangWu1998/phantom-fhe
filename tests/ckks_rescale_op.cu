#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include "phantom.h"
#include <vector>
#include <cmath>
#include <random>
#include <memory>

using namespace phantom;
using namespace phantom::arith;
using namespace phantom::util;
using namespace std;

const double EPSILON = 0.001;

vector<complex<double>> generate_random_vector(size_t size) {
    vector<complex<double>> result(size);
    random_device rd;
    mt19937 gen(rd());
    uniform_real_distribution<> dis(-1.0, 1.0);
    for (size_t i = 0; i < size; ++i) {
        result[i] = complex<double>(dis(gen), dis(gen));
    }
    return result;
}

vector<complex<double>> generate_constant_vector(size_t size) {
    vector<complex<double>> result(size);
     for (size_t i = 0; i < size; ++i) {
        result[i] = 1;
    }
    return result;
}

void run_rescale_test(size_t poly_modulus_degree, const vector<int>& coeff_modulus, double scale){
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(phantom::arith::CoeffModulus::Create(poly_modulus_degree, coeff_modulus));

    PhantomContext context(parms);
    PhantomCKKSEncoder encoder(context);
    PhantomSecretKey secret_key(context);
    PhantomPublicKey public_key = secret_key.gen_publickey(context);
    PhantomRelinKey relin_keys = secret_key.gen_relinkey(context);
    PhantomGaloisKey galois_keys = secret_key.create_galois_keys(context);

    CKKSEvaluator ckks_evaluator(&context, &public_key, &secret_key, &encoder, &relin_keys, &galois_keys, scale);

    int slots = ckks_evaluator.encoder.slot_count();
    vector<complex<double>> input1_vector = generate_random_vector(slots);
    vector<complex<double>> input2_vector = generate_constant_vector(slots);

    PhantomPlaintext plain1_rescale, plain2_rescale, result_rescale;
    ckks_evaluator.encoder.encode(input1_vector, scale, plain1_rescale);
    ckks_evaluator.encoder.encode(input2_vector, scale, plain2_rescale);

    PhantomCiphertext cipher1_rescale, cipher2_rescale;
    ckks_evaluator.encryptor.encrypt(plain1_rescale, cipher1_rescale);
    ckks_evaluator.encryptor.encrypt(plain2_rescale, cipher2_rescale);

    ckks_evaluator.evaluator.multiply_inplace(cipher1_rescale, cipher2_rescale);
    ckks_evaluator.evaluator.rescale_to_next_inplace(cipher1_rescale);

    ckks_evaluator.decryptor.decrypt(cipher1_rescale, result_rescale);

    vector<complex<double>> output_rescale;
    ckks_evaluator.encoder.decode(result_rescale, output_rescale);

    ASSERT_EQ(input1_vector.size(), output_rescale.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real(), output_rescale[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag(), output_rescale[i].imag(), EPSILON);
    }
}

namespace phantomtest{
    TEST(PhantomCKKSBasicOperationsTest, RescaleperationTest1) {
        run_rescale_test(65536, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleperationTest2) {
        run_rescale_test(8192, {60, 30, 30, 30, 60}, pow(2.0, 30));
    }

    TEST(PhantomCKKSBasicOperationsTest, RescaleperationTest3) {
        run_rescale_test(16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }

    TEST(PhantomCKKSBasicOperationsTest, RescaleperationTest4) {
        run_rescale_test(32768, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleperationTest5) {
        run_rescale_test(65536, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleperationTest6) {
        run_rescale_test(8192, {60, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleperationTest7) {
        run_rescale_test(16384, {50, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 50}, pow(2.0, 30));
    }

    TEST(PhantomCKKSBasicOperationsTest, RescaleperationTest8) {
        run_rescale_test(32768, {60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60}, pow(2.0, 60));
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleperationTest9) {
        run_rescale_test(8192, {30, 30, 30, 30}, pow(2.0, 30));
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleperationTest10) {
        run_rescale_test(32768, {30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30}, pow(2.0, 30));
    }
}
