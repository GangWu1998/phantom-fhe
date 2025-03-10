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

const double EPSILON = 0.01;

std::vector<complex<double>> generate_random_vector(size_t size) {
    std::vector<complex<double>> result(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-1.0, 1.0);
    for (size_t i = 0; i < size; ++i) {
        result[i] = complex<double>(dis(gen), dis(gen));
    }
    return result;
}

void run_negation_test(size_t poly_modulus_degree, const vector<int>& coeff_modulus, double scale){
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
    vector<complex<double>> input_vector = generate_random_vector(slots);

    PhantomPlaintext plain;
    ckks_evaluator.encoder.encode(input_vector, scale, plain);

    PhantomCiphertext cipher;
    ckks_evaluator.encryptor.encrypt(plain, cipher);

    //Negation
    PhantomCiphertext dest_negate;
    ckks_evaluator.evaluator.negate(cipher, dest_negate);

    PhantomPlaintext result_negate;
    ckks_evaluator.decryptor.decrypt(dest_negate, result_negate);
    vector<complex<double>> output_negate;
    ckks_evaluator.encoder.decode(result_negate, output_negate);
    
    ASSERT_EQ(input_vector.size(), output_negate.size());
    for(size_t i = 0; i < input_vector.size(); i++){
        EXPECT_NEAR(input_vector[i].real(), -output_negate[i].real(), EPSILON);
        EXPECT_NEAR(input_vector[i].imag(), -output_negate[i].imag(), EPSILON);
    }

    //Negation_inplace
    ckks_evaluator.evaluator.negate_inplace(cipher);

    PhantomPlaintext result_negate_inplace;
    ckks_evaluator.decryptor.decrypt(cipher, result_negate_inplace);
    vector<complex<double>> output_negate_inplace;
    ckks_evaluator.encoder.decode(result_negate_inplace, output_negate_inplace);
    
    ASSERT_EQ(input_vector.size(), output_negate_inplace.size());
    for(size_t i = 0; i < input_vector.size(); i++){
        EXPECT_NEAR(input_vector[i].real(), -output_negate_inplace[i].real(), EPSILON);
        EXPECT_NEAR(input_vector[i].imag(), -output_negate_inplace[i].imag(), EPSILON);
    }
}

namespace phantomtest{
    TEST(PhantomCKKSBasicOperationsTest, NegationOperationTest1) {
        run_negation_test(65536, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, NegationOperationTest2) {
        run_negation_test(8192, {60, 30, 30, 30, 60}, pow(2.0, 30));
    }

    TEST(PhantomCKKSBasicOperationsTest, NegationOperationTest3) {
        run_negation_test(16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }

    TEST(PhantomCKKSBasicOperationsTest, NegationOperationTest4) {
        run_negation_test(32768, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, NegationOperationTest5) {
        run_negation_test(65536, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, NegationOperationTest6) {
        run_negation_test(8192, {60, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, NegationOperationTest7) {
        run_negation_test(16384, {50, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 50}, pow(2.0, 30));
    }

    TEST(PhantomCKKSBasicOperationsTest, NegationOperationTest8) {
        run_negation_test(32768, {60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60}, pow(2.0, 60));
    }
    TEST(PhantomCKKSBasicOperationsTest, NegationOperationTest9) {
        run_negation_test(8192, {30, 30, 30, 30}, pow(2.0, 30));
    }
    TEST(PhantomCKKSBasicOperationsTest, NegationOperationTest10) {
        run_negation_test(32768, {30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30}, pow(2.0, 30));
    }
}

