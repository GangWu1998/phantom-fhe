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

void run_multi_test(size_t poly_modulus_degree, const vector<int>& coeff_modulus, double scale){
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
    vector<complex<double>> input2_vector = generate_random_vector(slots);

    PhantomPlaintext plain1, plain2;
    ckks_evaluator.encoder.encode(input1_vector, scale, plain1);
    ckks_evaluator.encoder.encode(input2_vector, scale, plain2);

    vector<complex<double>> expected(input1_vector.size());

    //multi_inplace
    PhantomCiphertext cipher1_inplace, cipher2_inplace;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1_inplace);
    ckks_evaluator.encryptor.encrypt(plain2, cipher2_inplace);

    ckks_evaluator.evaluator.multiply_inplace(cipher1_inplace, cipher2_inplace);
    ckks_evaluator.evaluator.rescale_to_next_inplace(cipher1_inplace);

    PhantomPlaintext multiresult_inplace;
    ckks_evaluator.decryptor.decrypt(cipher1_inplace, multiresult_inplace);
    vector<complex<double>> output_inplace;
    ckks_evaluator.encoder.decode(multiresult_inplace, output_inplace);

    ASSERT_EQ(input1_vector.size(), output_inplace.size());
    for(size_t i = 0; i < input1_vector.size(); i++){
        expected[i] = input1_vector[i] * input2_vector[i];
        EXPECT_NEAR(expected[i].real(), output_inplace[i].real(), EPSILON);
        EXPECT_NEAR(expected[i].imag(), output_inplace[i].imag(), EPSILON);
    }

    //multiply_plain_inplace
    PhantomCiphertext cipher1_plain_inplace;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1_plain_inplace);
    ckks_evaluator.evaluator.multiply_plain_inplace(cipher1_plain_inplace ,plain2); 

    PhantomPlaintext multiresult_plain_inplace;
    ckks_evaluator.decryptor.decrypt(cipher1_plain_inplace, multiresult_plain_inplace);

    vector<complex<double>> output_plain_inplace;
    ckks_evaluator.encoder.decode(multiresult_plain_inplace, output_plain_inplace);

    ASSERT_EQ(input1_vector.size(), output_plain_inplace.size());
    for(size_t i = 0; i < input1_vector.size(); i++){
        expected[i] = input1_vector[i] * input2_vector[i];
        EXPECT_NEAR(expected[i].real(), output_plain_inplace[i].real(), EPSILON);
        EXPECT_NEAR(expected[i].imag(), output_plain_inplace[i].imag(), EPSILON);
    }


    //multi_plain
    PhantomCiphertext cipher1_plain, dest_plain;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1_plain);    
    
    ckks_evaluator.evaluator.multiply_plain(cipher1_plain, plain2, dest_plain);

    PhantomPlaintext multiresult_plain;
    ckks_evaluator.decryptor.decrypt(dest_plain, multiresult_plain);

    vector<complex<double>> output_plain;
    ckks_evaluator.encoder.decode(multiresult_plain, output_plain);

    ASSERT_EQ(input1_vector.size(), output_plain.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(expected[i].real(), output_plain[i].real(), EPSILON);
        EXPECT_NEAR(expected[i].imag(), output_plain[i].imag(), EPSILON);
    }

    //multiply
    PhantomCiphertext cipher1_multiply, cipher2_multiply, dest_multiply;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1_multiply);
    ckks_evaluator.encryptor.encrypt(plain2, cipher2_multiply); 

    ckks_evaluator.evaluator.multiply(cipher1_multiply, cipher2_multiply, dest_multiply);
    ckks_evaluator.evaluator.rescale_to_next_inplace(dest_multiply);

    PhantomPlaintext plain_multiply;
    ckks_evaluator.decryptor.decrypt(dest_multiply, plain_multiply);
    vector<complex<double>> output_multiply;
    ckks_evaluator.encoder.decode(plain_multiply, output_multiply);
    
    ASSERT_EQ(input1_vector.size(), output_multiply.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(expected[i].real(), output_multiply[i].real(), EPSILON);
        EXPECT_NEAR(expected[i].imag(), output_multiply[i].imag(), EPSILON);
    }
}

namespace phantomtest{
    TEST(PhantomCKKSBasicOperationsTest, MultiOperationTest1) {
        run_multi_test(65536, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, MultiOperationTest2) {
        run_multi_test(8192, {60, 30, 30, 30, 60}, pow(2.0, 30));
    }

    TEST(PhantomCKKSBasicOperationsTest, MultiOperationTest3) {
        run_multi_test(16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }

    TEST(PhantomCKKSBasicOperationsTest, MultiOperationTest4) {
        run_multi_test(32768, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, MultiOperationTest5) {
        run_multi_test(65536, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, MultiOperationTest6) {
        run_multi_test(8192, {60, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, MultiOperationTest7) {
        run_multi_test(16384, {50, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 50}, pow(2.0, 30));
    }

    TEST(PhantomCKKSBasicOperationsTest, MultiOperationTest8) {
        run_multi_test(32768, {60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60}, pow(2.0, 60));
    }
    TEST(PhantomCKKSBasicOperationsTest, MultiOperationTest9) {
        run_multi_test(8192, {30, 30, 30, 30}, pow(2.0, 30));
    }
    TEST(PhantomCKKSBasicOperationsTest, MultiOperationTest10) {
        run_multi_test(32768, {30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30}, pow(2.0, 30));
    }
}

