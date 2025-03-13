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

void run_relinearize_test(size_t poly_modulus_degree, const vector<int>& coeff_modulus, double scale){
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

    PhantomCiphertext cipher1, cipher2;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1);
    ckks_evaluator.encryptor.encrypt(plain2, cipher2);
    ckks_evaluator.evaluator.multiply_inplace(cipher1, cipher2);

    //relinearize_inplace
    PhantomCiphertext dest_relin_inplace = cipher1;
    ckks_evaluator.evaluator.relinearize_inplace(dest_relin_inplace, relin_keys);

    PhantomPlaintext result_relin_inplace;
    ckks_evaluator.decryptor.decrypt(dest_relin_inplace, result_relin_inplace);

    vector<complex<double>> output_relin_inplace;
    ckks_evaluator.encoder.decode(result_relin_inplace, output_relin_inplace);

    ASSERT_EQ(input1_vector.size(), output_relin_inplace.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real(), output_relin_inplace[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag(), output_relin_inplace[i].imag(), EPSILON);
    }

    //relinearize
    PhantomCiphertext dest_relin;
    ckks_evaluator.evaluator.relinearize(cipher1, relin_keys, dest_relin);

    PhantomPlaintext result_relin;
    ckks_evaluator.decryptor.decrypt(dest_relin, result_relin);

    vector<complex<double>> output_relin;
    ckks_evaluator.encoder.decode(result_relin, output_relin);

    ASSERT_EQ(input1_vector.size(), output_relin.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real(), output_relin[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag(), output_relin[i].imag(), EPSILON);
    }
}

namespace phantomtest{
    TEST(PhantomCKKSBasicOperationsTest, RelinearizeOperationTest1) {
        run_relinearize_test(65536, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, RelinearizeOperationTest2) {
        run_relinearize_test(8192, {60, 30, 30, 30, 60}, pow(2.0, 30));
    }

    TEST(PhantomCKKSBasicOperationsTest, RelinearizeOperationTest3) {
        run_relinearize_test(16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }

    TEST(PhantomCKKSBasicOperationsTest, RelinearizeOperationTest4) {
        run_relinearize_test(32768, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, RelinearizeOperationTest5) {
        run_relinearize_test(65536, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, RelinearizeOperationTest6) {
        run_relinearize_test(8192, {60, 40, 40, 60}, pow(2.0, 40));
    }   
    TEST(PhantomCKKSBasicOperationsTest, RelinearizeOperationTest7) {
        run_relinearize_test(16384, {50, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 50}, pow(2.0, 30));
    }

    TEST(PhantomCKKSBasicOperationsTest, RelinearizeOperationTest8) {
        run_relinearize_test(32768, {60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60}, pow(2.0, 60));
    }
    TEST(PhantomCKKSBasicOperationsTest, RelinearizeOperationTest9) {
        run_relinearize_test(8192, {30, 30, 30, 30}, pow(2.0, 30));
    }
    TEST(PhantomCKKSBasicOperationsTest, RelinearizeOperationTest10) {
        run_relinearize_test(32768, {30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30}, pow(2.0, 30));
    }
}
