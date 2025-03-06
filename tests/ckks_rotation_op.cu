#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include "phantom.h"
#include <vector>
#include <cmath>
#include <random>
#include <memory>
#include <complex>

using namespace phantom;
using namespace phantom::arith;
using namespace phantom::util;
using namespace std;

const double EPSILON = 0.001;

size_t total_memory_used = 0;

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

void run_rotation_test(size_t poly_modulus_degree, const vector<int>& coeff_modulus, double scale, size_t test_count,size_t verify_count){
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

    for(size_t j = 1; j<test_count; ++j){
        PhantomPlaintext plaintext, result;
        ckks_evaluator.encoder.encode(input_vector, scale, plaintext);

        PhantomCiphertext ciphertext, rotated_ciphertext;
        ckks_evaluator.encryptor.encrypt(plaintext, ciphertext);
        ckks_evaluator.evaluator.rotate_vector(ciphertext, j, galois_keys, rotated_ciphertext);

        ckks_evaluator.decryptor.decrypt(rotated_ciphertext, result);
        vector<complex<double>> output_vector;
        ckks_evaluator.encoder.decode(result, output_vector);

        ASSERT_EQ(input_vector.size(), output_vector.size());
        for(size_t i = 0; i < verify_count; ++i){
            EXPECT_NEAR(input_vector[(i + j) % slots].real(), output_vector[i].real(), EPSILON);
            EXPECT_NEAR(input_vector[(i + j) % slots].imag(), output_vector[i].imag(), EPSILON);
        }
    }
}


namespace phantomtest{
    TEST(PhantomCKKSBasicOperationsTest, RotationOperationTest1) {
        run_rotation_test(65536, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40), 10, 8);
    }
    TEST(PhantomCKKSBasicOperationsTest, RotationOperationTest2) {
        run_rotation_test(8192, {60, 30, 30, 30, 60}, pow(2.0, 30), 4, 9);
    }

    TEST(PhantomCKKSBasicOperationsTest, RotationOperationTest3) {
        run_rotation_test(16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40), 17, 10);
    }

    TEST(PhantomCKKSBasicOperationsTest, RotationOperationTest4) {
        run_rotation_test(32768, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50), 29, 16);
    }
    TEST(PhantomCKKSBasicOperationsTest, RotationOperationTest5) {
        run_rotation_test(65536, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50), 10, 8);
    }
    TEST(PhantomCKKSBasicOperationsTest, RotationOperationTest6) {
        run_rotation_test(8192, {60, 40, 40, 60}, pow(2.0, 40), 3, 9);
    }
    TEST(PhantomCKKSBasicOperationsTest, RotationOperationTest7) {
        run_rotation_test(16384, {50, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 50}, pow(2.0, 30), 17, 10);
    }

    TEST(PhantomCKKSBasicOperationsTest, RotationOperationTest8) {
        run_rotation_test(32768, {60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60}, pow(2.0, 60), 29, 16);
    }
    TEST(PhantomCKKSBasicOperationsTest, RotationOperationTest9) {
        run_rotation_test(8192, {30, 30, 30, 30}, pow(2.0, 30), 4, 9);
    }
    TEST(PhantomCKKSBasicOperationsTest, RotationOperationTest10) {
        run_rotation_test(32768, {30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30}, pow(2.0, 30), 29, 16);
    }
}

