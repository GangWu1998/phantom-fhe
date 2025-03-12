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

void run_galois_test(size_t poly_modulus_degree, const vector<int>& coeff_modulus, double scale, uint32_t galois_elts,int step){
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
/*
    //apply_galois
    PhantomCiphertext cipher_galois, dest_galois;
    ckks_evaluator.encryptor.encrypt(plain, cipher_galois);

    ckks_evaluator.evaluator.apply_galois(cipher_galois, galois_elts, galois_keys, dest_galois);

    PhantomPlaintext result_galois;
    ckks_evaluator.decryptor.decrypt(dest_galois, result_galois);
    vector<complex<double>> output_galois;
    ckks_evaluator.encoder.decode(result_galois, output_galois);

    ASSERT_EQ(input_vector.size(), output_galois.size());
    for(size_t i = 0; i < galois_elts; ++i){
        EXPECT_NEAR(input_vector[(i + galois_elts) % slots].real(), output_galois[i].real(), EPSILON);
        EXPECT_NEAR(input_vector[(i + galois_elts) % slots].imag(), output_galois[i].imag(), EPSILON);
    }
*/
    //apply_galois_inplace
    PhantomCiphertext cipher_galois_inplace;
    ckks_evaluator.encryptor.encrypt(plain, cipher_galois_inplace);

    ckks_evaluator.evaluator.apply_galois_inplace(cipher_galois_inplace, step, galois_keys);

    PhantomPlaintext result_galois_inplace;
    ckks_evaluator.decryptor.decrypt(cipher_galois_inplace, result_galois_inplace);
    vector<complex<double>> output_galois_inplace;
    ckks_evaluator.encoder.decode(result_galois_inplace, output_galois_inplace);

    ASSERT_EQ(input_vector.size(), output_galois_inplace.size());
    for(size_t i = 0; i < galois_elts; ++i){
        EXPECT_NEAR(input_vector[(i + galois_elts) % slots].real(), output_galois_inplace[i].real(), EPSILON);
        EXPECT_NEAR(input_vector[(i + galois_elts) % slots].imag(), output_galois_inplace[i].imag(), EPSILON);
    }
}

namespace phantomtest{
    TEST(PhantomCKKSBasicOperationsTest, GaloisOperationTest1) {
        run_galois_test(65536, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40), 2, 2);
    }
    TEST(PhantomCKKSBasicOperationsTest, GaloisOperationTest2) {
        run_galois_test(8192, {60, 30, 30, 30, 60}, pow(2.0, 30), 1, 2);
    }

    TEST(PhantomCKKSBasicOperationsTest, GaloisOperationTest3) {
        run_galois_test(16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40), 3, 2);
    }

    TEST(PhantomCKKSBasicOperationsTest, GaloisOperationTest4) {
        run_galois_test(32768, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50), 2, 3);
    }
    TEST(PhantomCKKSBasicOperationsTest, GaloisOperationTest5) {
        run_galois_test(65536, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50), 3, 2);
    }
    TEST(PhantomCKKSBasicOperationsTest, GaloisOperationTest6) {
        run_galois_test(8192, {60, 40, 40, 60}, pow(2.0, 40), 2, 1);
    }
    TEST(PhantomCKKSBasicOperationsTest, GaloisOperationTest7) {
        run_galois_test(16384, {50, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 50}, pow(2.0, 30), 4, 2);
    }

    TEST(PhantomCKKSBasicOperationsTest, GaloisOperationTest8) {
        run_galois_test(32768, {60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60}, pow(2.0, 60), 5, 2);
    }
    TEST(PhantomCKKSBasicOperationsTest, GaloisOperationTest9) {
        run_galois_test(8192, {30, 30, 30, 30}, pow(2.0, 30), 1, 1);
    }
    TEST(PhantomCKKSBasicOperationsTest, GaloisOperationTest10) {
        run_galois_test(32768, {30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30}, pow(2.0, 30), 6, 5);
    }
}

