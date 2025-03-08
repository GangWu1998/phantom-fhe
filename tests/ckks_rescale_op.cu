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

void run_rescale_test(size_t poly_modulus_degree, const vector<int>& coeff_modulus, double scale, size_t chain_index){
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(phantom::arith::CoeffModulus::Create(poly_modulus_degree, coeff_modulus));
    (void) chain_index;

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

    PhantomPlaintext plain1, plain2;
    ckks_evaluator.encoder.encode(input1_vector, scale, plain1);
    ckks_evaluator.encoder.encode(input2_vector, scale, plain2);

    PhantomCiphertext cipher1, cipher2;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1);
    ckks_evaluator.encryptor.encrypt(plain2, cipher2);
    ckks_evaluator.evaluator.multiply_inplace(cipher1, cipher2);

    //rescale_to_next_inplace
    PhantomCiphertext dest_rescale_inplace = cipher1;
    ckks_evaluator.evaluator.rescale_to_next_inplace(dest_rescale_inplace);

    PhantomPlaintext result_rescale_inplace;
    ckks_evaluator.decryptor.decrypt(dest_rescale_inplace, result_rescale_inplace);

    vector<complex<double>> output_rescale_inplace;
    ckks_evaluator.encoder.decode(result_rescale_inplace, output_rescale_inplace);

    ASSERT_EQ(input1_vector.size(), output_rescale_inplace.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real(), output_rescale_inplace[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag(), output_rescale_inplace[i].imag(), EPSILON);
    }

    //rescale_to_next
    PhantomCiphertext dest_rescale;
    ckks_evaluator.evaluator.rescale_to_next(cipher1, dest_rescale);

    PhantomPlaintext result_rescale;
    ckks_evaluator.decryptor.decrypt(dest_rescale, result_rescale);

    vector<complex<double>> output_rescale;
    ckks_evaluator.encoder.decode(result_rescale, output_rescale);

    ASSERT_EQ(input1_vector.size(), output_rescale.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real(), output_rescale[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag(), output_rescale[i].imag(), EPSILON);
    }

    //mod_swtich_to_inplace1
    PhantomCiphertext dest_mod_inplace = cipher1;
    ckks_evaluator.evaluator.mod_switch_to_inplace(dest_mod_inplace, chain_index);

    PhantomPlaintext result_mod_inplace;
    ckks_evaluator.decryptor.decrypt(dest_mod_inplace, result_mod_inplace);

    vector<complex<double>> output_mod_inplace;
    ckks_evaluator.encoder.decode(result_mod_inplace, output_mod_inplace);

    ASSERT_EQ(input1_vector.size(), output_mod_inplace.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real(), output_mod_inplace[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag(), output_mod_inplace[i].imag(), EPSILON);
    }

    //mod_swtich_to_inplace2
    PhantomPlaintext result_mod_inplace2;
    ckks_evaluator.decryptor.decrypt(cipher1, result_mod_inplace2);
    ckks_evaluator.evaluator.mod_switch_to_inplace(result_mod_inplace2, chain_index);

    vector<complex<double>> output_mod_inplace2;
    ckks_evaluator.encoder.decode(result_mod_inplace2, output_mod_inplace2);

    ASSERT_EQ(input1_vector.size(), output_mod_inplace2.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real(), output_mod_inplace2[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag(), output_mod_inplace2[i].imag(), EPSILON);
    }

    //mod_switch_to_next_inplace
    PhantomCiphertext dest_mod_next = cipher1;
    ckks_evaluator.evaluator.mod_switch_to_next_inplace(dest_mod_next);

    PhantomPlaintext result_mod_next;
    ckks_evaluator.decryptor.decrypt(dest_mod_next, result_mod_next);

    vector<complex<double>> output_mod_next;
    ckks_evaluator.encoder.decode(result_mod_next, output_mod_next);

    ASSERT_EQ(input1_vector.size(), output_mod_next.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real(), output_mod_next[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag(), output_mod_next[i].imag(), EPSILON);
    }
}

namespace phantomtest{
    TEST(PhantomCKKSBasicOperationsTest, RescaleOperationTest1) {
        run_rescale_test(65536, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40), 2);
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleOperationTest2) {
        run_rescale_test(8192, {60, 30, 30, 30, 60}, pow(2.0, 30), 2);
    }

    TEST(PhantomCKKSBasicOperationsTest, RescaleOperationTest3) {
        run_rescale_test(16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40), 3);
    }

    TEST(PhantomCKKSBasicOperationsTest, RescaleOperationTest4) {
        run_rescale_test(32768, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50), 4);
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleOperationTest5) {
        run_rescale_test(65536, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50), 4);
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleOperationTest6) {
        run_rescale_test(8192, {60, 40, 40, 60}, pow(2.0, 40), 2);
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleOperationTest7) {
        run_rescale_test(16384, {50, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 50}, pow(2.0, 30), 5);
    }

    TEST(PhantomCKKSBasicOperationsTest, RescaleOperationTest8) {
        run_rescale_test(32768, {60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60}, pow(2.0, 60), 6);
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleOperationTest9) {
        run_rescale_test(8192, {30, 30, 30, 30}, pow(2.0, 30), 3);
    }
    TEST(PhantomCKKSBasicOperationsTest, RescaleOperationTest10) {
        run_rescale_test(32768, {30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30}, pow(2.0, 30), 6);
    }
}
