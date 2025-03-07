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

void run_sub_test(size_t poly_modulus_degree, const vector<int>& coeff_modulus, double scale){
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

    //sub_inplace
    PhantomCiphertext cipher1_inplace, cipher2_inplace;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1_inplace);
    ckks_evaluator.encryptor.encrypt(plain2, cipher2_inplace);

    ckks_evaluator.evaluator.sub_inplace(cipher1_inplace, cipher2_inplace);
    PhantomPlaintext subresult_inplace;
    ckks_evaluator.decryptor.decrypt(cipher1_inplace, subresult_inplace);
    vector<complex<double>> output_inplace;
    ckks_evaluator.encoder.decode(subresult_inplace, output_inplace);

    ASSERT_EQ(input1_vector.size(), output_inplace.size());
    for(size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real() - input2_vector[i].real(), output_inplace[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag() - input2_vector[i].imag(), output_inplace[i].imag(), EPSILON);
    }

    //sub_plain
    PhantomCiphertext cipher1_plain, dest_plain;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1_plain);
    ckks_evaluator.evaluator.sub_plain(cipher1_plain ,plain2, dest_plain); 

    PhantomPlaintext subresult_plain;
    ckks_evaluator.decryptor.decrypt(dest_plain, subresult_plain);

    vector<complex<double>> output_plain;
    ckks_evaluator.encoder.decode(subresult_plain, output_plain);

    ASSERT_EQ(input1_vector.size(), output_plain.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real() - input2_vector[i].real(), output_plain[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag() - input2_vector[i].imag(), output_plain[i].imag(), EPSILON);
    }

    //sub_plain_inplace
    PhantomCiphertext cipher1_plain_inplace;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1_plain_inplace);    
    
    ckks_evaluator.evaluator.sub_plain_inplace(cipher1_plain_inplace, plain2);

    PhantomPlaintext subresult_plain_inplace;
    ckks_evaluator.decryptor.decrypt(cipher1_plain_inplace, subresult_plain_inplace);

    vector<complex<double>> output_plain_inplace;
    ckks_evaluator.encoder.decode(subresult_plain_inplace, output_plain_inplace);

    ASSERT_EQ(input1_vector.size(), output_plain_inplace.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real() - input2_vector[i].real(), output_plain_inplace[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag() - input2_vector[i].imag(), output_plain_inplace[i].imag(), EPSILON);
    }

    //sub
    PhantomCiphertext cipher1_sub, cipher2_sub, dest_sub;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1_sub);
    ckks_evaluator.encryptor.encrypt(plain2, cipher2_sub);

    ckks_evaluator.evaluator.sub(cipher1_sub, cipher2_sub, dest_sub);

    PhantomPlaintext plain_sub;
    ckks_evaluator.decryptor.decrypt(dest_sub, plain_sub);
    vector<complex<double>> output_sub;
    ckks_evaluator.encoder.decode(plain_sub, output_sub);
    
    ASSERT_EQ(input1_vector.size(), output_sub.size());
    for (size_t i = 0; i < input1_vector.size(); i++){
        EXPECT_NEAR(input1_vector[i].real() - input2_vector[i].real(), output_sub[i].real(), EPSILON);
        EXPECT_NEAR(input1_vector[i].imag() - input2_vector[i].imag(), output_sub[i].imag(), EPSILON);
    }
}

namespace phantomtest{
    TEST(PhantomCKKSBasicOperationsTest, SubOperationTest1) {
        run_sub_test(65536, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, SubOperationTest2) {
        run_sub_test(8192, {60, 30, 30, 30, 60}, pow(2.0, 30));
    }

    TEST(PhantomCKKSBasicOperationsTest, SubOperationTest3) {
        run_sub_test(16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }

    TEST(PhantomCKKSBasicOperationsTest, SubOperationTest4) {
        run_sub_test(32768, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, SubOperationTest5) {
        run_sub_test(65536, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, SubOperationTest6) {
        run_sub_test(8192, {60, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, SubOperationTest7) {
        run_sub_test(16384, {50, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 50}, pow(2.0, 30));
    }

    TEST(PhantomCKKSBasicOperationsTest, SubOperationTest8) {
        run_sub_test(32768, {60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60}, pow(2.0, 60));
    }
    TEST(PhantomCKKSBasicOperationsTest, SubOperationTest9) {
        run_sub_test(8192, {30, 30, 30, 30}, pow(2.0, 30));
    }
    TEST(PhantomCKKSBasicOperationsTest, SubOperationTest10) {
        run_sub_test(32768, {30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30}, pow(2.0, 30));
    }
}

