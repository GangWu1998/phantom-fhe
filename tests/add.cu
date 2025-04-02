#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include "phantom.h"
#include "boot/Bootstrapper.cuh"
#include <vector>
#include <cmath>
#include <random>
#include <memory>
#include <Eigen/Dense>

using namespace phantom;
using namespace phantom::arith;
using namespace phantom::util;
using namespace std;

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
Eigen::VectorXcd vectorToEigen(const std::vector<std::complex<double>>& v) {
    Eigen::VectorXcd ev(v.size());
    for (size_t i = 0; i < v.size(); ++i) {
        ev[i] = v[i];
    }
    return ev;
}

void run_add_test(size_t poly_modulus_degree, const vector<int>& coeff_modulus, double scale){
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
    vector<complex<double>> input3_vector = generate_random_vector(slots);

    PhantomPlaintext plain1, plain2, plain3;
    ckks_evaluator.encoder.encode(input1_vector, scale, plain1);
    ckks_evaluator.encoder.encode(input2_vector, scale, plain2);
    ckks_evaluator.encoder.encode(input3_vector, scale, plain3);

    //add
    PhantomCiphertext cipher1_add, cipher2_add, dest_add;
    ckks_evaluator.encryptor.encrypt(plain1, cipher1_add);
    ckks_evaluator.encryptor.encrypt(plain2, cipher2_add);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    ckks_evaluator.evaluator.add(cipher1_add, cipher2_add, dest_add);
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    //duration<double> sec = system_clock::now() - start;
    std::cout << "Add Kernel execution time: " << elapsedTime << " ms" << std::endl;  

    PhantomPlaintext plain_add;
    ckks_evaluator.decryptor.decrypt(dest_add, plain_add);
    vector<complex<double>> output_add;
    ckks_evaluator.encoder.decode(plain_add, output_add);
    
    ASSERT_EQ(input1_vector.size(), output_add.size());

    vector<complex<double>> input_vector(input1_vector.size()); 
    for(size_t i = 0; i < input1_vector.size(); i++){
        input_vector[i] = input1_vector[i] + input2_vector[i];
    }
    Eigen::VectorXcd input1_eigen = vectorToEigen(input_vector);
    Eigen::VectorXcd output_eigen = vectorToEigen(output_add);
    Eigen::VectorXd absolute_error = (input1_eigen - output_eigen).cwiseAbs();
    Eigen::VectorXd relative_error = absolute_error.cwiseQuotient(input1_eigen.cwiseAbs());
 
    double mse = (input1_eigen - output_eigen).squaredNorm() / input1_eigen.size();
    std::cout << "Add Mean Squared Error (MSE): " << mse << std::endl;

    // 计算最大误差
    double max_error = absolute_error.maxCoeff();
    std::cout << "Add Max Error: " << max_error << std::endl;
}

namespace phantomtest{
    TEST(PhantomCKKSBasicOperationsTest, AddOperationTest1) {
        run_add_test(8192, {60, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, AddOperationTest2) {
        run_add_test(8192, {50, 40, 40, 50}, pow(2.0, 40));
    }

    TEST(PhantomCKKSBasicOperationsTest, AddOperationTest3) {
        run_add_test(16384, {60, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }

    TEST(PhantomCKKSBasicOperationsTest, AddOperationTest4) {
        run_add_test(16384, {60, 45, 45, 45, 45, 45, 45, 45, 60}, pow(2.0, 45));
    }
    TEST(PhantomCKKSBasicOperationsTest, AddOperationTest5) {
        run_add_test(16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, AddOperationTest6) {
        run_add_test(32768, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, AddOperationTest7) {
        run_add_test(32768, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }

    TEST(PhantomCKKSBasicOperationsTest, AddOperationTest8) {
        run_add_test(32768, {60, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 60}, pow(2.0, 60));
    }
    TEST(PhantomCKKSBasicOperationsTest, AddOperationTest9) {
        run_add_test(65536, {60, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 60}, pow(2.0, 60));
    }
    TEST(PhantomCKKSBasicOperationsTest, AddOperationTest10) {
        run_add_test(65536, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50,50, 60}, pow(2.0, 50));
    }
}

