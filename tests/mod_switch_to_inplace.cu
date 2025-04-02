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

void run_modswitch_test(size_t poly_modulus_degree, const vector<int>& coeff_modulus, double scale){
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

    //multi_inplace
    PhantomCiphertext cipher_inplace;
    ckks_evaluator.encryptor.encrypt(plain, cipher_inplace);
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    ckks_evaluator.evaluator.mod_switch_to_inplace(cipher_inplace, 3);
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    //duration<double> sec = system_clock::now() - start;
    std::cout << "Sub Kernel execution time: " << elapsedTime * 1000 << " us" << std::endl;  

    PhantomPlaintext result_inplace;
    ckks_evaluator.decryptor.decrypt(cipher_inplace, result_inplace);
    vector<complex<double>> output_inplace;
    ckks_evaluator.encoder.decode(result_inplace, output_inplace);

    ASSERT_EQ(input_vector.size(), output_inplace.size());

    Eigen::VectorXcd input1_eigen = vectorToEigen(input_vector);
    Eigen::VectorXcd output_eigen = vectorToEigen(output_inplace);
    Eigen::VectorXd absolute_error = (input1_eigen - output_eigen).cwiseAbs();
    Eigen::VectorXd relative_error = absolute_error.cwiseQuotient(input1_eigen.cwiseAbs());
 
    double mse = (input1_eigen - output_eigen).squaredNorm() / input1_eigen.size();
    std::cout << "Sub Mean Squared Error (MSE): " << mse << std::endl;

    double max_error = absolute_error.maxCoeff();
    std::cout << "Sub Max Error: " << max_error << std::endl;

}

namespace phantomtest{
    TEST(PhantomCKKSBasicOperationsTest, ModSwitchOperationTest1) {
        run_modswitch_test(8192, {60, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, ModSwitchOperationTest2) {
        run_modswitch_test(8192, {50, 40, 40, 50}, pow(2.0, 40));
    }

    TEST(PhantomCKKSBasicOperationsTest, ModSwitchOperationTest3) {
        run_modswitch_test(16384, {60, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }

    TEST(PhantomCKKSBasicOperationsTest, ModSwitchOperationTest4) {
        run_modswitch_test(16384, {60, 45, 45, 45, 45, 45, 45, 45, 60}, pow(2.0, 45));
    }
    TEST(PhantomCKKSBasicOperationsTest, ModSwitchOperationTest5) {
        run_modswitch_test(16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }
    TEST(PhantomCKKSBasicOperationsTest, ModSwitchOperationTest6) {
        run_modswitch_test(32768, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60}, pow(2.0, 50));
    }
    TEST(PhantomCKKSBasicOperationsTest, ModSwitchOperationTest7) {
        run_modswitch_test(32768, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}, pow(2.0, 40));
    }

    TEST(PhantomCKKSBasicOperationsTest, ModSwitchOperationTest8) {
        run_modswitch_test(32768, {60, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 60}, pow(2.0, 60));
    }
    TEST(PhantomCKKSBasicOperationsTest, ModSwitchOperationTest9) {
        run_modswitch_test(65536, {60, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 60}, pow(2.0, 60));
    }
    TEST(PhantomCKKSBasicOperationsTest, ModSwitchOperationTest10) {
        run_modswitch_test(65536, {60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50,50, 60}, pow(2.0, 50));
    }
}

