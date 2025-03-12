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

vector<double> generate_random_vector(size_t size) {
    vector<double> result(size);
    random_device rd;
    mt19937 gen(rd());
    uniform_real_distribution<> dis(-1.0, 1.0);
    for (size_t i = 0; i < size; ++i) {
        result[i] = dis(gen);
    }
    return result;
}

TEST(PhantomCKKSBasicOperationsTest, Chain_Index_OperationTest){                
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(65536);
    parms.set_coeff_modulus(phantom::arith::CoeffModulus::Create(65536, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}));
    double scale = pow(2.0, 40);

    PhantomContext context(parms);
    PhantomCKKSEncoder encoder(context);
    PhantomSecretKey secret_key(context);
    PhantomPublicKey public_key = secret_key.gen_publickey(context);
    PhantomRelinKey relin_keys = secret_key.gen_relinkey(context);
    PhantomGaloisKey galois_keys;

    CKKSEvaluator ckks_evaluator(&context, &public_key, &secret_key, &encoder, &relin_keys, &galois_keys, scale);

    vector<double> input1 = generate_random_vector(encoder.slot_count());
    vector<double> input2 = generate_random_vector(encoder.slot_count());
    vector<double> input3 = generate_random_vector(encoder.slot_count());


    //multi_plain
    for(int j = 1; j < 5; j++){
    cout << "this is multi_plain operation :" << endl;
    PhantomPlaintext plain1_plain, plain2_plain, result_plain_plain;
    ckks_evaluator.encoder.encode(input2, j, scale, plain2_plain);
    cout<<"the chain_index of plain  are :" << plain1_plain.chain_index() << endl;
    PhantomCiphertext cipher1_plain, dest_plain;
    public_key.encrypt_asymmetric(context, plain1_plain, cipher1_plain);
    dest_plain = multiply_plain(context, cipher1_plain, plain2_plain);

    secret_key.decrypt(context, dest_plain, result_plain_plain);

    vector<double> output_plain;
    ckks_evaluator.encoder.decode(result_plain_plain, output_plain);

    for (size_t i = 0; i < 4; ++i) {
        double num = input1[i] * input2[i];
        cout << num << "    " << output_plain[i] << endl;
        }
    }

    cout << "\n" << endl;
    cout << "this is multi_inplace operation :" << endl;
    //multi_inplace
    for(int j = 1; j < 5; j++){
    PhantomPlaintext plain1_inplace, plain2_inplace, result_plain_inplace;
    ckks_evaluator.encoder.encode(input1, j, scale, plain1_inplace);
    ckks_evaluator.encoder.encode(input2, j, scale, plain2_inplace);
    cout<<"the chain_index of plain  are :" << plain1_inplace.chain_index() << endl;
    PhantomCiphertext cipher1_inplace, cipher2_inplace;
    public_key.encrypt_asymmetric(context, plain1_inplace, cipher1_inplace);
    public_key.encrypt_asymmetric(context, plain2_inplace, cipher2_inplace);

    multiply_inplace(context, cipher1_inplace, cipher2_inplace);
    rescale_to_next_inplace(context, cipher1_inplace);
    // multiply_inplace(context, cipher1_inplace, cipher2_inplace);
    // rescale_to_next_inplace(context, cipher1_inplace);
    // multiply_inplace(context, cipher1_inplace, cipher2_inplace);
    // rescale_to_next_inplace(context, cipher1_inplace);

    secret_key.decrypt(context, cipher1_inplace, result_plain_inplace);

    vector<double> output_inplace;
    ckks_evaluator.encoder.decode(result_plain_inplace, output_inplace);

    for (size_t i = 0; i < 4; ++i) {
        double num = input1[i] * input2[i] * input2[i] * input2[i];
        cout << num << "    " << output_inplace[i] << endl;
        }
    }

    cout << "\n" << endl;
    cout << "this is add_inplace operation :" << endl;
    //add_inplace
    for(int j = 1; j < 5; j++){
    PhantomPlaintext plain1_addinplace, plain2_addinplace, result_plain_addinplace;
    ckks_evaluator.encoder.encode(input1, j, scale, plain1_addinplace);
    ckks_evaluator.encoder.encode(input2, j, scale, plain2_addinplace);
    cout<<"the chain_index of plain  are :" << plain1_addinplace.chain_index() << endl;
    PhantomCiphertext cipher1_addinplace, cipher2_addinplace;
    public_key.encrypt_asymmetric(context, plain1_addinplace, cipher1_addinplace);
    public_key.encrypt_asymmetric(context, plain2_addinplace, cipher2_addinplace);

    add_inplace(context, cipher1_addinplace, cipher2_addinplace);
    add_inplace(context, cipher1_addinplace, cipher2_addinplace);
    add_inplace(context, cipher1_addinplace, cipher2_addinplace);

    secret_key.decrypt(context, cipher1_addinplace, result_plain_addinplace);

    vector<double> output_addinplace;
    ckks_evaluator.encoder.decode(result_plain_addinplace, output_addinplace);

    for (size_t i = 0; i < 4; ++i) {
        double num = input1[i] + input2[i] + input2[i] + input2[i];
        cout << num << "    " << output_addinplace[i] << endl;
        }
    }

    cout << "\n" << endl;
    cout << "this is add_plain operation :" << endl;
    //add_plain
    for(int j = 1; j < 5; j++){
    PhantomPlaintext plain1_addplain, plain2_addplain, result_plain_addplain;
    ckks_evaluator.encoder.encode(input1, j, scale, plain1_addplain);
    ckks_evaluator.encoder.encode(input2, j, scale, plain2_addplain);
    cout<<"the chain_index of plain  are :" << plain1_addplain.chain_index() << endl;
    PhantomCiphertext cipher1_addplain, dest_addplain;
    public_key.encrypt_asymmetric(context, plain1_addplain, cipher1_addplain);
    //public_key.encrypt_asymmetric(context, plain2_addplain, cipher2_addplain);

    dest_addplain = add_plain(context, cipher1_addplain, plain2_addplain);

    secret_key.decrypt(context, dest_addplain, result_plain_addplain);

    vector<double> output_addplain;
    ckks_evaluator.encoder.decode(result_plain_addplain, output_addplain);

    for (size_t i = 0; i < 4; ++i) {
        double num = input1[i] + input2[i];
        cout << num << "    " << output_addplain[i] << endl;
        }
    }

    cout << "\n" << endl;
    cout << "this is add_plain_inplace operation :" << endl;
    //add_plain_inplace
    for(int j = 1; j < 5; j++){
    PhantomPlaintext plain1_addplain_inplace, plain2_addplain_inplace, result_plain_addplain_inplace;
    ckks_evaluator.encoder.encode(input1, j, scale, plain1_addplain_inplace);
    ckks_evaluator.encoder.encode(input2, j, scale, plain2_addplain_inplace);
    cout<<"the chain_index of plain  are :" << plain1_addplain_inplace.chain_index() << endl;
    PhantomCiphertext cipher1_addplain_inplace, dest_addplain_inplace;
    public_key.encrypt_asymmetric(context, plain1_addplain_inplace, cipher1_addplain_inplace);
    //public_key.encrypt_asymmetric(context, plain2_addplain_inplace, cipher2_addplain_inplace);

    add_plain_inplace(context, cipher1_addplain_inplace, plain2_addplain_inplace);

    secret_key.decrypt(context, cipher1_addplain_inplace, result_plain_addplain_inplace);

    vector<double> output_addplain_inplace;
    ckks_evaluator.encoder.decode(result_plain_addplain_inplace, output_addplain_inplace);

    for (size_t i = 0; i < 4; ++i) {
        double num = input1[i] + input2[i];
        cout << num << "    " << output_addplain_inplace[i] << endl;
        }
    }

    cout << "\n" << endl;
    cout << "this is add_many operation :" << endl;
    //add_many
    for(int j = 1; j < 5; j++){
    PhantomPlaintext plain1_addmany, plain2_addmany, plain3_addmany, result_plain_addmany;
    ckks_evaluator.encoder.encode(input1, j, scale, plain1_addmany);
    ckks_evaluator.encoder.encode(input2, j, scale, plain2_addmany);
    ckks_evaluator.encoder.encode(input3, j, scale, plain3_addmany);
    cout<<"the chain_index of plain  are :" << plain1_addmany.chain_index() << endl;
    PhantomCiphertext cipher1_addmany, cipher2_addmany, cipher3_addmany, dest_addmany;
    public_key.encrypt_asymmetric(context, plain1_addmany, cipher1_addmany);
    public_key.encrypt_asymmetric(context, plain2_addmany, cipher2_addmany);
    public_key.encrypt_asymmetric(context, plain3_addmany, cipher3_addmany);
    vector<PhantomCiphertext> cts = {cipher1_addmany, cipher2_addmany, cipher3_addmany};

    dest_addmany = add(context, cts[0], cts[1]);
    for (size_t i = 2; i < cts.size(); i++)
    {
        add_inplace(context, dest_addmany, cts[i]);
    }

    secret_key.decrypt(context, dest_addmany, result_plain_addmany);

    vector<double> output_addmany;
    ckks_evaluator.encoder.decode(result_plain_addmany, output_addmany);

    for (size_t i = 0; i < 4; ++i) {
        double num = input1[i] + input2[i] + input3[i];
        cout << num << "    " << output_addmany[i] << endl;
        }
    }

    cout << "\n" << endl;
    cout << "this is mod_switch operation :" << endl;
    //mod_switch
    for(int j = 1; j < 5; j++){
    PhantomPlaintext plain1_mod_switch, plain2_mod_switch, result_mod_switch;
    ckks_evaluator.encoder.encode(input1, j, scale, plain1_mod_switch);

    cout<<"the chain_index of plain  are :" << plain1_mod_switch.chain_index() << endl;
    PhantomCiphertext cipher1_mod_switch, dest_mod_switch;
    public_key.encrypt_asymmetric(context, plain1_mod_switch, cipher1_mod_switch);
    //public_key.encrypt_asymmetric(context, plain2_mod_switch, cipher2_mod_switch);

    mod_switch_to_next_inplace(context, cipher1_mod_switch);
    mod_switch_to_inplace(context, cipher1_mod_switch, j + 2);

    secret_key.decrypt(context, cipher1_mod_switch, result_mod_switch);
    //plain mod_switch
    mod_switch_to_inplace(context, result_mod_switch, j + 3);

    secret_key.decrypt(context, cipher1_mod_switch, result_mod_switch);

    vector<double> output_mod_switch;
    ckks_evaluator.encoder.decode(result_mod_switch, output_mod_switch);

    for (size_t i = 0; i < 4; ++i) {
        cout << input1[i] << "    " << output_mod_switch[i] << endl;
        }
    }

    cout << "\n" << endl;
    cout << "this is mod_switch operation :" << endl;
    //convert
    for(int j = 1; j < 5; j++){
    PhantomPlaintext plain1_convert, plain2_convert, plain3_convert;
    vector<double>  result1_convert, result2_convert, final_convert;
    ckks_evaluator.encoder.encode(input1, j, scale, plain1_convert);
    cout<<"the chain_index of plain  are :" << plain1_convert.chain_index() << endl;
    ckks_evaluator.encoder.decode(plain1_convert, result1_convert);
    ckks_evaluator.encoder.encode(result1_convert, j, scale, plain2_convert);
    ckks_evaluator.encoder.decode(plain2_convert, result2_convert);
    ckks_evaluator.encoder.encode(result2_convert, j, scale, plain3_convert);
    ckks_evaluator.encoder.decode(plain3_convert, final_convert);

    for (size_t i = 0; i < 4; ++i) {
        cout << input1[i] << "    " << result1_convert[i] << "    " << result2_convert[i]<< "    " << final_convert[i] << endl;
        }
    }
}