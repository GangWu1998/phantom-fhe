    for(int j = 1; j < 5; j++){
    PhantomPlaintext plain1_convert, plain2_convert, plain3_convert, result1_convert, result2_convert, final_convert;
    cout<<"the chain_index of plain  are :" << plain1_convert.chain_index() << endl;
    ckks_evaluator.encoder.encode(input1, j, scale, plain1_convert);
    ckks_evaluator.encoder.decode(plain1_convert, result1_convert);
    ckks_evaluator.encoder.encode(result1_convert, j, scale, plain2_convert);
    ckks_evaluator.encoder.decode(plain2_convert, result2_convert);
    ckks_evaluator.encoder.encode(result2_convert, j, scale, plain3_convert);
    ckks_evaluator.encoder.decode(plain3_convert, final_convert);

    for (size_t i = 0; i < 4; ++i) {
        cout << input1[i] << "    " << result1_convert[i] << << "    " << result2_convert[i]<< "    " << final_convert[i]endl;
        }
    }