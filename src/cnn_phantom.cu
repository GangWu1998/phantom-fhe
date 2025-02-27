#include "cnn_phantom.h"

TensorCipher::TensorCipher()
{
	k_ = 0;
	h_ = 0;
	w_ = 0;
	c_ = 0;
	t_ = 0;
	p_ = 0;
}
TensorCipher::TensorCipher(int logn, int k, int h, int w, int c, int t, int p, vector<double> data, CKKSEvaluator &evaluator, int logp)
{
	if (k != 1)
		throw std::invalid_argument("supported k is only 1 right now");

	// 1 <= logn <= 16
	if (logn < 1 || logn > 16)
		throw std::out_of_range("the value of logn is out of range");
	if (data.size() > static_cast<long unsigned int>(1 << logn))
		throw std::out_of_range("the size of data is larger than n");

	this->k_ = k;
	this->h_ = h;
	this->w_ = w;
	this->c_ = c;
	this->t_ = t;
	this->p_ = p;
	this->logn_ = logn;

	// generate vector that contains data
	vector<double> vec;
	for (int i = 0; i < static_cast<int>(data.size()); i++)
		vec.emplace_back(data[i]);
	for (int i = data.size(); i < 1 << logn; i++)
		vec.emplace_back(0); // zero padding

	// vec size = n
	if (vec.size() != static_cast<long unsigned int>(1 << logn))
		throw std::out_of_range("the size of vec is not n");

	// encode & encrypt
	PhantomPlaintext plain;
	PhantomCiphertext cipher;
	double scale = pow(2.0, logp);
	evaluator.encoder.encode(vec, scale, plain);
	evaluator.encryptor.encrypt(plain, cipher);
	this->set_ciphertext(cipher);
}
TensorCipher::TensorCipher(int logn, int k, int h, int w, int c, int t, int p, PhantomCiphertext cipher)
{
	this->k_ = k;
	this->h_ = h;
	this->w_ = w;
	this->c_ = c;
	this->t_ = t;
	this->p_ = p;
	this->logn_ = logn;
	this->cipher_ = cipher;
}
int TensorCipher::k() const
{
	return k_;
}
int TensorCipher::h() const
{
	return h_;
}
int TensorCipher::w() const
{
	return w_;
}
int TensorCipher::c() const
{
	return c_;
}
int TensorCipher::t() const
{
	return t_;
}
int TensorCipher::p() const
{
	return p_;
}
int TensorCipher::logn() const
{
	return logn_;
}
PhantomCiphertext TensorCipher::cipher() const
{
	return cipher_;
}
void TensorCipher::set_ciphertext(PhantomCiphertext cipher)
{
	cipher_ = cipher;
}
void TensorCipher::print_parms()
{
	cout << "k: " << k_ << endl;
	cout << "h: " << h_ << endl;
	cout << "w: " << w_ << endl;
	cout << "c: " << c_ << endl;
	cout << "t: " << t_ << endl;
	cout << "p: " << p_ << endl;
}
// void multiplexed_parallel_convolution_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw, const vector<double> &data, vector<double> running_var, vector<double> constant_weight, double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, Evaluator &evaluator, GaloisKeys &gal_keys, vector<PhantomCiphertext> &cipher_pool, ofstream &output, Decryptor &decryptor, SEALContext &context, size_t stage, bool end)
void multiplexed_parallel_convolution_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw, const vector<double> &data, vector<double> running_var, vector<double> constant_weight, double epsilon, CKKSEvaluator &ckksevaluator, vector<PhantomCiphertext> &cipher_pool, ofstream &output, size_t stage, bool end)
{
	cout << "multiplexed parallel convolution..." << endl;
	output << "multiplexed parallel convolution..." << endl;
	int logn = cnn_in.logn();
	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;

	time_start = chrono::high_resolution_clock::now();
	// convolution_seal_sparse(cnn_in, cnn_out, hprime, st, kernel, false, data, running_var, constant_weight, epsilon, encoder, encryptor, scale_evaluator, gal_keys, cipher_pool, end);
	multiplexed_parallel_convolution_phantom(cnn_in, cnn_out, co, st, fh, fw, data, running_var, constant_weight, epsilon, ckksevaluator, cipher_pool, end);
	time_end = chrono::high_resolution_clock::now();
	time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
	cout << "time : " << time_diff.count() / 1000 << " ms" << endl;
	// cout << "convolution " << stage << " result" << endl;
	output << "time : " << time_diff.count() / 1000 << " ms" << endl;
	// output << "convolution " << stage << " result" << endl;
	auto decry_and_print_temp = cnn_out.cipher();
	decrypt_and_print(decry_and_print_temp, ckksevaluator, 1 << logn, 256, 2);
	cnn_out.print_parms();
	// decrypt_and_print_txt(cnn_out.cipher(), decryptor, encoder, 1<<logn, 256, 2, output); cnn_out.print_parms();
	cout << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	cout << "scale: " << cnn_out.cipher().scale() << endl
		 << endl;
	output << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	output << "scale: " << cnn_out.cipher().scale() << endl
		   << endl;
}
void multiplexed_parallel_batch_norm_phantom_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> bias, vector<double> running_mean, vector<double> running_var, vector<double> weight, double epsilon, CKKSEvaluator &ckksevaluator, double B, ofstream &output, size_t stage, bool end)
{
	cout << "multiplexed parallel batch normalization..." << endl;
	output << "multiplexed parallel batch normalization..." << endl;
	int logn = cnn_in.logn();
	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;

	// batch norm
	time_start = chrono::high_resolution_clock::now();
	multiplexed_parallel_batch_norm_phantom(cnn_in, cnn_out, bias, running_mean, running_var, weight, epsilon, ckksevaluator, B, end);
	time_end = chrono::high_resolution_clock::now();
	time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
	cout << "time : " << time_diff.count() / 1000 << " ms" << endl;
	// cout << "batch normalization " << stage << " result" << endl;
	output << "time : " << time_diff.count() / 1000 << " ms" << endl;
	// output << "batch normalization " << stage << " result" << endl;
	auto decry_and_print_temp = cnn_out.cipher();
	decrypt_and_print(decry_and_print_temp, ckksevaluator, 1 << logn, 256, 2);
	cnn_out.print_parms();
	// decrypt_and_print_txt(cnn_out.cipher(), decryptor, encoder, 1<<logn, 256, 2, output); cnn_out.print_parms();
	cout << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	cout << "scale: " << cnn_out.cipher().scale() << endl
		 << endl;
	output << "remaining level : " << cnn_out.cipher().chain_index()<< endl;
	output << "scale: " << cnn_out.cipher().scale() << endl
		   << endl;
}
void approx_ReLU_phantom_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no, vector<int> deg, long alpha, vector<Tree> &tree, double scaled_val, long scalingfactor, CKKSEvaluator &ckksevaluator, double B, ofstream &output, size_t stage)
{
	cout << "approximate ReLU..." << endl;
	output << "approximate ReLU..." << endl;
	int logn = cnn_in.logn();
	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;

	time_start = chrono::high_resolution_clock::now();
	ReLU_phantom(cnn_in, cnn_out, comp_no, deg, alpha, tree, scaled_val, scalingfactor, ckksevaluator, B);
	// ReLU_remove_imaginary_seal(cnn_in, cnn_out, comp_no, deg, alpha, tree, scaled_val, scalingfactor, encryptor, evaluator, scale_evaluator, decryptor, encoder, public_key, secret_key, relin_keys, output, gal_keys, B);
	time_end = chrono::high_resolution_clock::now();
	time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
	cout << "time : " << time_diff.count() / 1000 << " ms" << endl;
	// cout << "ReLU function " << stage << " result" << endl;
	output << "time : " << time_diff.count() / 1000 << " ms" << endl;
	// output << "ReLU function " << stage << " result" << endl;
	auto decry_and_print_temp = cnn_out.cipher();
	decrypt_and_print(decry_and_print_temp, ckksevaluator, 1 << logn, 256, 2);
	cnn_out.print_parms();
	// decrypt_and_print_txt(cnn_out.cipher(), decryptor, encoder, 1<<logn, 256, 2, output); cnn_out.print_parms();
	cout << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	cout << "scale: " << cnn_out.cipher().scale() << endl
		 << endl;
	output << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	output << "scale: " << cnn_out.cipher().scale() << endl
		   << endl;

	cout << "intermediate decrypted values: " << endl;
	output << "intermediate decrypted values: " << endl;
	decry_and_print_temp = cnn_out.cipher();
	decrypt_and_print_txt(decry_and_print_temp, ckksevaluator, 1 << logn, 4, 1, output); // cnn_out.print_parms();
}
void bootstrap_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, Bootstrapper &bootstrapper, CKKSEvaluator &ckksevaluator, ofstream &output, size_t stage)
{
	cout << "bootstrapping..." << endl;
	output << "bootstrapping..." << endl;
	PhantomCiphertext ctxt, rtn;
	int logn = cnn_in.logn();
	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;

	ctxt = cnn_in.cipher();
	time_start = chrono::high_resolution_clock::now();
	// bootstrapper.bootstrap_3(rtn, ctxt);
	bootstrapper.bootstrap_real_3(rtn, ctxt);
	time_end = chrono::high_resolution_clock::now();
	time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
	cout << "time : " << time_diff.count() / 1000 << " ms" << endl;
	output << "time : " << time_diff.count() / 1000 << " ms" << endl;
	cnn_out.set_ciphertext(rtn);
	cout << "bootstrapping " << stage << " result" << endl;
	output << "bootstrapping " << stage << " result" << endl;
	auto decry_and_print_temp = cnn_out.cipher();
	decrypt_and_print(decry_and_print_temp, ckksevaluator, 1 << logn, 256, 2);
	cnn_out.print_parms();
	// decrypt_and_print_txt(cnn_out.cipher(), decryptor, encoder, 1<<logn, 256, 2, output); cnn_out.print_parms();
	cout << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	cout << "scale: " << cnn_out.cipher().scale() << endl
		 << endl;
	output << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	output << "scale: " << cnn_out.cipher().scale() << endl
		   << endl;
}


void multiplexed_parallel_downsampling_phantom_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, CKKSEvaluator &ckksevaluator, ofstream &output)
{
	cout << "multiplexed parallel downsampling..." << endl;
	output << "multiplexed parallel downsampling..." << endl;
	int logn = cnn_in.logn();
	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;

	time_start = chrono::high_resolution_clock::now();
	multiplexed_parallel_downsampling_phantom(cnn_in, cnn_out, ckksevaluator);
	time_end = chrono::high_resolution_clock::now();
	time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
	cout << "time : " << time_diff.count() / 1000 << " ms" << endl;
	output << "time : " << time_diff.count() / 1000 << " ms" << endl;
	auto decry_and_print_temp = cnn_out.cipher();
	decrypt_and_print(decry_and_print_temp, ckksevaluator, 1 << logn, 256, 2);
	cnn_out.print_parms();
	// decrypt_and_print_txt(cnn_out.cipher(), decryptor, encoder, 1<<logn, 256, 2, output); cnn_out.print_parms();
	cout << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	cout << "scale: " << cnn_out.cipher().scale() << endl
		 << endl;
	output << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	output << "scale: " << cnn_out.cipher().scale() << endl
		   << endl;
}
void averagepooling_phantom_scale_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, CKKSEvaluator &ckksevaluator, double B, ofstream &output)
{
	cout << "average pooling..." << endl;
	output << "average pooling..." << endl;
	int logn = cnn_in.logn();
	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;

	time_start = chrono::high_resolution_clock::now();
	// averagepooling_seal_scale(cnn_in, cnn_out, scale_evaluator, gal_keys, B);
	averagepooling_phantom_scale(cnn_in, cnn_out, ckksevaluator, B, output);
	time_end = chrono::high_resolution_clock::now();
	time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
	cout << "time : " << time_diff.count() / 1000 << " ms" << endl;
	output << "time : " << time_diff.count() / 1000 << " ms" << endl;
	auto decry_and_print_temp = cnn_out.cipher();
	decrypt_and_print(decry_and_print_temp, ckksevaluator, 1 << logn, 256, 2);
	cnn_out.print_parms();
	// decrypt_and_print_txt(cnn_out.cipher(), decryptor, encoder, 1<<logn, 256, 2, output); cnn_out.print_parms();
	cout << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	cout << "scale: " << cnn_out.cipher().scale() << endl
		 << endl;
	output << "remaining level : " << cnn_out.cipher().chain_index()<< endl;
	output << "scale: " << cnn_out.cipher().scale() << endl
		   << endl;
}
void fully_connected_phantom_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> matrix, vector<double> bias, int q, int r, CKKSEvaluator &ckksevaluator, ofstream &output)
{
	cout << "fully connected layer..." << endl;
	output << "fully connected layer..." << endl;
	int logn = cnn_in.logn();
	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;

	time_start = chrono::high_resolution_clock::now();
	matrix_multiplication_phantom(cnn_in, cnn_out, matrix, bias, q, r,ckksevaluator);
	time_end = chrono::high_resolution_clock::now();
	time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
	cout << "time : " << time_diff.count() / 1000 << " ms" << endl;
	output << "time : " << time_diff.count() / 1000 << " ms" << endl;
	auto decry_and_print_temp = cnn_out.cipher();
	decrypt_and_print(decry_and_print_temp, ckksevaluator, 1 << logn, 256, 2);
	cnn_out.print_parms();
	// decrypt_and_print_txt(cnn_out.cipher(), decryptor, encoder, 1<<logn, 256, 2, output); cnn_out.print_parms();
	cout << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	cout << "scale: " << cnn_out.cipher().scale() << endl
		 << endl;
	output << "remaining level : " << cnn_out.cipher().chain_index() << endl;
	output << "scale: " << cnn_out.cipher().scale() << endl
		   << endl;
}
// void multiplexed_parallel_convolution_phantom(const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw, const vector<double> &data, vector<double> running_var, vector<double> constant_weight, double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, Evaluator &evaluator, GaloisKeys &gal_keys, vector<PhantomCiphertext> &cipher_pool, bool end)
void multiplexed_parallel_convolution_phantom(const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw, const vector<double> &data, vector<double> running_var, vector<double> constant_weight, double epsilon, CKKSEvaluator &ckksevaluator, vector<PhantomCiphertext> &cipher_pool, bool end)
{
	// set parameters
	vector<double> conv_data;
	int ki = cnn_in.k(), hi = cnn_in.h(), wi = cnn_in.w(), ci = cnn_in.c(), ti = cnn_in.t(), pi = cnn_in.p(), logn = cnn_in.logn();
	int ko = 0, ho = 0, wo = 0, to = 0, po = 0;

	// error check
	if (st != 1 && st != 2)
		throw invalid_argument("supported st is only 1 or 2"); // check if st is 1 or 2
	if (static_cast<int>(data.size()) != fh * fw * ci * co)
		throw std::invalid_argument("the size of data vector is not ker x ker x h x h"); // check if the size of data vector is kernel x kernel x h x h'
	if (log2_long(ki) == -1)
		throw std::invalid_argument("ki is not power of two");

	if (static_cast<int>(running_var.size()) != co || static_cast<int>(constant_weight.size()) != co)
		throw std::invalid_argument("the size of running_var or weight is not correct");
	for (auto num : running_var)
		if (num < pow(10, -16) && num > -pow(10, -16))
			throw std::invalid_argument("the size of running_var is too small. nearly zero.");

	// set ho, wo, ko
	if (st == 1)
	{
		ho = hi;
		wo = wi;
		ko = ki;
	}
	else if (st == 2)
	{
		if (hi % 2 == 1 || wi % 2 == 1)
			throw std::invalid_argument("hi or wi is not even");
		ho = hi / 2;
		wo = wi / 2;
		ko = 2 * ki;
	}

	// set to, po, q
	long n = 1 << logn;
	to = (co + ko * ko - 1) / (ko * ko);
	po = pow2(floor_to_int(log(static_cast<double>(n) / static_cast<double>(ko * ko * ho * wo * to)) / log(2.0)));
	long q = (co + pi - 1) / pi;

	// check if pi, po | n
	if (n % pi != 0)
		throw std::out_of_range("n is not divisible by pi");
	if (n % po != 0)
		throw std::out_of_range("n is not divisible by po");

	// check if ki^2 hi wi ti pi <= n and ko^2 ho wo to po <= n
	if (ki * ki * hi * wi * ti * pi > n)
		throw std::out_of_range("ki^2 hi wi ti pi is larger than n");
	if (ko * ko * ho * wo * to * po > (1 << logn))
		throw std::out_of_range("ko^2 ho wo to po is larger than n");

	// variable
	vector<vector<vector<vector<double>>>> weight(fh, vector<vector<vector<double>>>(fw, vector<vector<double>>(ci, vector<double>(co, 0.0))));			  // weight tensor
	vector<vector<vector<vector<double>>>> compact_weight_vec(fh, vector<vector<vector<double>>>(fw, vector<vector<double>>(q, vector<double>(n, 0.0)))); // multiplexed parallel shifted weight tensor
	vector<vector<vector<vector<double>>>> select_one(co, vector<vector<vector<double>>>(ko * ho, vector<vector<double>>(ko * wo, vector<double>(to, 0.0))));
	vector<vector<double>> select_one_vec(co, vector<double>(1 << logn, 0.0));

	// weight setting
	for (int i1 = 0; i1 < fh; i1++)
	{
		for (int i2 = 0; i2 < fw; i2++)
		{
			for (int j3 = 0; j3 < ci; j3++)
			{
				for (int j4 = 0; j4 < co; j4++)
				{
					weight[i1][i2][j3][j4] = data[fh * fw * ci * j4 + fh * fw * j3 + fw * i1 + i2];
				}
			}
		}
	}

	// compact shifted weight vector setting
	for (int i1 = 0; i1 < fh; i1++)
	{
		for (int i2 = 0; i2 < fw; i2++)
		{
			for (int i9 = 0; i9 < q; i9++)
			{
				for (int j8 = 0; j8 < n; j8++)
				{
					int j5 = ((j8 % (n / pi)) % (ki * ki * hi * wi)) / (ki * wi), j6 = (j8 % (n / pi)) % (ki * wi), i7 = (j8 % (n / pi)) / (ki * ki * hi * wi), i8 = j8 / (n / pi);
					if (j8 % (n / pi) >= ki * ki * hi * wi * ti || i8 + pi * i9 >= co || ki * ki * i7 + ki * (j5 % ki) + j6 % ki >= ci || (j6 / ki) - (fw - 1) / 2 + i2 < 0 || (j6 / ki) - (fw - 1) / 2 + i2 > wi - 1 || (j5 / ki) - (fh - 1) / 2 + i1 < 0 || (j5 / ki) - (fh - 1) / 2 + i1 > hi - 1)
						compact_weight_vec[i1][i2][i9][j8] = 0.0;
					else
					{
						compact_weight_vec[i1][i2][i9][j8] = weight[i1][i2][ki * ki * i7 + ki * (j5 % ki) + j6 % ki][i8 + pi * i9];
					}
				}
			}
		}
	}

	// select one setting
	for (int j4 = 0; j4 < co; j4++)
	{
		for (int v1 = 0; v1 < ko * ho; v1++)
		{
			for (int v2 = 0; v2 < ko * wo; v2++)
			{
				for (int u3 = 0; u3 < to; u3++)
				{
					if (ko * ko * u3 + ko * (v1 % ko) + v2 % ko == j4)
						select_one[j4][v1][v2][u3] = constant_weight[j4] / sqrt(running_var[j4] + epsilon);
					else
						select_one[j4][v1][v2][u3] = 0.0;
				}
			}
		}
	}

	// select one vector setting
	for (int j4 = 0; j4 < co; j4++)
	{
		for (int v1 = 0; v1 < ko * ho; v1++)
		{
			for (int v2 = 0; v2 < ko * wo; v2++)
			{
				for (int u3 = 0; u3 < to; u3++)
				{
					select_one_vec[j4][ko * ko * ho * wo * u3 + ko * wo * v1 + v2] = select_one[j4][v1][v2][u3];
				}
			}
		}
	}

	// PhantomCiphertext variables
	PhantomCiphertext *ctxt_in = &cipher_pool[0], *ct_zero = &cipher_pool[1], *temp = &cipher_pool[2], *sum = &cipher_pool[3], *total_sum = &cipher_pool[4], *var = &cipher_pool[5];

	// PhantomCiphertext input
	*ctxt_in = cnn_in.cipher();

	// rotated input precomputation
	vector<vector<PhantomCiphertext *>> ctxt_rot(fh, vector<PhantomCiphertext *>(fw));
	// if(fh != 3 || fw != 3) throw std::invalid_argument("fh and fw should be 3");
	if (fh % 2 == 0 || fw % 2 == 0)
		throw std::invalid_argument("fh and fw should be odd");
	for (int i1 = 0; i1 < fh; i1++)
	{
		for (int i2 = 0; i2 < fw; i2++)
		{
			if (i1 == (fh - 1) / 2 && i2 == (fw - 1) / 2)
				ctxt_rot[i1][i2] = ctxt_in; // i1=(fh-1)/2, i2=(fw-1)/2 means ctxt_in
			else if ((i1 == (fh - 1) / 2 && i2 > (fw - 1) / 2) || i1 > (fh - 1) / 2)
				ctxt_rot[i1][i2] = &cipher_pool[6 + fw * i1 + i2 - 1];
			else
				ctxt_rot[i1][i2] = &cipher_pool[6 + fw * i1 + i2];
		}
	}
	// ctxt_rot[0][0] = &cipher_pool[6];	ctxt_rot[0][1] = &cipher_pool[7];	ctxt_rot[0][2] = &cipher_pool[8];
	// ctxt_rot[1][0] = &cipher_pool[9];	ctxt_rot[1][1] = ctxt_in;			ctxt_rot[1][2] = &cipher_pool[10];		// i1=1, i2=1 means ctxt_in
	// ctxt_rot[2][0] = &cipher_pool[11];	ctxt_rot[2][1] = &cipher_pool[12];	ctxt_rot[2][2] = &cipher_pool[13];
	for (int i1 = 0; i1 < fh; i1++)
	{
		for (int i2 = 0; i2 < fw; i2++)
		{
			*ctxt_rot[i1][i2] = *ctxt_in;
			memory_save_rotate(*ctxt_rot[i1][i2], *ctxt_rot[i1][i2], ki * ki * wi * (i1 - (fh - 1) / 2) + ki * (i2 - (fw - 1) / 2), ckksevaluator);
		}
	}

	// generate zero PhantomCiphertext
	vector<double> zero(1 << logn, 0.0);
	PhantomPlaintext plain;
	ckksevaluator.encoder.encode(zero, ctxt_in->scale(), plain);
	ckksevaluator.encryptor.encrypt(plain, *ct_zero); // ct_zero: original scaling factor

	for (int i9 = 0; i9 < q; i9++)
	{
		// weight multiplication
		// cout << "multiplication by filter coefficients" << endl;
		for (int i1 = 0; i1 < fh; i1++)
		{
			for (int i2 = 0; i2 < fw; i2++)
			{
				// *temp = *ctxt_in;
				// memory_save_rotate(*temp, *temp, k*k*l*(i1-(kernel-1)/2) + k*(i2-(kernel-1)/2), scale_evaluator, gal_keys);
				// scale_evaluator.multiply_vector_inplace_scaleinv(*temp, compact_weight_vec[i1][i2][i9]);		// temp: double scaling factor
				// evaluator.multiply_vector_reduced_error(*ctxt_rot[i1][i2], compact_weight_vec[i1][i2][i9], *temp);		// temp: double scaling factor
				ckksevaluator.evaluator.multiply_vector_reduced_error(*ctxt_rot[i1][i2], compact_weight_vec[i1][i2][i9], *temp);
				if (i1 == 0 && i2 == 0)
					*sum = *temp; // sum: double scaling factor
				else
					ckksevaluator.evaluator.add_inplace_reduced_error(*sum, *temp);
			}
		}
		ckksevaluator.evaluator.rescale_to_next_inplace(*sum);
		*var = *sum;

		// summation for all input channels
		// cout << "summation for all input channels" << endl;
		int d = log2_long(ki), c = log2_long(ti);
		for (int x = 0; x < d; x++)
		{
			*temp = *var;
			//	scale_evaluator.rotate_vector(temp, pow2(x), gal_keys, temp);
			memory_save_rotate(*temp, *temp, pow2(x), ckksevaluator);
			ckksevaluator.evaluator.add_inplace_reduced_error(*var, *temp);
		}
		for (int x = 0; x < d; x++)
		{
			*temp = *var;
			//	scale_evaluator.rotate_vector(temp, pow2(x)*k*l, gal_keys, temp);
			memory_save_rotate(*temp, *temp, pow2(x) * ki * wi, ckksevaluator);
			ckksevaluator.evaluator.add_inplace_reduced_error(*var, *temp);
		}
		if (c == -1)
		{
			*sum = *ct_zero;
			for (int x = 0; x < ti; x++)
			{
				*temp = *var;
				//	scale_evaluator.rotate_vector(temp, k*k*l*l*x, gal_keys, temp);
				memory_save_rotate(*temp, *temp, ki * ki * hi * wi * x, ckksevaluator);
				ckksevaluator.evaluator.add_inplace_reduced_error(*sum, *temp);
			}
			*var = *sum;
		}
		else
		{
			for (int x = 0; x < c; x++)
			{
				*temp = *var;
				//	scale_evaluator.rotate_vector(temp, pow2(x)*k*k*l*l, gal_keys, temp);
				memory_save_rotate(*temp, *temp, pow2(x) * ki * ki * hi * wi, ckksevaluator);
				ckksevaluator.evaluator.add_inplace_reduced_error(*var, *temp);
			}
		}

		// collecting valid values into one PhantomCiphertext.
		// cout << "collecting valid values into one PhantomCiphertext." << endl;
		for (int i8 = 0; i8 < pi && pi * i9 + i8 < co; i8++)
		{
			int j4 = pi * i9 + i8;
			if (j4 >= co)
				throw std::out_of_range("the value of j4 is out of range!");

			*temp = *var;
			memory_save_rotate(*temp, *temp, (n / pi) * (j4 % pi) - j4 % ko - (j4 / (ko * ko)) * ko * ko * ho * wo - ((j4 % (ko * ko)) / ko) * ko * wo, ckksevaluator);
			ckksevaluator.evaluator.multiply_vector_inplace_reduced_error(*temp, select_one_vec[j4]); // temp: double scaling factor
			if (i8 == 0 && i9 == 0)
				*total_sum = *temp; // total_sum: double scaling factor
			else
				ckksevaluator.evaluator.add_inplace_reduced_error(*total_sum, *temp);
		}
	}
	ckksevaluator.evaluator.rescale_to_next_inplace(*total_sum);
	*var = *total_sum;

	// po copies
	if (end == false)
	{
		// cout << "po copies" << endl;
		*sum = *ct_zero;
		for (int u6 = 0; u6 < po; u6++)
		{
			*temp = *var;
			memory_save_rotate(*temp, *temp, -u6 * (n / po), ckksevaluator);
			ckksevaluator.evaluator.add_inplace_reduced_error(*sum, *temp); // sum: original scaling factor.
		}
		*var = *sum;
	}

	cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, *var);
}
// void multiplexed_parallel_batch_norm_phantom(const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> bias, vector<double> running_mean, vector<double> running_var, vector<double> weight, double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, Evaluator &evaluator, double B, bool end)
void multiplexed_parallel_batch_norm_phantom(const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> bias, vector<double> running_mean, vector<double> running_var, vector<double> weight, double epsilon, CKKSEvaluator &ckksevaluator, double B, bool end)
{
	// parameter setting
	int ki = cnn_in.k(), hi = cnn_in.h(), wi = cnn_in.w(), ci = cnn_in.c(), ti = cnn_in.t(), pi = cnn_in.p(), logn = cnn_in.logn();
	int ko = ki, ho = hi, wo = wi, co = ci, to = ti, po = pi;

	// error check
	if (static_cast<int>(bias.size()) != ci || static_cast<int>(running_mean.size()) != ci || static_cast<int>(running_var.size()) != ci || static_cast<int>(weight.size()) != ci)
		throw std::invalid_argument("the size of bias, running_mean, running_var, or weight are not correct");
	for (auto num : running_var)
		if (num < pow(10, -16) && num > -pow(10, -16))
			throw std::invalid_argument("the size of running_var is too small. nearly zero.");
	if (hi * wi * ci > 1 << logn)
		throw std::invalid_argument("hi*wi*ci should not be larger than n");

	// generate g vector
	vector<double> g(1 << logn, 0.0);

	// set f value
	long n = 1 << logn;

	// check if pi | n
	if (n % pi != 0)
		throw std::out_of_range("n is not divisible by pi");

	// set g vector
	for (int v4 = 0; v4 < n; v4++)
	{
		int v1 = ((v4 % (n / pi)) % (ki * ki * hi * wi)) / (ki * wi), v2 = (v4 % (n / pi)) % (ki * wi), u3 = (v4 % (n / pi)) / (ki * ki * hi * wi);
		if (ki * ki * u3 + ki * (v1 % ki) + v2 % ki >= ci || v4 % (n / pi) >= ki * ki * hi * wi * ti)
			g[v4] = 0.0;
		else
		{
			int idx = ki * ki * u3 + ki * (v1 % ki) + v2 % ki;
			g[v4] = (running_mean[idx] * weight[idx] / sqrt(running_var[idx] + epsilon) - bias[idx]) / B;
		}
	}

	// encode & encrypt
	PhantomPlaintext plain;
	PhantomCiphertext cipher_g;
	PhantomCiphertext temp;
	temp = cnn_in.cipher();
	ckksevaluator.encoder.encode(g, temp.scale(), plain);
	ckksevaluator.encryptor.encrypt(plain, cipher_g);

	// batch norm
	ckksevaluator.evaluator.sub_inplace_reduced_error(temp, cipher_g);

	cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, temp);
}
// void ReLU_phantom(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no, vector<int> deg, long alpha, vector<Tree> &tree, double scaled_val, long scalingfactor, Encryptor &encryptor, Evaluator &evaluator, Decryptor &decryptor, CKKSEncoder &encoder, PublicKey &public_key, SecretKey &secret_key, RelinKeys &relin_keys, double scale)
void ReLU_phantom(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no, vector<int> deg, long alpha, vector<Tree> &tree, double scaled_val, long scalingfactor, CKKSEvaluator &ckksevaluator, double scale)
{
	// parameter setting
	int ki = cnn_in.k(), hi = cnn_in.h(), wi = cnn_in.w(), ci = cnn_in.c(), ti = cnn_in.t(), pi = cnn_in.p(), logn = cnn_in.logn();
	int ko = ki, ho = hi, wo = wi, co = ci, to = ti, po = pi;

	// error check
	if (hi * wi * ci > 1 << logn)
		throw std::invalid_argument("hi*wi*ci should not be larger than n");

	// ReLU
	PhantomCiphertext temp;
	temp = cnn_in.cipher();
	minimax_ReLU_phantom(comp_no, deg, alpha, tree, scaled_val, scalingfactor, ckksevaluator, temp, temp);

	cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, temp);
}
void cipher_add_phantom_print(const TensorCipher &cnn1, const TensorCipher &cnn2, TensorCipher &destination, CKKSEvaluator &ckksevaluator, ofstream &output)
{
	cout << "cipher add..." << endl;
	output << "cipher add..." << endl;
	int logn = cnn1.logn();
	cnn_add_phantom(cnn1, cnn2, destination, ckksevaluator);
	// cout << "cipher add result" << endl;
	auto decry_and_print_temp = destination.cipher();
	decrypt_and_print(decry_and_print_temp, ckksevaluator, 1 << logn, 256, 2);
	destination.print_parms();
	// decrypt_and_print_txt(cnn_out.cipher(), decryptor, encoder, 1<<logn, 256, 2, output); cnn_out.print_parms();
	cout << "remaining level : " << destination.cipher().chain_index() << endl;
	cout << "scale: " << destination.cipher().scale() << endl
		 << endl;
	output << "remaining level : " << destination.cipher().chain_index() << endl;
	output << "scale: " << destination.cipher().scale() << endl
		   << endl;
}
void cnn_add_phantom(const TensorCipher &cnn1, const TensorCipher &cnn2, TensorCipher &destination, CKKSEvaluator &ckksevaluator)
{
	// parameter setting
	int k1 = cnn1.k(), h1 = cnn1.h(), w1 = cnn1.w(), c1 = cnn1.c(), t1 = cnn1.t(), p1 = cnn1.p(), logn1 = cnn1.logn();
	int k2 = cnn2.k(), h2 = cnn2.h(), w2 = cnn2.w(), c2 = cnn2.c(), t2 = cnn2.t(), p2 = cnn2.p(), logn2 = cnn2.logn();

	// error check
	if (k1 != k2 || h1 != h2 || w1 != w2 || c1 != c2 || t1 != t2 || p1 != p2 || logn1 != logn2)
		throw std::invalid_argument("the parameters of cnn1 and cnn2 are not the same");

	// addition
	PhantomCiphertext temp1, temp2;
	temp1 = cnn1.cipher();
	temp2 = cnn2.cipher();
	ckksevaluator.evaluator.add_inplace_reduced_error(temp1, temp2);

	destination = TensorCipher(logn1, k1, h1, w1, c1, t1, p1, temp1);
}
void multiplexed_parallel_downsampling_phantom(const TensorCipher &cnn_in, TensorCipher &cnn_out, CKKSEvaluator &ckksevaluator)
{
	// parameter setting
	int ki = cnn_in.k(), hi = cnn_in.h(), wi = cnn_in.w(), ci = cnn_in.c(), ti = cnn_in.t(), pi = cnn_in.p(), logn = cnn_in.logn();
	int ko = 0, ho = 0, wo = 0, co = 0, to = 0, po = 0;

	// parameter setting
	long n = 1 << logn;
	ko = 2 * ki;
	ho = hi / 2;
	wo = wi / 2;
	to = ti / 2;
	co = 2 * ci;
	po = pow2(floor_to_int(log(static_cast<double>(n) / static_cast<double>(ko * ko * ho * wo * to)) / log(2.0)));

	// error check
	if (ti % 8 != 0)
		throw std::invalid_argument("ti is not multiple of 8");
	if (hi % 2 != 0)
		throw std::invalid_argument("hi is not even");
	if (wi % 2 != 0)
		throw std::invalid_argument("wi is not even");
	if (n % po != 0)
		throw std::out_of_range("n is not divisible by po"); // check if po | n

	// variables
	vector<vector<vector<double>>> select_one_vec(ki, vector<vector<double>>(ti, vector<double>(1 << logn, 0.0)));
	PhantomCiphertext ct, sum, temp;
	ct = cnn_in.cipher();

	// selecting tensor vector setting
	for (int w1 = 0; w1 < ki; w1++)
	{
		for (int w2 = 0; w2 < ti; w2++)
		{
			for (int v4 = 0; v4 < 1 << logn; v4++)
			{
				int j5 = (v4 % (ki * ki * hi * wi)) / (ki * wi), j6 = v4 % (ki * wi), i7 = v4 / (ki * ki * hi * wi);
				if (v4 < ki * ki * hi * wi * ti && (j5 / ki) % 2 == 0 && (j6 / ki) % 2 == 0 && (j5 % ki) == w1 && i7 == w2)
					select_one_vec[w1][w2][v4] = 1.0;
				else
					select_one_vec[w1][w2][v4] = 0.0;
			}
		}
	}

	for (int w1 = 0; w1 < ki; w1++)
	{
		for (int w2 = 0; w2 < ti; w2++)
		{
			temp = ct;
			ckksevaluator.evaluator.multiply_vector_inplace_reduced_error(temp, select_one_vec[w1][w2]);

			int w3 = ((ki * w2 + w1) % (2 * ko)) / 2, w4 = (ki * w2 + w1) % 2, w5 = (ki * w2 + w1) / (2 * ko);
			memory_save_rotate(temp, temp, ki * ki * hi * wi * w2 + ki * wi * w1 - ko * ko * ho * wo * w5 - ko * wo * w3 - ki * w4 - ko * ko * ho * wo * (ti / 8), ckksevaluator);
			if (w1 == 0 && w2 == 0)
				sum = temp;
			else
				ckksevaluator.evaluator.add_inplace_reduced_error(sum, temp);
		}
	}
	ckksevaluator.evaluator.rescale_to_next_inplace(sum); // added
	ct = sum;

	// for fprime packing
	sum = ct;
	for (int u6 = 1; u6 < po; u6++)
	{
		temp = ct;
		memory_save_rotate(temp, temp, -(n / po) * u6, ckksevaluator);
		ckksevaluator.evaluator.add_inplace_reduced_error(sum, temp);
	}
	ct = sum;

	cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, ct);
}

void averagepooling_phantom_scale(const TensorCipher &cnn_in, TensorCipher &cnn_out, CKKSEvaluator &ckksevaluator, double B, ofstream &output)
{
	// parameter setting
	int ki = cnn_in.k(), hi = cnn_in.h(), wi = cnn_in.w(), ci = cnn_in.c(), ti = cnn_in.t(), pi = cnn_in.p(), logn = cnn_in.logn();
	int ko = 1, ho = 1, wo = 1, co = ci, to = ti;

	if (log2_long(hi) == -1)
		throw std::invalid_argument("hi is not power of two");
	if (log2_long(wi) == -1)
		throw std::invalid_argument("wi is not power of two");

	PhantomCiphertext ct, temp, sum;
	ct = cnn_in.cipher();

	// sum_hiwi
	// cout << "sum hiwi" << endl;

	for (int x = 0; x < log2_long(wi); x++)
	{
		temp = ct;
		//	scale_evaluator.rotate_vector_inplace(temp, pow2(x)*k, gal_keys);
		memory_save_rotate(temp, temp, pow2(x) * ki, ckksevaluator);
		ckksevaluator.evaluator.add_inplace_reduced_error(ct, temp);
	}
	for (int x = 0; x < log2_long(hi); x++)
	{
		temp = ct;
		//	scale_evaluator.rotate_vector_inplace(temp, pow2(x)*k*k*l, gal_keys);
		memory_save_rotate(temp, temp, pow2(x) * ki * ki * wi, ckksevaluator);
		ckksevaluator.evaluator.add_inplace_reduced_error(ct, temp);
	}

	// cout << "sum l^2 results" << endl;
	// output << "sum l^2 results" << endl;
	// decrypt_and_print_txt(ct, decryptor, encoder, 1<<logn, 256, 2, output);

	// final
	// cout << "final" << endl;
	vector<double> select_one(1 << logn, 0.0), zero(1 << logn, 0.0);
	for (int s = 0; s < ki; s++)
	{
		for (int u = 0; u < ti; u++)
		{
			int p = ki * u + s;
			temp = ct;
			//	scale_evaluator.rotate_vector_inplace(temp, -p*k + k*k*l*l*u + k*l*s, gal_keys);
			memory_save_rotate(temp, temp, -p * ki + ki * ki * hi * wi * u + ki * wi * s,ckksevaluator);
			select_one = zero;
			// for(int i=0; i<k; i++) select_one[(k*u+s)*k+i] = 1.0 / static_cast<double>(l*l);
			for (int i = 0; i < ki; i++)
				select_one[(ki * u + s) * ki + i] = B / static_cast<double>(hi * wi);

				ckksevaluator.evaluator.multiply_vector_inplace_reduced_error(temp, select_one);
			if (u == 0 && s == 0)
				sum = temp; // double scaling factor
			else
			ckksevaluator.evaluator.add_inplace_reduced_error(sum, temp);
		}

		// cout << "final iteration results" << endl;
		// output << "final iteration results" << endl;
		// decrypt_and_print_txt(sum, decryptor, encoder, 1<<logn, 256, 2, output);
	}
	ckksevaluator.evaluator.rescale_to_next_inplace(sum);

	// cout << "rescaling results" << endl;
	// output << "rescaling results" << endl;
	// decrypt_and_print_txt(sum, decryptor, encoder, 1<<logn, 256, 2, output);

	cnn_out = TensorCipher(logn, ko, ho, wo, co, to, 1, sum);
}
void matrix_multiplication_phantom(const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> matrix, vector<double> bias, int q, int r, CKKSEvaluator &ckksevaluator)
{
	// parameter setting
	int ki = cnn_in.k(), hi = cnn_in.h(), wi = cnn_in.w(), ci = cnn_in.c(), ti = cnn_in.t(), pi = cnn_in.p(), logn = cnn_in.logn();
	int ko = ki, ho = hi, wo = wi, co = ci, to = ti, po = pi;

	if (static_cast<int>(matrix.size()) != q * r)
		throw std::invalid_argument("the size of matrix is not q*r");
	if (static_cast<int>(bias.size()) != q)
		throw std::invalid_argument("the size of bias is not q");

	// generate matrix and bias
	vector<vector<double>> W(q + r - 1, vector<double>(1 << logn, 0.0));
	vector<double> b(1 << logn, 0.0);

	for (int z = 0; z < q; z++)
		b[z] = bias[z];
	for (int i = 0; i < q; i++)
	{
		for (int j = 0; j < r; j++)
		{
			W[i - j + r - 1][i] = matrix[i * r + j];
			if (i - j + r - 1 < 0 || i - j + r - 1 >= q + r - 1)
				throw std::out_of_range("i-j+r-1 is out of range");
			if (i * r + j < 0 || i * r + j >= static_cast<int>(matrix.size()))
				throw std::out_of_range("i*r+j is out of range");
		}
	}

	// matrix multiplication
	PhantomCiphertext ct, temp, sum;
	ct = cnn_in.cipher();
	for (int s = 0; s < q + r - 1; s++)
	{
		temp = ct;
		//	scale_evaluator.rotate_vector_inplace(temp, r-1-s, gal_keys);
		memory_save_rotate(temp, temp, r - 1 - s, ckksevaluator);
		ckksevaluator.evaluator.multiply_vector_inplace_reduced_error(temp, W[s]);
		if (s == 0)
			sum = temp;
		else
		ckksevaluator.evaluator.add_inplace_reduced_error(sum, temp);
	}
	ckksevaluator.evaluator.rescale_to_next_inplace(sum);

	cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, sum);
}
void minimax_ReLU_phantom(long comp_no, vector<int> deg, long alpha, vector<Tree> &tree, double scaled_val, long scalingfactor, CKKSEvaluator &ckksevaluator, PhantomCiphertext &cipher_in, PhantomCiphertext &cipher_res)
{
	// variables
	vector<vector<double>> decomp_coeff(comp_no, vector<double>(0));
	vector<double> scale_val(comp_no, 0.0);
	PhantomPlaintext plain_half;
	PhantomCiphertext cipher_temp, cipher_half, cipher_x;

	// ifstream and scale
	string str;
	string addr = "../result";
	str = addr + "/d" + to_string(alpha) + ".txt";
	ifstream in(str);

	// scaled value setting
	scale_val[0] = 1.0;
	for (int i = 1; i < comp_no; i++)
		scale_val[i] = 2.0;
	scale_val[comp_no - 1] = scaled_val;

	// print degrees and coefficients of the component polynomials of minimax composite polynomial
	// for(int i=0; i<comp_no; i++) cout << deg[i] << " ";
	// cout << endl;
	for (int i = 0; i < comp_no; i++)
	{
		for (int j = 0; j < coeff_number(deg[i], tree[i]); j++)
		{
			double temp;
			in >> temp;
			decomp_coeff[i].emplace_back(temp);
			// cout << decomp_coeff[i][j] << " ";
		}
		// cout << endl;
	}

	// scale coefficients properly so that unnecessary level consumptions do not occur
	for (int i = 0; i < comp_no - 1; i++)
		for (int j = 0; j < coeff_number(deg[i], tree[i]); j++)
			decomp_coeff[i][j] /= scale_val[i + 1];
	for (int j = 0; j < coeff_number(deg[comp_no - 1], tree[comp_no - 1]); j++)
		decomp_coeff[comp_no - 1][j] *= 0.5; // scale

	// generation of half PhantomCiphertext
	long n = cipher_in.poly_modulus_degree() / 2;
	vector<double> m_half(n);
	for (int i = 0; i < n; i++)
		m_half[i] = 0.5;
	cipher_x = cipher_in;

	// evaluating pk ... p1(x) / 2
	for (int i = 0; i < comp_no; ++i)
	{
		// cout << "*******************************************" << endl;
		// cout << "               No: " << i << endl;
		eval_polynomial_integrate(ckksevaluator, cipher_x, cipher_x, deg[i], decomp_coeff[i], tree[i]);
		decrypt_and_print_part(cipher_x, ckksevaluator, n, 0, 5);
	}

	// x(1+sgn(x))/2 from sgn(x)/2
	ckksevaluator.encoder.encode(m_half, cipher_x.scale(), plain_half);
	ckksevaluator.encryptor.encrypt(plain_half, cipher_half);
	ckksevaluator.evaluator.add_reduced_error(cipher_x, cipher_half, cipher_temp);
	ckksevaluator.evaluator.multiply_reduced_error(cipher_temp, cipher_in, *(ckksevaluator.relin_keys), cipher_res);
	ckksevaluator.evaluator.rescale_to_next_inplace(cipher_res);
}

void memory_save_rotate(const PhantomCiphertext &cipher_in, PhantomCiphertext &cipher_out, int steps, CKKSEvaluator &ckksevaluator)
{
	long n = cipher_in.poly_modulus_degree() / 2;
	PhantomCiphertext temp = cipher_in;
	steps = (steps + n) % n; // 0 ~ n-1
	int first_step = 0;

	if (34 <= steps && steps <= 55)
		first_step = 33;
	else if (57 <= steps && steps <= 61)
		first_step = 33;
	else
		first_step = 0;
	if (steps == 0)
		return; // no rotation

	if (first_step == 0)
		ckksevaluator.evaluator.rotate_vector_inplace(temp, steps, *(ckksevaluator.galois_keys));
	else
	{
		// evaluator.rotate_vector_inplace(temp, first_step, gal_keys);
		ckksevaluator.evaluator.rotate_vector_inplace(temp, first_step, *(ckksevaluator.galois_keys));
		// evaluator.rotate_vector_inplace(temp, steps-first_step, gal_keys);
		ckksevaluator.evaluator.rotate_vector_inplace(temp, steps - first_step, *(ckksevaluator.galois_keys));
	}

	cipher_out = temp;
	//	else scale_evaluator.rotate_vector(cipher_in, steps, gal_keys, cipher_out);
}

void MultipleAdd_SEAL(CKKSEvaluator &ckksevaluator, PhantomCiphertext &cipher, PhantomCiphertext &result, long long n)
{
	long long k, abs_n;
	long long *binary;
	//	PhantomCiphertext temp;
	if (n >= 0)
		abs_n = n;
	else
		abs_n = -n;

	for (k = 1; k < 100; k++)
	{
		if (abs_n < pow2(k))
			break;
	}

	binary = new long long[k];
	for (long i = 0; i < k; i++)
	{
		binary[i] = (abs_n / pow2(i)) % 2;
	}

	// evaluator.add(cipher, cipher, result);
	ckksevaluator.evaluator.add(cipher, cipher, result);
	if (binary[k - 2] == 1)
		ckksevaluator.evaluator.add_inplace(result, cipher);

	for (long i = k - 3; i >= 0; i--)
	{
		ckksevaluator.evaluator.add_inplace(result, result);
		if (binary[i] == 1)
			ckksevaluator.evaluator.add_inplace(result, cipher);
	}

	if (n < 0)
		ckksevaluator.evaluator.negate_inplace(result);
}
void test_evaluation(CKKSEvaluator &ckksevaluator, const PhantomCiphertext &cipher_in, PhantomCiphertext &cipher_out);
void geneT0T1(CKKSEvaluator &ckksevaluator, PhantomCiphertext &T0, PhantomCiphertext &T1, PhantomCiphertext &cipher)
{

	double scale = cipher.scale();
	long n = cipher.poly_modulus_degree() / 2;
	//	vector<double> m_one(n), m_scaled(n);
	vector<double> m_one(n);

	// ctxt_1
	for (int i = 0; i < n; i++)
		m_one[i] = 1.0;
	PhantomPlaintext plain_1;
	ckksevaluator.encoder.encode(m_one, scale, plain_1);
	PhantomCiphertext ctxt_1;
	ckksevaluator.encryptor.encrypt(plain_1, ctxt_1);

	T0 = ctxt_1;
	T1 = cipher;
}
void evalT(CKKSEvaluator &ckksevaluator, PhantomCiphertext &Tmplusn, const PhantomCiphertext &Tm, const PhantomCiphertext &Tn, const PhantomCiphertext &Tmminusn)
{
	PhantomCiphertext temp;
	ckksevaluator.evaluator.multiply_reduced_error(Tm, Tn, *(ckksevaluator.relin_keys), temp);
	ckksevaluator.evaluator.add_inplace_reduced_error(temp, temp);
	ckksevaluator.evaluator.rescale_to_next_inplace(temp);
	ckksevaluator.evaluator.sub_reduced_error(temp, Tmminusn, Tmplusn);
}
void eval_polynomial_integrate(CKKSEvaluator &ckksevaluator, PhantomCiphertext &res, PhantomCiphertext &cipher, long deg, const vector<double> &decomp_coeff, Tree &tree)
{
	double scale = cipher.scale(); // ex) 2^42. exact value.
	long n = cipher.poly_modulus_degree() / 2;
	long total_depth = ceil_to_int(log(static_cast<double>(deg + 1)) / log(2.0)); // required minimum depth considering both scalar and nonscalar multiplications
	PhantomCiphertext temp1, temp2, state, ctxt_zero;
	evaltype eval_type = tree.type;
	vector<long> decomp_deg(pow2(tree.depth + 1), -1);
	vector<long> start_index(pow2(tree.depth + 1), -1);
	vector<std::unique_ptr<PhantomCiphertext>> T(100);
	vector<std::unique_ptr<PhantomCiphertext>> pt(100);
	for (size_t i = 0; i < 100; i++)
		T[i] = nullptr;
	for (size_t i = 0; i < 100; i++)
		pt[i] = nullptr;
	T[0] = std::make_unique<PhantomCiphertext>();
	T[1] = std::make_unique<PhantomCiphertext>();

	// generation of zero PhantomCiphertext
	vector<double> m_coeff(n), m_zero(n, 0.0);
	PhantomPlaintext plain_coeff, plain_zero;
	ckksevaluator.encoder.encode(m_zero, scale * scale, plain_zero); // scaling factor: scale^2 for lazy scaling
	ckksevaluator.encryptor.encrypt(plain_zero, ctxt_zero);

	// set start temp_index
	long num = 0, temp_index;
	if (eval_type == evaltype::oddbaby)
		temp_index = 1;
	else if (eval_type == evaltype::baby)
		temp_index = 0;

	// evaluate decompose polynomial degrees
	decomp_deg[1] = deg;
	for (int i = 1; i <= tree.depth; i++)
	{
		for (int j = pow2(i); j < pow2(i + 1); j++)
		{
			if (j >= static_cast<int>(decomp_deg.size()))
				throw std::invalid_argument("invalid index");
			if (j % 2 == 0)
				decomp_deg[j] = tree.tree[j / 2] - 1;
			else if (j % 2 == 1)
				decomp_deg[j] = decomp_deg[j / 2] - tree.tree[j / 2];
		}
	}

	// compute start index.
	for (int i = 1; i < pow2(tree.depth + 1); i++)
	{
		if (tree.tree[i] == 0)
		{
			start_index[i] = temp_index;
			temp_index += (decomp_deg[i] + 1);
		}
	}

	// generate T0, T1
	geneT0T1(ckksevaluator, *T[0], *T[1], cipher);

	if (eval_type == evaltype::oddbaby)
	{
		// i: depth stage
		for (int i = 1; i <= total_depth; i++)
		{
			// cout << "////////////// stage : " << i << endl;

			// depth i computation. all end points.
			for (int j = 1; j < pow2(tree.depth + 1); j++)
			{
				if (tree.tree[j] == 0 && total_depth + 1 - num_one(j) == i) // depth i stage end points. j: index
				{
					int temp_idx = start_index[j];
					// cout << "pt: " << j << endl;
					pt[j] = std::make_unique<PhantomCiphertext>();
					ckksevaluator.evaluator.multiply_const(*T[1], decomp_coeff[temp_idx], *pt[j]);
					temp_idx += 2;
					for (int k = 3; k <= decomp_deg[j]; k += 2)
					{
						ckksevaluator.evaluator.multiply_const(*T[k], decomp_coeff[temp_idx], temp1);
						ckksevaluator.evaluator.add_inplace_reduced_error(*pt[j], temp1); // this is lazy scaling!!

						temp_idx += 2;
					}
					ckksevaluator.evaluator.rescale_to_next_inplace(*pt[j]);
					// print_cipher(decryptor, encoder, public_key, secret_key, relin_keys, *pt[j]);
					// decrypt_and_print_part(*pt[j], decryptor, encoder, n, 0, 5);
				}
			}

			// depth i computation. all intersection points.
			long inter[40];
			long inter_num = 0;

			for (int j = 1; j < pow2(tree.depth + 1); j++)
			{
				if (tree.tree[j] > 0 && total_depth + 1 - num_one(j) == i && j % 2 == 1) // depth i stage intersection points
				{
					long k = j;
					// cout << "pt: " << j << endl;
					pt[j] = std::make_unique<PhantomCiphertext>();
					ckksevaluator.evaluator.multiply_reduced_error(*T[tree.tree[k]], *pt[2 * k + 1], *(ckksevaluator.relin_keys), *pt[j]);
					k *= 2;
					while (1)
					{
						if (tree.tree[k] == 0)
							break;
						ckksevaluator.evaluator.multiply_reduced_error(*T[tree.tree[k]], *pt[2 * k + 1], *(ckksevaluator.relin_keys), temp1);
						ckksevaluator.evaluator.add_inplace_reduced_error(*pt[j], temp1); // lazy scaling code
						k *= 2;
					}
					ckksevaluator.evaluator.rescale_to_next_inplace(*pt[j]);
					ckksevaluator.evaluator.add_inplace_reduced_error(*pt[j], *pt[k]);
					// print_cipher(decryptor, encoder, public_key, secret_key, relin_keys, *pt[j]);
					// decrypt_and_print_part(*pt[j], decryptor, encoder, n, 0, 5);
				}
			}

			// Ti evaluation
			if (i <= tree.m - 1)
			{
				// cout << "T: " << pow2(i) << endl;
				T[pow2(i)] = std::make_unique<PhantomCiphertext>();
				evalT(ckksevaluator, *T[pow2(i)], *T[pow2(i - 1)], *T[pow2(i - 1)], *T[0]);
				// print_cipher(decryptor, encoder, public_key, secret_key, relin_keys, *T[pow2(i)]);
				// decrypt_and_print_part(*T[pow2(i)], decryptor, encoder, n, 0, 5);
			}

			if (i <= tree.l)
			{
				for (int j = pow2(i - 1) + 1; j <= pow2(i) - 1; j += 2) // T1 is not computed. other odd Tis are computed.
				{
					// cout << "T: " << j << endl;
					T[j] = std::make_unique<PhantomCiphertext>();
					evalT(ckksevaluator, *T[j], *T[pow2(i - 1)], *T[j - pow2(i - 1)], *T[pow2(i) - j]);
					// print_cipher(decryptor, encoder, public_key, secret_key, relin_keys, *T[j]);
					// decrypt_and_print_part(*T[j], decryptor, encoder, n, 0, 5);
				}
			}
		}
		res = *pt[1];
	}
	else if (eval_type == evaltype::baby)
	{
		// i: depth stage
		for (int i = 1; i <= total_depth; i++)
		{
			// cout << "////////////// stage : " << i << endl;

			// depth i computation. all end points.
			for (int j = 1; j < pow2(tree.depth + 1); j++)
			{
				if (tree.tree[j] == 0 && total_depth + 1 - num_one(j) == i) // depth i stage end points. j: index
				{
					int temp_idx = start_index[j];
					// cout << "pt: " << j << endl;
					pt[j] = std::make_unique<PhantomCiphertext>();

					*pt[j] = ctxt_zero;

					for (int k = 0; k <= decomp_deg[j]; k++)
					{
						// cout << "coeff[temp_idx]: " <<  coeff[temp_idx] << endl;
						if (abs(decomp_coeff[temp_idx]) > 1.0 / scale) // to avoid transparent PhantomCiphertext
						{
							if (T[k] == nullptr)
								throw std::runtime_error("T[k] is not set");
							ckksevaluator.evaluator.multiply_const(*T[k], decomp_coeff[temp_idx], temp1);
							ckksevaluator.evaluator.add_inplace(*pt[j], temp1); // this is lazy scaling!!
						}
						temp_idx++;
					}
					ckksevaluator.evaluator.rescale_to_next_inplace(*pt[j]);
					// print_cipher(decryptor, encoder, public_key, secret_key, relin_keys, *pt[j]);
				}
			}

			// depth i computation. all intersection points.
			long inter[40];
			long inter_num = 0;

			for (int j = 1; j < pow2(tree.depth + 1); j++)
			{
				if (tree.tree[j] > 0 && total_depth + 1 - num_one(j) == i) // depth i stage intersection points
				{
					int temp = j;
					bool no_execute = false;
					for (int k = 0; k < inter_num; k++)
					{
						while (1)
						{
							if (temp == inter[k])
							{
								no_execute = true;
								break;
							}
							if (temp % 2 == 0)
								temp /= 2;
							else
								break;
						}
					}

					if (no_execute == false)
					{
						inter[inter_num] = j;
						inter_num += 1;

						long k = j;

						// cout << "pt: " << j << endl;
						pt[j] = std::make_unique<PhantomCiphertext>();
						if (T[tree.tree[k]] == nullptr)
							throw std::runtime_error("T[tree.tree[k]] is not set");
						if (pt[2 * k + 1] == nullptr)
							throw std::runtime_error("pt[2*k+1] is not set");
						ckksevaluator.evaluator.multiply_reduced_error(*T[tree.tree[k]], *pt[2 * k + 1], *(ckksevaluator.relin_keys), *pt[j]);
						k *= 2;

						while (1)
						{
							if (tree.tree[k] == 0)
								break;
							if (T[tree.tree[k]] == nullptr)
								throw std::runtime_error("T[tree.tree[k]] is not set");
							if (pt[2 * k + 1] == nullptr)
								throw std::runtime_error("pt[2*k+1] is not set");
							ckksevaluator.evaluator.multiply_reduced_error(*T[tree.tree[k]], *pt[2 * k + 1], *(ckksevaluator.relin_keys), temp1);
							ckksevaluator.evaluator.add_inplace(*pt[j], temp1); // lazy scaling code
							k *= 2;
						}
						ckksevaluator.evaluator.rescale_to_next_inplace(*pt[j]);
						ckksevaluator.evaluator.add_inplace_reduced_error(*pt[j], *pt[k]);
						// print_cipher(decryptor, encoder, public_key, secret_key, relin_keys, *pt[j]);
					}
				}
			}

			// Ti evaluation
			for (int j = 2; j <= tree.b; j++)
			{
				int g = j;
				if (pow2(i - 1) < g && g <= pow2(i))
				{
					// cout << "T: " << g << endl;
					T[g] = std::make_unique<PhantomCiphertext>();
					if (g % 2 == 0)
					{
						if (T[g / 2] == nullptr)
							throw std::runtime_error("T[g/2] is not set");
						if (T[0] == nullptr)
							throw std::runtime_error("T[0] is not set");
						evalT(ckksevaluator, *T[g], *T[g / 2], *T[g / 2], *T[0]);
					}
					else
					{
						if (T[g / 2] == nullptr)
							throw std::runtime_error("T[g/2] is not set");
						if (T[(g + 1) / 2] == nullptr)
							throw std::runtime_error("T[(g+1)/2] is not set");
						if (T[0] == nullptr)
							throw std::runtime_error("T[0] is not set");
						evalT(ckksevaluator, *T[g], *T[g / 2], *T[(g + 1) / 2], *T[1]);
					}
					// print_cipher(decryptor, encoder, public_key, secret_key, relin_keys, *T[g]);
				}
			}
			for (int j = 1; j <= tree.m - 1; j++)
			{
				int g = pow2(j) * tree.b;
				if (pow2(i - 1) < g && g <= pow2(i))
				{
					// cout << "T: " << g << endl;
					T[g] = std::make_unique<PhantomCiphertext>();
					if (g % 2 == 0)
					{
						if (T[g / 2] == nullptr)
							throw std::runtime_error("T[g/2] is not set");
						if (T[0] == nullptr)
							throw std::runtime_error("T[0] is not set");
						evalT(ckksevaluator, *T[g], *T[g / 2], *T[g / 2], *T[0]);
					}
					else
					{
						if (T[g / 2] == nullptr)
							throw std::runtime_error("T[g/2] is not set");
						if (T[(g + 1) / 2] == nullptr)
							throw std::runtime_error("T[(g+1)/2] is not set");
						if (T[0] == nullptr)
							throw std::runtime_error("T[0] is not set");
						evalT(ckksevaluator, *T[g], *T[g / 2], *T[(g + 1) / 2], *T[1]);
					}
					// print_cipher(decryptor, encoder, public_key, secret_key, relin_keys, *T[g]);
				}
			}
		}
		res = *pt[1];
	}
}
long coeff_number(long deg, Tree &tree)
{
	long num = 0;
	long *decomp_deg = new long[pow2(tree.depth + 1)];
	decomp_deg[1] = deg;
	for (int i = 1; i <= tree.depth; i++)
	{
		for (int j = pow2(i); j < pow2(i + 1); j++)
		{
			if (j % 2 == 0)
				decomp_deg[j] = tree.tree[j / 2] - 1;
			else if (j % 2 == 1)
				decomp_deg[j] = decomp_deg[j / 2] - tree.tree[j / 2];
		}
	}

	for (int i = 0; i < pow2(tree.depth + 1); i++)
	{
		if (tree.tree[i] == 0)
		{
			num += (decomp_deg[i] + 1);
		}
	}
	delete decomp_deg;
	return num;
}
void coeff_change(long comp_no, long deg[], double *coeff[], long type[], vector<Tree> &tree);
long ShowFailure_ReLU(CKKSEvaluator &ckksevaluator, PhantomCiphertext &cipher, vector<double> &x, long precision, long n)
{
	long failure = 0;
	double bound = pow(2.0, static_cast<double>(-precision));
	PhantomPlaintext plain_out;
	vector<double> output;
	ckksevaluator.decryptor.decrypt(cipher, plain_out);
	ckksevaluator.encoder.decode(plain_out, output);

	for (int i = 0; i < n; ++i)
		if (abs(ReLU(x[i]) - output[i]) > bound)
			failure++;

	cout << "-------------------------------------------------" << endl;
	cout << "failure : " << failure << endl;
	cout << "-------------------------------------------------" << endl;
	return failure;
}

void decrypt_and_print( PhantomCiphertext &cipher, CKKSEvaluator &ckksevaluator, long sparse_slots, size_t front, size_t back)
{
	PhantomPlaintext plain;
	ckksevaluator.decryptor.decrypt(cipher, plain);

	vector<complex<double>> rtn_vec;
	// encoder.decode(plain, rtn_vec, sparse_slots);
	ckksevaluator.encoder.decode(plain, rtn_vec);

	cout << "( ";
	for (size_t i = 0; i < front; i++)
		cout << rtn_vec[i] << ", ";
	cout << "... ";

	size_t slots;
	if (sparse_slots == 0)
		slots = rtn_vec.size();
	else
		slots = sparse_slots;
	for (size_t i = 0; i < back; i++)
	{
		cout << rtn_vec[slots - back + i];
		if (i != back - 1)
			cout << ", ";
	}
	cout << ")" << endl;
}
void decrypt_and_print_part( PhantomCiphertext &cipher, CKKSEvaluator &ckksevaluator, long sparse_slots, size_t start, size_t end)
{
	PhantomPlaintext plain;
	ckksevaluator.decryptor.decrypt(cipher, plain);

	vector<complex<double>> rtn_vec;
	// encoder.decode(plain, rtn_vec, sparse_slots);
	ckksevaluator.encoder.decode(plain, rtn_vec);

	cout << "( ";
	cout << "... ";
	for (size_t i = start; i <= end; i++)
		cout << rtn_vec[i] << ", ";
	cout << "... ";
	cout << ")" << endl;
	cout << "scale: " << cipher.scale() << endl;
}
void decrypt_and_print_txt( PhantomCiphertext &cipher, CKKSEvaluator &ckksevaluator, long sparse_slots, size_t front, size_t back, ofstream &output)
{
	PhantomPlaintext plain;
	ckksevaluator.decryptor.decrypt(cipher, plain);

	vector<complex<double>> rtn_vec;
	// encoder.decode(plain, rtn_vec, sparse_slots);
	ckksevaluator.encoder.decode(plain, rtn_vec);

	cout << "( ";
	output << "( ";
	for (size_t i = 0; i < front; i++)
	{
		cout << rtn_vec[i] << ", ";
		if ((i + 1) % 1024 == 0)
			cout << endl
				 << endl;
	}
	for (size_t i = 0; i < front; i++)
	{
		output << rtn_vec[i] << ", ";
		if ((i + 1) % 1024 == 0)
			output << endl
				   << endl;
	}
	cout << "... ";
	output << "... ";

	size_t slots;
	if (sparse_slots == 0)
		slots = rtn_vec.size();
	else
		slots = sparse_slots;
	for (size_t i = 0; i < back; i++)
	{
		cout << rtn_vec[slots - back + i];
		output << rtn_vec[slots - back + i];
		if (i != back - 1)
			cout << ", ";
	}
	cout << ")" << endl;
	output << ")" << endl;

	cout << endl;
	output << endl;
}

// infer_seal
//  import parameters
void import_parameters_cifar10(vector<double> &linear_weight, vector<double> &linear_bias, vector<vector<double>> &conv_weight, vector<vector<double>> &bn_bias, vector<vector<double>> &bn_running_mean, vector<vector<double>> &bn_running_var, vector<vector<double>> &bn_weight, size_t layer_num, size_t end_num)
{
	string dir;
	if (layer_num != 20 && layer_num != 32 && layer_num != 44 && layer_num != 56 && layer_num != 110)
		throw std::invalid_argument("layer number is not valid");
	if (layer_num == 20)
		dir = "resnet20_new";
	else if (layer_num == 32)
		dir = "resnet32_new";
	else if (layer_num == 44)
		dir = "resnet44_new";
	else if (layer_num == 56)
		dir = "resnet56_new";
	else if (layer_num == 110)
		dir = "resnet110_new";

	ifstream in;
	double val;
	size_t num_c = 0, num_b = 0, num_m = 0, num_v = 0, num_w = 0;

	conv_weight.clear();
	conv_weight.resize(layer_num - 1);
	bn_bias.clear();
	bn_bias.resize(layer_num - 1);
	bn_running_mean.clear();
	bn_running_mean.resize(layer_num - 1);
	bn_running_var.clear();
	bn_running_var.resize(layer_num - 1);
	bn_weight.clear();
	bn_weight.resize(layer_num - 1);

	int fh = 3, fw = 3;
	int ci = 0, co = 0;

	// convolution parameters
	ci = 3, co = 16;
	in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/conv1_weight.txt");
	
	if (!in.is_open())
		throw std::runtime_error("file is not open");
	for (long i = 0; i < fh * fw * ci * co; i++)
	{
		in >> val;
		conv_weight[num_c].emplace_back(val);
	}
	in.close();
	num_c++;

	// convolution parameters
	for (int j = 1; j <= 3; j++)
	{
		for (int k = 0; k <= end_num; k++)
		{
			// co setting
			if (j == 1)
				co = 16;
			else if (j == 2)
				co = 32;
			else if (j == 3)
				co = 64;

			// ci setting
			if (j == 1 || (j == 2 && k == 0))
				ci = 16;
			else if ((j == 2 && k != 0) || (j == 3 && k == 0))
				ci = 32;
			else
				ci = 64;
			in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_conv1_weight.txt");
			if (!in.is_open())
				throw std::runtime_error("file is not open");
			for (long i = 0; i < fh * fw * ci * co; i++)
			{
				in >> val;
				conv_weight[num_c].emplace_back(val);
			}
			in.close();
			num_c++;

			// ci setting
			if (j == 1)
				ci = 16;
			else if (j == 2)
				ci = 32;
			else if (j == 3)
				ci = 64;
			in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_conv2_weight.txt");
			if (!in.is_open())
				throw std::runtime_error("file is not open");
			for (long i = 0; i < fh * fw * ci * co; i++)
			{
				in >> val;
				conv_weight[num_c].emplace_back(val);
			}
			in.close();
			num_c++;
		}
	}

	// batch_normalization parameters
	ci = 16;
	in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/bn1_bias.txt");
	if (!in.is_open())
		throw std::runtime_error("file is not open");
	for (long i = 0; i < ci; i++)
	{
		in >> val;
		bn_bias[num_b].emplace_back(val);
	}
	in.close();
	num_b++;
	in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/bn1_running_mean.txt");
	if (!in.is_open())
		throw std::runtime_error("file is not open");
	for (long i = 0; i < ci; i++)
	{
		in >> val;
		bn_running_mean[num_m].emplace_back(val);
	}
	in.close();
	num_m++;
	in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/bn1_running_var.txt");
	if (!in.is_open())
		throw std::runtime_error("file is not open");
	for (long i = 0; i < ci; i++)
	{
		in >> val;
		bn_running_var[num_v].emplace_back(val);
	}
	in.close();
	num_v++;
	in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/bn1_weight.txt");
	if (!in.is_open())
		throw std::runtime_error("file is not open");
	for (long i = 0; i < ci; i++)
	{
		in >> val;
		bn_weight[num_w].emplace_back(val);
	}
	in.close();
	num_w++;

	// batch_normalization parameters
	for (int j = 1; j <= 3; j++)
	{
		int ci;
		if (j == 1)
			ci = 16;
		else if (j == 2)
			ci = 32;
		else if (j == 3)
			ci = 64;

		for (int k = 0; k <= end_num; k++)
		{
			in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn1_bias.txt");
			if (!in.is_open())
				throw std::runtime_error("file is not open");
			for (long i = 0; i < ci; i++)
			{
				in >> val;
				bn_bias[num_b].emplace_back(val);
			}
			in.close();
			num_b++;
			in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn1_running_mean.txt");
			if (!in.is_open())
				throw std::runtime_error("file is not open");
			for (long i = 0; i < ci; i++)
			{
				in >> val;
				bn_running_mean[num_m].emplace_back(val);
			}
			in.close();
			num_m++;
			in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn1_running_var.txt");
			if (!in.is_open())
				throw std::runtime_error("file is not open");
			for (long i = 0; i < ci; i++)
			{
				in >> val;
				bn_running_var[num_v].emplace_back(val);
			}
			in.close();
			num_v++;
			in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn1_weight.txt");
			if (!in.is_open())
				throw std::runtime_error("file is not open");
			for (long i = 0; i < ci; i++)
			{
				in >> val;
				bn_weight[num_w].emplace_back(val);
			}
			in.close();
			num_w++;
			in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn2_bias.txt");
			if (!in.is_open())
				throw std::runtime_error("file is not open");
			for (long i = 0; i < ci; i++)
			{
				in >> val;
				bn_bias[num_b].emplace_back(val);
			}
			in.close();
			num_b++;
			in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn2_running_mean.txt");
			if (!in.is_open())
				throw std::runtime_error("file is not open");
			for (long i = 0; i < ci; i++)
			{
				in >> val;
				bn_running_mean[num_m].emplace_back(val);
			}
			in.close();
			num_m++;
			in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn2_running_var.txt");
			if (!in.is_open())
				throw std::runtime_error("file is not open");
			for (long i = 0; i < ci; i++)
			{
				in >> val;
				bn_running_var[num_v].emplace_back(val);
			}
			in.close();
			num_v++;
			in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn2_weight.txt");
			if (!in.is_open())
				throw std::runtime_error("file is not open");
			for (long i = 0; i < ci; i++)
			{
				in >> val;
				bn_weight[num_w].emplace_back(val);
			}
			in.close();
			num_w++;
		}
	}

	// FC
	in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/linear_weight.txt");
	if (!in.is_open())
		throw std::runtime_error("file is not open");
	for (long i = 0; i < 10 * 64; i++)
	{
		in >> val;
		linear_weight.emplace_back(val);
	}
	in.close();
	in.open("/root/phantom-fhe/pretrained_parameters/" + dir + "/linear_bias.txt");
	if (!in.is_open())
		throw std::runtime_error("file is not open");
	for (long i = 0; i < 10; i++)
	{
		in >> val;
		linear_bias.emplace_back(val);
	}
	in.close();
}
