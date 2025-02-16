#pragma once

//! @brief phantom_api.h
//! Define phantom API can be used by rtlib

#include "phantom.h"
#include "rt_def.h"

typedef double              SCALE_T;
typedef phantom::parms_id_type LEVEL_T;


//! @brief Seal API for context management

CIPHERTEXT Phantom_get_input_data(const char* name, size_t idx);
void Phantom_encode_float(PLAIN plain, float* input, size_t len, SCALE_T scale,
                       LEVEL_T level);
void Phantom_encode_double(PLAIN plain, double* input, size_t len, SCALE_T scale,
                        LEVEL_T level);
void Phantom_encode_float_cst_lvl(PLAIN plain, float* input, size_t len,
                               SCALE_T scale, int level);
void Phantom_encode_double_cst_lvl(PLAIN plain, double* input, size_t len,
                                SCALE_T scale, int level);
void Phantom_encode_float_mask(PLAIN plain, float input, size_t len, SCALE_T scale,
                            LEVEL_T level);
void Phantom_encode_double_mask(PLAIN plain, double input, size_t len,
                             SCALE_T scale, LEVEL_T level);
void Phantom_encode_float_mask_cst_lvl(PLAIN plain, float input, size_t len,
                                    SCALE_T scale, int level);
void Phantom_encode_double_mask_cst_lvl(PLAIN plain, double input, size_t len,
                                     SCALE_T scale, int level);
double* Phantom_handle_output(const char* name);

//! @brief Seal API for evaluation
void Phantom_add_ciph(CIPHER res, CIPHER op1, CIPHER op2);
void Phantom_add_plain(CIPHER res, CIPHER op1, PLAIN op2);
void Phantom_mul_ciph(CIPHER res, CIPHER op1, CIPHER op2);
void Phantom_mul_plain(CIPHER res, CIPHER op1, PLAIN op2);
void Phantom_rotate(CIPHER res, CIPHER op, int step);
void Phantom_rescale(CIPHER res, CIPHER op);
void Phantom_mod_switch(CIPHER res, CIPHER op);
void Phantom_relin(CIPHER res, CIPHER3 op);
void Phantom_copy(CIPHER res, CIPHER op);
void Phantom_zero(CIPHER res);

SCALE_T Phantom_scale(CIPHER res);
LEVEL_T Phantom_level(CIPHER res);




