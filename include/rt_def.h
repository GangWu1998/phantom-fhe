#pragma once

// NOLINTBEGIN (readability-identifier-naming)

//! @brief Forward declaration of SEAL types
namespace phantom {
class PhantomCiphertext;
class PhantomPlaintext;
}  // namespace seal

//! @brief Define CIPHERTEXT/CIPHER/PLAINTEXT/PLAIN for rt APIs
typedef phantom::PhantomCiphertext  CIPHERTEXT;
typedef phantom::PhantomCiphertext  CIPHERTEXT3;
typedef phantom::PhantomCiphertext* CIPHER;
typedef phantom::PhantomCiphertext* CIPHER3;
typedef phantom::PhantomPlaintext  PLAINTEXT;
typedef phantom::PhantomPlaintext* PLAIN;

// NOLINTEND (readability-identifier-naming)

#define CIPHER_DEFINED 1
#define PLAIN_DEFINED  1

