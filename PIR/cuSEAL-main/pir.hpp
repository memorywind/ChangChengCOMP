#pragma once

#include "SIGMA/src/sigma.h"
#include "SIGMA/src//util/polyarithsmallmod.h"
#include <cassert>
#include <cmath>
#include <string>
#include <vector>

typedef std::vector<sigma::Plaintext> Database;
typedef std::vector<std::vector<sigma::Ciphertext>> PirQuery;
typedef std::vector<sigma::Ciphertext> PirReply;

struct PirParams {
  bool enable_symmetric;
  bool enable_batching;
  bool enable_mswitching;
  std::uint64_t ele_num;
  std::uint64_t ele_size;
  std::uint64_t elements_per_plaintext;
  std::uint64_t num_of_plaintexts; // number of plaintexts in database
  std::uint32_t d;                 // number of dimensions for the database
  std::uint32_t expansion_ratio;   // ratio of ciphertext to plaintext
  std::vector<std::uint64_t> nvec; // size of each of the d dimensions
  std::uint32_t slot_count;
};

void gen_encryption_params(std::uint32_t N,    // degree of polynomial
                           std::uint32_t logt, // bits of plaintext coefficient
                           sigma::EncryptionParameters &enc_params);

void gen_pir_params(uint64_t ele_num, uint64_t ele_size, uint32_t d,
                    const sigma::EncryptionParameters &enc_params,
                    PirParams &pir_params, bool enable_symmetric = false,
                    bool enable_batching = true, bool enable_mswitching = true);

void gen_params(uint64_t ele_num, uint64_t ele_size, uint32_t N, uint32_t logt,
                uint32_t d, sigma::EncryptionParameters &params,
                PirParams &pir_params);

void verify_encryption_params(const sigma::EncryptionParameters &enc_params);

void print_pir_params(const PirParams &pir_params);
void print_seal_params(const sigma::EncryptionParameters &enc_params);

// returns the number of plaintexts that the database can hold
std::uint64_t plaintexts_per_db(std::uint32_t logt, std::uint64_t N,
                                std::uint64_t ele_num, std::uint64_t ele_size);

// returns the number of elements that a single FV plaintext can hold
std::uint64_t elements_per_ptxt(std::uint32_t logt, std::uint64_t N,
                                std::uint64_t ele_size);

// returns the number of coefficients needed to store one element
std::uint64_t coefficients_per_element(std::uint32_t logt,
                                       std::uint64_t ele_size);

// Converts an array of bytes to a vector of coefficients, each of which is less
// than the plaintext modulus
std::vector<std::uint64_t> bytes_to_coeffs(std::uint32_t limit,
                                           const std::uint8_t *bytes,
                                           std::uint64_t size);

// Converts an array of coefficients into an array of bytes
void coeffs_to_bytes(std::uint32_t limit,
                     const std::vector<std::uint64_t> &coeffs,
                     std::uint8_t *output, std::uint32_t size_out,
                     std::uint32_t ele_size);

// Takes a vector of coefficients and returns the corresponding FV plaintext
void vector_to_plaintext(const std::vector<std::uint64_t> &coeffs,
                         sigma::Plaintext &plain);

// Since the database has d dimensions, and an item is a particular cell
// in the d-dimensional hypercube, this function computes the corresponding
// index for each of the d dimensions
std::vector<std::uint64_t> compute_indices(std::uint64_t desiredIndex,
                                           std::vector<std::uint64_t> nvec);

uint64_t invert_mod(uint64_t m, const sigma::Modulus &mod);

uint32_t compute_expansion_ratio(sigma::EncryptionParameters params);
std::vector<sigma::Plaintext>
decompose_to_plaintexts(sigma::EncryptionParameters params,
                        sigma::Ciphertext &ct);

// We need the returned ciphertext to be initialized by Context so the caller
// will pass it in
void compose_to_ciphertext(sigma::EncryptionParameters params,
                           const std::vector<sigma::Plaintext> &pts,
                           sigma::Ciphertext &ct);
void compose_to_ciphertext(sigma::EncryptionParameters params,
                           std::vector<sigma::Plaintext>::const_iterator pt_iter,
                           sigma::Ciphertext &ct);

// Serialize and deserialize galois keys to send them over the network
std::string serialize_galoiskeys(sigma::Serializable<sigma::GaloisKeys> g);
sigma::GaloisKeys *
deserialize_galoiskeys(std::string s,
                       std::shared_ptr<sigma::SIGMAContext> context);
