// Copyright (c) 2017-2021 Thomas Fussell
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE
//
// @license: http://www.opensource.org/licenses/mit-license.php
// @author: see AUTHORS file

#include <array>
#include <random>

#include <detail/binary.hpp>
#include <detail/cryptography/aes.hpp>
#include <detail/cryptography/encryption_info.hpp>

namespace {

using xlnt::detail::encryption_info;

std::vector<std::uint8_t> calculate_standard_key(
    const encryption_info::standard_encryption_info &info,
    const std::u16string &password)
{
    // H_0 = H(salt + password)
    auto salt_plus_password = info.salt;
    auto password_bytes = xlnt::detail::string_to_bytes(password);
    std::copy(password_bytes.begin(),
        password_bytes.end(),
        std::back_inserter(salt_plus_password));
    auto h_0 = hash(info.hash, salt_plus_password);

    // H_n = H(iterator + H_n-1)
    std::vector<std::uint8_t> iterator_plus_h_n(4, 0);
    iterator_plus_h_n.insert(iterator_plus_h_n.end(), h_0.begin(), h_0.end());
    std::uint32_t &iterator = *reinterpret_cast<std::uint32_t *>(iterator_plus_h_n.data());
    std::vector<std::uint8_t> h_n;
    for (iterator = 0; iterator < info.spin_count; ++iterator)
    {
        hash(info.hash, iterator_plus_h_n, h_n);
        std::copy(h_n.begin(), h_n.end(), iterator_plus_h_n.begin() + 4);
    }

    // H_final = H(H_n + block)
    auto h_n_plus_block = h_n;
    const std::uint32_t block_number = 0;
    h_n_plus_block.insert(
        h_n_plus_block.end(),
        reinterpret_cast<const std::uint8_t *>(&block_number),
        reinterpret_cast<const std::uint8_t *>(&block_number) + sizeof(std::uint32_t));
    auto h_final = hash(info.hash, h_n_plus_block);

    // X1 = H(h_final ^ 0x36)
    std::vector<std::uint8_t> buffer(64, 0x36);
    for (std::size_t i = 0; i < h_final.size(); ++i)
    {
        buffer[i] = static_cast<std::uint8_t>(0x36 ^ h_final[i]);
    }
    auto X1 = hash(info.hash, buffer);

    // X2 = H(h_final ^ 0x5C)
    buffer.assign(64, 0x5c);
    for (std::size_t i = 0; i < h_final.size(); ++i)
    {
        buffer[i] = static_cast<std::uint8_t>(0x5c ^ h_final[i]);
    }
    auto X2 = hash(info.hash, buffer);

    auto X3 = X1;
    X3.insert(X3.end(), X2.begin(), X2.end());

    auto key = std::vector<std::uint8_t>(X3.begin(),
        X3.begin() + static_cast<std::ptrdiff_t>(info.key_bytes));

    using xlnt::detail::aes_ecb_decrypt;

    auto calculated_verifier_hash = hash(info.hash,
        aes_ecb_decrypt(info.encrypted_verifier, key));
    auto decrypted_verifier_hash = aes_ecb_decrypt(
        info.encrypted_verifier_hash, key);
    decrypted_verifier_hash.resize(calculated_verifier_hash.size());

    if (calculated_verifier_hash != decrypted_verifier_hash)
    {
        throw xlnt::exception("bad password");
    }

    return key;
}

std::vector<std::uint8_t> hash_password(
    xlnt::detail::hash_algorithm hash_algor,
    size_t spin_count,
    const std::vector<std::uint8_t> &salt,
    const std::u16string &password)
{
    // H_0 = H(salt + password)
    auto salt_plus_password(salt);
    auto password_bytes = xlnt::detail::string_to_bytes(password);
    std::copy(password_bytes.begin(),
        password_bytes.end(),
        std::back_inserter(salt_plus_password));

    auto h = hash(hash_algor, salt_plus_password);

    // H_n = H(iterator + H_n-1)
    std::vector<std::uint8_t> iterator_plus_h_n(4, 0);
    iterator_plus_h_n.insert(iterator_plus_h_n.end(), h.begin(), h.end());
    std::uint32_t &iterator = *reinterpret_cast<std::uint32_t *>(iterator_plus_h_n.data());
    for (iterator = 0; iterator < spin_count; ++iterator)
    {
        hash(hash_algor, iterator_plus_h_n, h);
        std::copy(h.begin(), h.end(), iterator_plus_h_n.begin() + 4);
    }
    return h;
}

inline std::vector<std::uint8_t> decrypt_block(
    const encryption_info::agile_encryption_info &info,
    const std::vector<std::uint8_t> &raw_key,
    const std::array<std::uint8_t, 8> &block,
    const std::vector<std::uint8_t> &encrypted)
{
    auto combined = raw_key;
    combined.insert(combined.end(), block.begin(), block.end());

    auto key = hash(info.key_encryptor.hash, combined);
    key.resize(info.key_encryptor.key_bits / 8);

    return xlnt::detail::aes_cbc_decrypt(encrypted, key, info.key_encryptor.salt_value);
};

const std::array<std::uint8_t, 8> input_block_key = {{0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79}};
const std::array<std::uint8_t, 8> verifier_block_key = {{0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e}};
const std::array<std::uint8_t, 8> key_value_block_key = {{0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6}};

std::vector<std::uint8_t> calculate_agile_key(
    const encryption_info::agile_encryption_info &info,
    const std::u16string &password)
{
    auto h_n = hash_password(info.key_encryptor.hash, info.key_encryptor.spin_count,
        info.key_encryptor.salt_value, password);

    auto hash_input = decrypt_block(info, h_n, input_block_key, info.key_encryptor.verifier_hash_input);
    auto calculated_verifier = hash(info.key_encryptor.hash, hash_input);

    auto expected_verifier = decrypt_block(info, h_n, verifier_block_key, info.key_encryptor.verifier_hash_value);
    expected_verifier.resize(calculated_verifier.size());

    if (calculated_verifier != expected_verifier)
    {
        throw xlnt::exception("bad password");
    }

    return decrypt_block(info, h_n, key_value_block_key, info.key_encryptor.encrypted_key_value);
}

inline std::vector<std::uint8_t> encrypt_block(
    const encryption_info::agile_encryption_info &info,
    const std::vector<std::uint8_t> &raw_key,
    const std::array<std::uint8_t, 8> &block,
    const std::vector<std::uint8_t> &encrypted)
{
    auto combined = raw_key;
    combined.insert(combined.end(), block.begin(), block.end());

    auto key = hash(info.key_encryptor.hash, combined);
    key.resize(info.key_encryptor.key_bits / 8);

    return xlnt::detail::aes_cbc_encrypt(encrypted, key, info.key_encryptor.salt_value);
};

encryption_info generate_agile_encryption_info(const std::u16string &password)
{
    std::random_device dev;
    std::mt19937 gen(dev());
    std::uniform_int_distribution<> dist(0, 255);
    encryption_info result;

    result.is_agile = true;

    auto &key_data = result.agile.key_data;
    key_data.block_size = 16;
    key_data.cipher_algorithm = "AES";
    key_data.cipher_chaining = "ChainingModeCBC";
    key_data.hash = xlnt::detail::hash_algorithm::sha512;
    key_data.hash_size = 64;
    key_data.key_bits = 256;
    key_data.salt_size = 16;
    key_data.salt_value.resize(key_data.salt_size);
    for (auto &v : key_data.salt_value)
        v = static_cast<uint8_t>(dist(gen));

    auto &key_enc = result.agile.key_encryptor;
    key_enc.spin_count = 100000;
    key_enc.block_size = 16;
    key_enc.cipher_algorithm = "AES";
    key_enc.cipher_chaining = "ChainingModeCBC";
    key_enc.hash = xlnt::detail::hash_algorithm::sha512;
    key_enc.hash_size = 64;
    key_enc.key_bits = 256;
    key_enc.salt_size = 16;
    key_enc.salt_value.resize(key_enc.salt_size);
    for (auto &v : key_enc.salt_value)
        v = static_cast<uint8_t>(dist(gen));

    auto h_n = hash_password(key_enc.hash, key_enc.spin_count,
        key_enc.salt_value, password);

    std::vector<std::uint8_t> salt(key_enc.salt_size);
    for (auto &v : salt)
        v = static_cast<uint8_t>(dist(gen));
    key_enc.verifier_hash_input = encrypt_block(result.agile, h_n, input_block_key, salt);
    auto hashed_verifier = hash(key_enc.hash, salt);

    key_enc.verifier_hash_value = encrypt_block(result.agile, h_n, verifier_block_key, hashed_verifier);

    result.encryption_key.resize(key_enc.key_bits / 8);
    for (auto &v : result.encryption_key)
        v = static_cast<uint8_t>(dist(gen));
    key_enc.encrypted_key_value = encrypt_block(result.agile, h_n, key_value_block_key, result.encryption_key);

    salt.resize(key_data.hash_size);
    for (auto &v : salt)
        v = static_cast<uint8_t>(dist(gen));
    const std::array<std::uint8_t, 8> integrity_block_key1 = {{0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6}};
    auto combined(key_data.salt_value);
    combined.insert(combined.end(), integrity_block_key1.begin(), integrity_block_key1.end());

    auto key = hash(key_data.hash, combined);
    key.resize(key_data.block_size);

    result.agile.data_integrity.hmac_key = xlnt::detail::aes_cbc_encrypt(salt, result.encryption_key, key);
    result.agile.data_integrity.hmac_value = salt;

    return result;
}

} // namespace

namespace xlnt {
namespace detail {

std::vector<std::uint8_t> encryption_info::calculate_key() const
{
    return is_agile
        ? calculate_agile_key(agile, password)
        : calculate_standard_key(standard, password);
}

encryption_info encryption_info::generate_encryption_info(const std::u16string &password)
{
    return generate_agile_encryption_info(password);
}

} // namespace detail
} // namespace xlnt
