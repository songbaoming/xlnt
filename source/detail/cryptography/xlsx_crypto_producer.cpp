// Copyright (c) 2014-2021 Thomas Fussell
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

#include <xlnt/utils/exceptions.hpp>
#include <detail/constants.hpp>
#include <detail/cryptography/aes.hpp>
#include <detail/cryptography/base64.hpp>
#include <detail/cryptography/compound_document.hpp>
#include <detail/cryptography/encryption_info.hpp>
#include <detail/cryptography/hmac.h>
#include <detail/cryptography/value_traits.hpp>
#include <detail/cryptography/xlsx_crypto_producer.hpp>
#include <detail/external/include_libstudxml.hpp>
#include <detail/serialization/vector_streambuf.hpp>
#include <detail/serialization/xlsx_producer.hpp>
#include <detail/serialization/zstream.hpp>
#include <detail/unicode.hpp>

namespace {

using xlnt::detail::encryption_info;

void write_agile_encryption_info(
    const encryption_info &info,
    std::ostream &info_stream)
{
    const auto version_major = std::uint16_t(4);
    const auto version_minor = std::uint16_t(4);
    const auto encryption_flags = std::uint32_t(0x40);

    info_stream.write(reinterpret_cast<const char *>(&version_major), sizeof(std::uint16_t));
    info_stream.write(reinterpret_cast<const char *>(&version_minor), sizeof(std::uint16_t));
    info_stream.write(reinterpret_cast<const char *>(&encryption_flags), sizeof(std::uint32_t));

    static const auto &xmlns = xlnt::constants::ns("encryption");
    static const auto &xmlns_p = xlnt::constants::ns("encryption-password");
    static const auto &xmlns_c = xlnt::constants::ns("encryption-certificate");

    xml::serializer serializer(info_stream, "EncryptionInfo", 0);

    serializer.xml_decl("1.0", "UTF-8", "yes");

    serializer.start_element(xmlns, "encryption");

    serializer.namespace_decl(xmlns, "");
    serializer.namespace_decl(xmlns_p, "p");
    serializer.namespace_decl(xmlns_c, "c");

    const auto key_data = info.agile.key_data;
    serializer.start_element(xmlns, "keyData");
    serializer.attribute("saltSize", key_data.salt_size);
    serializer.attribute("blockSize", key_data.block_size);
    serializer.attribute("keyBits", key_data.key_bits);
    serializer.attribute("hashSize", key_data.hash_size);
    serializer.attribute("cipherAlgorithm", key_data.cipher_algorithm);
    serializer.attribute("cipherChaining", key_data.cipher_chaining);
    serializer.attribute("hashAlgorithm", key_data.hash);
    serializer.attribute("saltValue",
        xlnt::detail::encode_base64(key_data.salt_value));
    serializer.end_element(xmlns, "keyData");

    const auto data_integrity = info.agile.data_integrity;
    serializer.start_element(xmlns, "dataIntegrity");
    serializer.attribute("encryptedHmacKey",
        xlnt::detail::encode_base64(data_integrity.hmac_key));
    serializer.attribute("encryptedHmacValue",
        xlnt::detail::encode_base64(data_integrity.hmac_value));
    serializer.end_element(xmlns, "dataIntegrity");

    const auto key_encryptor = info.agile.key_encryptor;
    serializer.start_element(xmlns, "keyEncryptors");
    serializer.start_element(xmlns, "keyEncryptor");
    serializer.attribute("uri", xmlns_p);
    serializer.start_element(xmlns_p, "encryptedKey");
    serializer.attribute("spinCount", key_encryptor.spin_count);
    serializer.attribute("saltSize", key_encryptor.salt_size);
    serializer.attribute("blockSize", key_encryptor.block_size);
    serializer.attribute("keyBits", key_encryptor.key_bits);
    serializer.attribute("hashSize", key_encryptor.hash_size);
    serializer.attribute("cipherAlgorithm", key_encryptor.cipher_algorithm);
    serializer.attribute("cipherChaining", key_encryptor.cipher_chaining);
    serializer.attribute("hashAlgorithm", key_encryptor.hash);
    serializer.attribute("saltValue",
        xlnt::detail::encode_base64(key_encryptor.salt_value));
    serializer.attribute("encryptedVerifierHashInput",
        xlnt::detail::encode_base64(key_encryptor.verifier_hash_input));
    serializer.attribute("encryptedVerifierHashValue",
        xlnt::detail::encode_base64(key_encryptor.verifier_hash_value));
    serializer.attribute("encryptedKeyValue",
        xlnt::detail::encode_base64(key_encryptor.encrypted_key_value));
    serializer.end_element(xmlns_p, "encryptedKey");
    serializer.end_element(xmlns, "keyEncryptor");
    serializer.end_element(xmlns, "keyEncryptors");

    serializer.end_element(xmlns, "encryption");
}

void write_standard_encryption_info(const encryption_info &info, std::ostream &info_stream)
{
    auto result = std::vector<std::uint8_t>();
    auto writer = xlnt::detail::binary_writer<std::uint8_t>(result);

    const auto version_major = std::uint16_t(4);
    const auto version_minor = std::uint16_t(2);
    const auto encryption_flags = std::uint32_t(0x10 & 0x20);

    writer.write(version_major);
    writer.write(version_minor);
    writer.write(encryption_flags);

    const auto header_length = std::uint32_t(32); // calculate this!

    writer.write(header_length);
    writer.write(std::uint32_t(0)); // skip_flags
    writer.write(std::uint32_t(0)); // size_extra
    writer.write(std::uint32_t(0x0000660E));
    writer.write(std::uint32_t(0x00008004));
    writer.write(std::uint32_t(info.standard.key_bits));
    writer.write(std::uint32_t(0x00000018));
    writer.write(std::uint32_t(0));
    writer.write(std::uint32_t(0));

    const auto provider = std::u16string(u"Microsoft Enhanced RSA and AES Cryptographic Provider");
    writer.append(xlnt::detail::string_to_bytes(provider));

    writer.write(std::uint32_t(info.standard.salt.size()));
    writer.append(info.standard.salt);

    writer.append(info.standard.encrypted_verifier);

    writer.write(std::uint32_t(20));
    writer.append(info.standard.encrypted_verifier_hash);

    info_stream.write(reinterpret_cast<char *>(result.data()),
        static_cast<std::streamsize>(result.size()));
}

void encrypt_xlsx_agile(
    encryption_info &info,
    const std::vector<std::uint8_t> &plaintext,
    std::ostream &ciphertext_stream)
{
    const auto length = static_cast<std::uint64_t>(plaintext.size());
    ciphertext_stream.write(reinterpret_cast<const char *>(&length), sizeof(std::uint64_t));

    auto &key = info.encryption_key;

    auto salt_size = info.agile.key_data.salt_size;
    auto salt_with_block_key = info.agile.key_data.salt_value;
    salt_with_block_key.resize(salt_size + sizeof(std::uint32_t), 0);
    auto &segment_index = *reinterpret_cast<std::uint32_t *>(salt_with_block_key.data() + salt_size);

    auto segment = std::vector<std::uint8_t>(4096, 0);

    HMAC_CTX ctx;
    auto &salt = info.agile.data_integrity.hmac_value;
    hmac_init(&ctx, DIGEST_sha512(), salt.data(), salt.size());
    hmac_update(&ctx, (const uint8_t *)&length, sizeof(length));
    for (auto i = std::size_t(0); i < length; i += 4096)
    {
        auto iv = hash(info.agile.key_encryptor.hash, salt_with_block_key);
        iv.resize(16);

        auto start = plaintext.begin() + static_cast<std::ptrdiff_t>(i);
        auto bytes = std::min(std::size_t(length - i), std::size_t(4096));
        std::copy(start, start + static_cast<std::ptrdiff_t>(bytes), segment.begin());
        auto encrypted_segment = xlnt::detail::aes_cbc_encrypt(segment, key, iv);
        auto mod = bytes % info.agile.key_encryptor.block_size;
        if (mod)
            bytes = bytes + info.agile.key_encryptor.block_size - mod;
        hmac_update(&ctx, (const uint8_t *)encrypted_segment.data(), bytes);
        ciphertext_stream.write(reinterpret_cast<char *>(encrypted_segment.data()),
            static_cast<std::streamsize>(bytes));
        ++segment_index;
    }

    size_t len = 0;
    hmac_finish(&ctx, segment.data(), &len);
    segment.resize(len);

    const std::array<std::uint8_t, 8> integrity_block_key2 = {{0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33}};
    auto combined(info.agile.key_data.salt_value);
    combined.insert(combined.end(), integrity_block_key2.begin(), integrity_block_key2.end());
    auto iv = xlnt::detail::hash(info.agile.key_data.hash, combined);
    iv.resize(info.agile.key_data.block_size);

    info.agile.data_integrity.hmac_value = xlnt::detail::aes_cbc_encrypt(segment, key, iv);
}

void encrypt_xlsx_standard(
    const encryption_info &info,
    const std::vector<std::uint8_t> &plaintext,
    std::ostream &ciphertext_stream)
{
    const auto length = static_cast<std::uint64_t>(plaintext.size());
    ciphertext_stream.write(reinterpret_cast<const char *>(&length), sizeof(std::uint64_t));

    auto key = info.calculate_key();
    auto segment = std::vector<std::uint8_t>(4096, 0);

    for (auto i = std::size_t(0); i < length; ++i)
    {
        auto start = plaintext.begin() + static_cast<std::ptrdiff_t>(i);
        auto bytes = std::min(std::size_t(length - i), std::size_t(4096));
        std::copy(start, start + static_cast<std::ptrdiff_t>(bytes), segment.begin());
        auto encrypted_segment = xlnt::detail::aes_ecb_encrypt(segment, key);
        ciphertext_stream.write(reinterpret_cast<char *>(encrypted_segment.data()),
            static_cast<std::streamsize>(bytes));
    }
}

void write_data_spaces(xlnt::detail::compound_document &document)
{
    // /\006DataSpaces/Version
    static const char version[76] = {
        0x3C, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x73, 0x00,
        0x6F, 0x00, 0x66, 0x00, 0x74, 0x00, 0x2E, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x74, 0x00,
        0x61, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x65, 0x00, 0x72, 0x00, 0x2E, 0x00, 0x44, 0x00, 0x61, 0x00,
        0x74, 0x00, 0x61, 0x00, 0x53, 0x00, 0x70, 0x00, 0x61, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    document.open_write_stream("/\006DataSpaces/Version").write(version, sizeof(version));

    // /\006DataSpaces/DataSpaceMap
    static const char data_space_map[112] = {
        0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x45, 0x00, 0x6E, 0x00, 0x63, 0x00, 0x72, 0x00,
        0x79, 0x00, 0x70, 0x00, 0x74, 0x00, 0x65, 0x00, 0x64, 0x00, 0x50, 0x00, 0x61, 0x00, 0x63, 0x00,
        0x6B, 0x00, 0x61, 0x00, 0x67, 0x00, 0x65, 0x00, 0x32, 0x00, 0x00, 0x00, 0x53, 0x00, 0x74, 0x00,
        0x72, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x45, 0x00, 0x6E, 0x00, 0x63, 0x00, 0x72, 0x00,
        0x79, 0x00, 0x70, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x44, 0x00, 0x61, 0x00,
        0x74, 0x00, 0x61, 0x00, 0x53, 0x00, 0x70, 0x00, 0x61, 0x00, 0x63, 0x00, 0x65, 0x00, 0x00, 0x00};
    document.open_write_stream("/\006DataSpaces/DataSpaceMap").write(data_space_map, sizeof(data_space_map));

    // /\006DataSpaces/DataSpaceInfo/StrongEncryptionDataSpace
    static const char data[64] = {
        0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x53, 0x00, 0x74, 0x00,
        0x72, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x45, 0x00, 0x6E, 0x00, 0x63, 0x00, 0x72, 0x00,
        0x79, 0x00, 0x70, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x54, 0x00, 0x72, 0x00,
        0x61, 0x00, 0x6E, 0x00, 0x73, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6D, 0x00, 0x00, 0x00};
    document.open_write_stream("/\006DataSpaces/DataSpaceInfo/StrongEncryptionDataSpace").write(data, sizeof(data));

    // /\006DataSpaces/TransformInfo/StrongEncryptionTransform/\006Primary
    static const char primary[200] = {
        0x58, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x4C, 0x00, 0x00, 0x00, 0x7B, 0x00, 0x46, 0x00,
        0x46, 0x00, 0x39, 0x00, 0x41, 0x00, 0x33, 0x00, 0x46, 0x00, 0x30, 0x00, 0x33, 0x00, 0x2D, 0x00,
        0x35, 0x00, 0x36, 0x00, 0x45, 0x00, 0x46, 0x00, 0x2D, 0x00, 0x34, 0x00, 0x36, 0x00, 0x31, 0x00,
        0x33, 0x00, 0x2D, 0x00, 0x42, 0x00, 0x44, 0x00, 0x44, 0x00, 0x35, 0x00, 0x2D, 0x00, 0x35, 0x00,
        0x41, 0x00, 0x34, 0x00, 0x31, 0x00, 0x43, 0x00, 0x31, 0x00, 0x44, 0x00, 0x30, 0x00, 0x37, 0x00,
        0x32, 0x00, 0x34, 0x00, 0x36, 0x00, 0x7D, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x69, 0x00,
        0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00, 0x2E, 0x00,
        0x43, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x65, 0x00,
        0x72, 0x00, 0x2E, 0x00, 0x45, 0x00, 0x6E, 0x00, 0x63, 0x00, 0x72, 0x00, 0x79, 0x00, 0x70, 0x00,
        0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x54, 0x00, 0x72, 0x00, 0x61, 0x00, 0x6E, 0x00,
        0x73, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6D, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00};
    document.open_write_stream("/\006DataSpaces/TransformInfo/StrongEncryptionTransform/\006Primary")
        .write(primary, sizeof(primary));
}

std::vector<std::uint8_t> encrypt_xlsx(
    const std::vector<std::uint8_t> &plaintext,
    const std::u16string &password)
{
    auto encryption_info = encryption_info::generate_encryption_info(password);

    auto ciphertext = std::vector<std::uint8_t>();

    xlnt::detail::vector_ostreambuf buffer(ciphertext);
    std::ostream stream(&buffer);
    xlnt::detail::compound_document document(stream);

    write_data_spaces(document);

    if (encryption_info.is_agile)
    {
        encrypt_xlsx_agile(encryption_info, plaintext,
            document.open_write_stream("/EncryptedPackage"));
        write_agile_encryption_info(encryption_info,
            document.open_write_stream("/EncryptionInfo"));
    }
    else
    {
        encrypt_xlsx_standard(encryption_info, plaintext,
            document.open_write_stream("/EncryptedPackage"));
        write_standard_encryption_info(encryption_info,
            document.open_write_stream("/EncryptionInfo"));
    }

    return ciphertext;
}

} // namespace

namespace xlnt {
namespace detail {

std::vector<std::uint8_t> XLNT_API encrypt_xlsx(
    const std::vector<std::uint8_t> &plaintext,
    const std::string &password)
{
    return ::encrypt_xlsx(plaintext, utf8_to_utf16(password));
}

void xlsx_producer::write(std::ostream &destination, const std::string &password)
{
    std::vector<std::uint8_t> plaintext;
    vector_ostreambuf plaintext_buffer(plaintext);
    std::ostream decrypted_stream(&plaintext_buffer);
    write(decrypted_stream);
    archive_.reset();

    const auto ciphertext = ::encrypt_xlsx(plaintext, utf8_to_utf16(password));
    vector_istreambuf encrypted_buffer(ciphertext);

    destination << &encrypted_buffer;
}

} // namespace detail
} // namespace xlnt
