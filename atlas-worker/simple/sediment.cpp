#include <vector>
#include <sstream>
#include <bits/stdc++.h>
#include <boost/scope_exit.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "spdlog/spdlog.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "BoardServer.hpp"
#include "Comm.hpp"
#include "CommandLine.hpp"
#include "CryptoServer.hpp"

namespace aarno::atlas::sediment {
//  SEDIMENT PassportCheck Message
//  2 Message Length (network order)
//  2 Digest length (host order)
//  ? digest
//  2 nonce length
//  ? nonce
//  1 Message ID
//  4 Timestamp (bytes host order?)
//  1 Device ID length
//  ? Device ID
//  1 provider id length
//  ? provider id
//  1 verifier id length
//  ? verifier id
//  4 issue timestamp
//  4 expire timestamp
//  2 signature length (host order)
//  ? signature
//

    int SHA256_Sign(const char *msg, size_t mlen, uint8_t *&sig, size_t &slen, EVP_PKEY *signingKey) {
        if (!msg) {
            SPDLOG_ERROR("NULL msg");
            return -1;
        }

        if (!mlen) {
            SPDLOG_ERROR("zero mlen");
            return -1;
        }

        sig = nullptr;
        slen = 0;

        EVP_MD_CTX *evp_md_ctx = nullptr;
        evp_md_ctx = EVP_MD_CTX_create();
        if (nullptr != evp_md_ctx) {
            BOOST_SCOPE_EXIT(&evp_md_ctx) {
                    if (evp_md_ctx) {
                        EVP_MD_CTX_destroy(evp_md_ctx);
                        evp_md_ctx = nullptr;
                    }
                }
            BOOST_SCOPE_EXIT_END

            constexpr auto sha256_ = "SHA256";
            const EVP_MD *md = EVP_get_digestbyname(sha256_);
            if (md == nullptr) {
                SPDLOG_ERROR("EVP_get_digestbyname for {} failed, error {}", sha256_, ERR_get_error());
                return -1;
            }

            const auto evp_digestinit = EVP_DigestInit_ex(evp_md_ctx, md, nullptr);
            if (evp_digestinit != 1) {
                SPDLOG_ERROR("EVP_DigestInit_ex for {} failed, rc={} error {}", sha256_, evp_digestinit,
                             ERR_get_error());
                return -1;
            }

            const auto evp_digestsign = EVP_DigestSignInit(evp_md_ctx, nullptr, md, nullptr, signingKey);
            if (evp_digestsign != 1) {
                SPDLOG_ERROR("EVP_DigestSign for {} failed, rc={} error {}", sha256_, evp_digestinit, ERR_get_error());
                return -1;
            }

            const auto evp_digestsignupdate = EVP_DigestSignUpdate(evp_md_ctx, msg, mlen);
            if (evp_digestsign != 1) {
                SPDLOG_ERROR("EVP_DigestSignUpdate for {} failed, rc={} error {}", sha256_, evp_digestsignupdate,
                             ERR_get_error());
                return -1;
            }

            size_t required_size = 0;
            // Get the required size
            const auto evp_digest_sign_final0 = EVP_DigestSignFinal(evp_md_ctx, nullptr, &required_size);
            if (evp_digest_sign_final0 != 1) {
                SPDLOG_ERROR("EVP_DigestSignFinal (size) for {} failed, rc={} error {}", sha256_,
                             evp_digest_sign_final0,
                             ERR_get_error());
                return -1;
            }

            if (required_size <= 0) {
                SPDLOG_ERROR("EVP_DigestSignFinal (size) for {} failed, rc={} required_size={} error {}", sha256_,
                             evp_digest_sign_final0,
                             required_size, ERR_get_error());
                return -1;
            }

            sig = (uint8_t *) OPENSSL_malloc(required_size);
            if (sig == nullptr) {
                SPDLOG_ERROR("OPENSSL_malloc failed, error {}", ERR_get_error());
                return -1;
            }

            slen = required_size;
            const auto evp_digest_sign_final = EVP_DigestSignFinal(evp_md_ctx, sig, &slen);
            if (evp_digest_sign_final != 1) {
                SPDLOG_ERROR("EVP_DigestSignFinal (final) for {} failed, rc={} required_size={} error {}", sha256_,
                             evp_digest_sign_final,
                             required_size, ERR_get_error());
                return -1;
            }

            return 0;
        } else {
            SPDLOG_ERROR("Unable to create EVP_MD_CTX");
            return -1;
        }
    }


std::string PassportCheckMessage(const std::vector<uint8_t> &key,
                                 const std::vector<unsigned char> &nonce,
                                 const uint8_t message_id,
                                 const uint32_t timestamp,
                                 const std::string &device_id,
                                 const std::string &provider_id,
                                 const std::string &verifier_id,
                                 const uint32_t issue_timestamp,
                                 const uint32_t expire_timestamp
) {
    const uint16_t digest_len = 32;
    const uint16_t nonce_len = nonce.size();
    const uint8_t device_id_len = device_id.size();
    const uint8_t provider_id_len = provider_id.size();
    const uint8_t verifier_id_len = verifier_id.size();

    uint16_t total_msg_len = 0;
    uint16_t sig_sha256_len = 256;

    const auto idx_msg_digest_len_end = sizeof(total_msg_len) + sizeof(digest_len);
    const auto idx_digest_end = idx_msg_digest_len_end + digest_len;
    const auto idx_msg_header_end = idx_digest_end
                                    + sizeof(nonce_len)
                                    + nonce_len
                                    + sizeof(message_id)
                                    + sizeof(timestamp)
                                    + sizeof(device_id_len)
                                    + device_id_len;
    total_msg_len = idx_msg_header_end
                    + sizeof(provider_id_len)
                    + provider_id_len
                    + sizeof(verifier_id_len)
                    + verifier_id_len
                    + sizeof(issue_timestamp)
                    + sizeof(expire_timestamp)
                    + sizeof(sig_sha256_len)
                    + sig_sha256_len;

    auto digest = std::string(digest_len, 'R');

    std::stringstream message;

    const auto message_len_network = htons(total_msg_len);
    const auto digest_len_network = htons(digest_len);

    message.write(reinterpret_cast<const char *>(&message_len_network), sizeof(message_len_network));
    message.write(reinterpret_cast<const char *>(&digest_len_network), sizeof(digest_len_network));

    // placeholder values for now, calculate actual digest when rest of message is completed
    message.write(digest.data(), digest_len);
    const auto nonce_len_network = htons(nonce_len);
    message.write(reinterpret_cast<const char *>(&nonce_len_network), sizeof(nonce_len_network));
    message.write(reinterpret_cast<const char *>(nonce.data()), nonce_len);
    message.write(reinterpret_cast<const char *>(&message_id), sizeof(message_id));
    const auto timestamp_network = htonl(timestamp);
    message.write(reinterpret_cast<const char *>(&timestamp_network), sizeof(timestamp_network));
    message.write(reinterpret_cast<const char *>(&device_id_len), sizeof(device_id_len));
    message.write(device_id.data(), device_id_len);
    message.write(reinterpret_cast<const char *>(&provider_id_len), sizeof(provider_id_len));
    message.write(provider_id.data(), provider_id_len);
    message.write(reinterpret_cast<const char *>(&verifier_id_len), sizeof(verifier_id_len));
    message.write(verifier_id.data(), verifier_id_len);
    const auto issue_timestamp_network = htonl(issue_timestamp);
    message.write(reinterpret_cast<const char *>(&issue_timestamp_network), sizeof(issue_timestamp_network));
    const auto expire_timestamp_network = htonl(expire_timestamp);
    message.write(reinterpret_cast<const char *>(&expire_timestamp_network), sizeof(expire_timestamp_network));

    EVP_PKEY *signingKey = nullptr;
    BIO *bio_private = BIO_new_file("/home/elahtinen/atlas/ra/data/sign_key.pem", "r");
    PEM_read_bio_PrivateKey(bio_private, &signingKey, 0, nullptr);
    BIO_flush(bio_private);
    BIO_free(bio_private);

    const auto message_bytes = message.str();
    uint8_t *sig = nullptr;
    size_t sig_len = 0;
    const auto sign_result = SHA256_Sign(
            message_bytes.c_str() + idx_msg_header_end,
            message_bytes.size() - idx_msg_header_end,
            sig,
            sig_len,
            signingKey);

    EVP_PKEY_free(signingKey);
    signingKey = nullptr;

    std::unique_ptr<uint8_t, decltype(std::free) *> passport_sig_guard{sig, std::free};

    if(0 != sign_result || sig_len != sig_sha256_len) {
        SPDLOG_ERROR("SH256 signing failed sign_result=({}) expected (0) sig_len=({}) expected ({})",
                     sign_result, sig_len, sig_sha256_len);
        return "";
    }

    sig_sha256_len = sig_len;
    const auto sig_len_network = htons(sig_len);
    message.write(reinterpret_cast<const char *>(&sig_len_network), sizeof(sig_len_network));
    message.write(reinterpret_cast<const char *>(sig), sig_sha256_len);

    auto final_message_bytes = message.str();

    unsigned int result_size = 0;
    const auto *hmac = reinterpret_cast<const unsigned char *>(final_message_bytes.c_str()) + idx_digest_end;
    auto hmac_size = total_msg_len - idx_digest_end;
    unsigned char *result = HMAC(EVP_sha256(),
                                 key.data(), key.size(),
                                hmac,
                                 total_msg_len - idx_digest_end,
                                 result,
                                 &result_size);

    if (digest_len != result_size) {
        SPDLOG_ERROR("HMAC SIZE error result_size[{}] expected[{}]", result_size, digest_len);
    }

    final_message_bytes.replace(idx_msg_digest_len_end, result_size, (const char *)result);
    return final_message_bytes;
}
}  // namespace aarno::atlas

time_t getTimestamp() {
    long ms;  // Milliseconds
    time_t s; // Seconds
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    s = spec.tv_sec;
    ms = round(spec.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
    if (ms > 999) {
        s++;
        ms = 0;
    }
    return s;
}


class CryptoCalAuthToken : public ICalAuthToken {
private:
public:
    Crypto crypto_;

    void calAuthToken(Message *message, uint8_t *serialized, uint32_t len) override {
        AuthToken &authToken = message->getAuthToken();
        crypto_.calDigest(authToken, serialized, len, message->getPayloadOffset());
    }
};

int main(int argc, char *argv[]) {

    std::string passport_buffer_str{};
    auto *passport_buffer = &passport_buffer_str[0];
    int passport_total_read = 0;
    Vector passport_vec{(unsigned char *) passport_buffer,
                        (int) passport_total_read};
    Passport passport;
    const auto expire_timestamp = getTimestamp();
    passport.setExpireDate(expire_timestamp);
    const auto issue_timestamp = getTimestamp();
    passport.setIssueDate(issue_timestamp);
    auto provider_id = std::string("ProverID0123456789");
    passport.setProverId(provider_id);
    auto verifier_id = std::string("Verifier0987654321");
    passport.setVerifierId(verifier_id);
    SPDLOG_DEBUG("[passport={}]", passport.toString().c_str());

    // exclude the passport_sig
    Vector &passport_sig = passport.getSignature();
    // serialize the passport into an array
    uint32_t passport_size = passport.getSize();
    Vector data(passport_size);
    passport.encode(data);

    Vector &signature = passport.getSignature();

    Vector passport_data(passport_size);

    passport.encode(passport_data);
    passport_size -= (SIGNATURE_LEN_LEN + signature.size()); // exclude the signature in the verification

    // sign the serialized passport
    uint8_t *sig = nullptr;
    size_t slen = 0;


//    cryptoServer.sign_it((const unsigned char *) data.at(0), size, &sig, &slen);
    // TODO: free sig
    signature.resize(slen);
    signature.put(sig, slen);

    CommandLine commandLine;
    commandLine.parseCmdline(argc, argv);

    CryptoServer cryptoServer(commandLine);
    uint8_t *passport_sig_bytes = nullptr;
    size_t passport_sig_size = 0;
    const auto test = data.at(0);
    cryptoServer.sign_it(data.at(0), passport_size, &passport_sig_bytes, &passport_sig_size);
    std::unique_ptr<uint8_t, decltype(std::free) *> passport_sig_guard{passport_sig_bytes, std::free};

    // TODO: free sig
    passport_sig.resize(passport_sig_size);
    passport_sig.put(passport_sig_bytes, passport_sig_size);
    PassportCheck passport_check{passport};

    std::string device_id{"AARNO-001"};
    passport_check.setDeviceID(device_id);

    CryptoCalAuthToken cryptoCalAuthToken{};

    const std::string authKeyStr = "25052EDB8E84D35BF72089EC0333E24DA093F436AD48C956A55ACEC938E0C218";
    std::vector<uint8_t> authKey;
    auto s = authKeyStr.size();
    for (auto it = std::cbegin(authKeyStr); it != std::cend(authKeyStr); std::advance(it, 2)) {
        constexpr int base16 = 16;
        const auto hex_str = std::string(it, it + 2);
        authKey.push_back(stoul(hex_str, nullptr, base16));
    }

    cryptoCalAuthToken.crypto_.changeKey(KEY_AUTH,
                                         authKey.data(),
                                         authKey.size());

    const auto msg_timestamp = getTimestamp();
    uint32_t their_msg_size = 0;
    auto their_msg_bytes = std::unique_ptr<uint8_t, decltype(std::free) *>(Comm::FinalizeMessage(&passport_check, msg_timestamp, cryptoCalAuthToken, their_msg_size), std::free);
    const auto their_msg = std::string(reinterpret_cast<const char *>(their_msg_bytes.get()), their_msg_size);

    const auto our_msg = aarno::atlas::sediment::PassportCheckMessage(
            authKey,
            passport_check.getAuthToken().getNonce(),
            PASSPORT_CHECK,
            msg_timestamp,
            device_id,
            provider_id,
            verifier_id,
            issue_timestamp,
            expire_timestamp);

    if (our_msg != their_msg) {
        std::cout << "message mismatch" << std::endl;
        auto ours = std::cbegin(our_msg);
        auto theirs = std::cbegin(their_msg);
        unsigned int i = 0;
        while (ours != std::end(our_msg) && theirs != std::end(their_msg)) {
            std::cout << i++ << ":" << static_cast<unsigned int>(static_cast<uint8_t>(*ours)) << ", "
                      << static_cast<unsigned int>(static_cast<uint8_t>(*theirs)) << std::endl;
            std::advance(ours, 1);
            std::advance(theirs, 1);
        }
    } else {
        std::cout << "!!!!Matched!!!!" << std::endl;
    }

    return 0;
}

