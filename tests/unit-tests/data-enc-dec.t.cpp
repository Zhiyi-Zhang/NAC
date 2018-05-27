/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2018,  Regents of the University of California
 *
 * This file is part of NAC (Name-based Access Control for NDN).
 * See AUTHORS.md for complete list of NAC authors and contributors.
 *
 * NAC is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NAC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NAC, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#include "data-enc-dec.hpp"
#include "crypto/aes.hpp"
#include "crypto/rsa.hpp"
#include "boost-test.hpp"

namespace ndn {
namespace nac {
namespace tests {

const uint8_t plaintext[] = { 0x41, 0x45, 0x53, 0x2d, 0x45, 0x6e, 0x63, 0x72,
                              0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74};

BOOST_AUTO_TEST_SUITE(TestDataEncDec)

BOOST_AUTO_TEST_CASE(EncryptionDecryption)
{
  RsaKeyParams params;
  auto priKey = crypto::Rsa::generateKey(params);
  auto pubKey = crypto::Rsa::deriveEncryptKey(priKey);

  auto dataBlock = encryptDataContent(plaintext, sizeof(plaintext),
                                      pubKey.data(), pubKey.size());

  Buffer encryptedAesKey(dataBlock.get(ENCRYPTED_AES_KEY).value(),
                         dataBlock.get(ENCRYPTED_AES_KEY).value_size());
  BOOST_CHECK(encryptedAesKey.size() > 0);

  Buffer encryptedPayload(dataBlock.get(ENCRYPTED_PAYLOAD).value(),
                          dataBlock.get(ENCRYPTED_PAYLOAD).value_size());
  BOOST_CHECK(encryptedPayload.size() > 0);

  Buffer iv(dataBlock.get(INITIAL_VECTOR).value(),
            dataBlock.get(INITIAL_VECTOR).value_size());
  BOOST_CHECK(iv.size() > 0);

  auto result = decryptDataContent(dataBlock, priKey.data(), priKey.size());

  BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                plaintext, plaintext + sizeof(plaintext));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nac
} // namespace ndn
