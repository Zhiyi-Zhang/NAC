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

#include "consumer.hpp"
#include "owner.hpp"
#include "producer.hpp"
#include "crypto/rsa.hpp"
#include "data-enc-dec.hpp"
#include "identity-management-fixture.hpp"
#include <iostream>

namespace ndn {
namespace nac {
namespace tests {

const uint8_t plaintext[1024] = {1};

BOOST_FIXTURE_TEST_SUITE(TestConsumer, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(PreparePackets)
{
  RsaKeyParams params;
  auto ownerId = addIdentity(Name("/access-manager"));
  auto ownerKey = ownerId.getDefaultKey();
  auto ownerCert = ownerKey.getDefaultCertificate();

  auto producerId = addIdentity(Name("/producer"));
  auto producerKey = producerId.getDefaultKey();
  auto producerCert = producerKey.getDefaultCertificate();

  auto consumerPriKey = crypto::Rsa::generateKey(params);
  auto consumerPubKey = crypto::Rsa::deriveEncryptKey(consumerPriKey);
  security::v2::Certificate consumerCert;
  consumerCert.setName(Name("/consumer/KEY/key001/self/001"));
  consumerCert.setContent(makeBinaryBlock(tlv::Content,
                                          consumerPubKey.data(), consumerPubKey.size()));
  signData(consumerCert);

  Owner owner(ownerCert, m_keyChain);
  auto dKeyData = owner.generateDecKeyData(Name("/producer/dataset1/example"), consumerCert);
  auto eKeyData = owner.generateEncKeyData(Name("/producer/dataset1/example"));

  Producer producer(producerCert, m_keyChain);
  // Name keyName;
  // Buffer keyBuffer;
  // std::tie(keyName, keyBuffer) = producer.parseEKeyData(*eKeyData);
  shared_ptr<Data> contentData = nullptr;
  shared_ptr<Data> ckData = nullptr;
  std::tie(contentData, ckData) = producer.produce(Name("/producer/dataset1/example/data1"),
                                                   plaintext, sizeof(plaintext), *eKeyData);

  auto ckRequest = Consumer::constructCKeyInterest(*contentData);
  BOOST_CHECK_EQUAL(ckRequest->getName().getPrefix(-1), Name("/producer/CK"));

  auto request = Consumer::constructDKeyInterest(*ckData, Name("/consumer"));
  BOOST_CHECK_EQUAL(request->getName().getPrefix(-3),
                    Name("/access-manager/NAC/producer/dataset1/example/KDK"));

  auto dKey = Consumer::decryptDKeyData(*dKeyData, consumerPriKey);
  auto dKeys = owner.getDecryptionKeys();
  auto rightDKey = dKeys[Name("/producer/dataset1/example")];
  BOOST_CHECK_EQUAL_COLLECTIONS(dKey.begin(), dKey.end(),
                                rightDKey.begin(), rightDKey.end());

  auto afterDec = Consumer::decryptContentData(*contentData, *ckData, dKey);
  BOOST_CHECK_EQUAL_COLLECTIONS(plaintext, plaintext + sizeof(plaintext),
                                afterDec.begin(), afterDec.end());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nac
} // namespace ndn
