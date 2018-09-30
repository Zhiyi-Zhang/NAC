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

#include "producer.hpp"
#include "consumer.hpp"
#include "owner.hpp"
#include "crypto/rsa.hpp"
#include "data-enc-dec.hpp"
#include "identity-management-fixture.hpp"
#include <iostream>

namespace ndn {
namespace nac {
namespace tests {

const uint8_t plaintext[1024] = {1};

BOOST_FIXTURE_TEST_SUITE(TestProducer, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(PreparePackets)
{
  // prepare certificates for owner and producer
  RsaKeyParams params;
  auto ownerId = addIdentity(Name("/access-controller"));
  auto ownerKey = ownerId.getDefaultKey();
  auto ownerCert = ownerKey.getDefaultCertificate();

  auto producerId = addIdentity(Name("/encryptor"));
  auto producerKey = producerId.getDefaultKey();
  auto producerCert = producerKey.getDefaultCertificate();

  // create owner and KEK
  Owner owner(ownerCert, m_keyChain);
  auto eKeyData = owner.generateEncKeyData(Name("/producer/dataset1/example"));

  std::cout << "eKeyData Data \n" << *eKeyData;
  std::cout << "eKeyData Data size :" << eKeyData->wireEncode().size() << std::endl;
  std::cout << "eKeyData Data name size :" << eKeyData->getName().wireEncode().size() << std::endl;
  std::cout << "===============================\n";

  // create producer
  Producer producer(producerCert, m_keyChain);
  // Name keyName;
  // Buffer keyBuffer;
  // std::tie(keyName, keyBuffer) = producer.parseEKeyData(*eKeyData);
  // BOOST_CHECK_EQUAL(keyName.getPrefix(-2), Name("/producer/dataset1/example"));

  // auto eKeys = owner.getEncryptionKeys();
  // auto rightKey = eKeys[keyName.getPrefix(-2)];
  // BOOST_CHECK_EQUAL_COLLECTIONS(rightKey.begin(), rightKey.end(),
  //                               keyBuffer.begin(), keyBuffer.end());

  shared_ptr<Data> contentData = nullptr;
  shared_ptr<Data> ckData = nullptr;
  std::tie(contentData, ckData) = producer.produce(Name("/producer/dataset1/example/data1"),
                                                   plaintext, sizeof(plaintext), *eKeyData);

  std::cout << "content Data \n" << *contentData;
  std::cout << "content Data size :" << contentData->wireEncode().size() << std::endl;
  std::cout << "content Data name size :" << contentData->getName().wireEncode().size() << std::endl;
  std::cout << "===============================\n";

  std::cout << "ck Data \n" << *ckData;
  std::cout << "ck Data size :" << ckData->wireEncode().size() << std::endl;
  std::cout << "ck Data name size :" << ckData->getName().wireEncode().size() << std::endl;
  std::cout << "===============================\n";

  auto dKeys = owner.getDecryptionKeys();
  auto priKey = dKeys[Name("/producer/dataset1/example")];
  auto afterDec = decryptDataContent(contentData->getContent(), ckData->getContent(), priKey.data(), priKey.size());

  BOOST_CHECK_EQUAL_COLLECTIONS(plaintext, plaintext + sizeof(plaintext),
                                afterDec.begin(), afterDec.end());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nac
} // namespace ndn
