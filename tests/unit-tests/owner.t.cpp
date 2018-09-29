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

#include "owner.hpp"
#include "consumer.hpp"
#include "producer.hpp"
#include "crypto/rsa.hpp"
#include "data-enc-dec.hpp"
#include "identity-management-fixture.hpp"
#include <iostream>

namespace ndn {
namespace nac {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestOwner, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(PreparePackets)
{
  RsaKeyParams params;
  auto ownerId = addIdentity(Name("/access-controller"));
  auto ownerKey = ownerId.getDefaultKey();
  auto ownerCert = ownerKey.getDefaultCertificate();

  auto producerId = addIdentity(Name("/producer"), params);
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
  auto dKeyData = owner.generateDecKeyData(Name("/access-controller"), Name("/producer/dataset1/example"), consumerCert);

  std::cout << "dKeyData Data \n" << *dKeyData;
  std::cout << "dKeyData Data size :" << dKeyData->wireEncode().size() << std::endl;
  std::cout << "dKeyData Data name size :" << dKeyData->getName().wireEncode().size() << std::endl;
  std::cout << "===============================\n";


  // auto eKeyData = owner.generateEncKeyData(Name("/access-controller"), Name("/producer/dataset1/example"));

  // BOOST_CHECK_EQUAL(dKeyData->getName(),
  //                   Name("/owner/consumer/D-KEY/location/8am/9am"));
  // BOOST_CHECK_EQUAL(eKeyData->getName(),
  //                   Name("/owner/E-KEY/location/8am/9am"));

  // auto dKey = Consumer::decryptDKeyData(*dKeyData, consumerPriKey);
  // auto dKeys = owner.getDecryptionKeys();
  // auto rightDKey = dKeys[Name("/location/8am/9am")];
  // BOOST_CHECK_EQUAL_COLLECTIONS(dKey.begin(), dKey.end(),
  //                               rightDKey.begin(), rightDKey.end());

  // Producer producer(producerCert, m_keyChain);
  // Name keyName;
  // Buffer keyBuffer;
  // std::tie(keyName, keyBuffer) = producer.parseEKeyData(*eKeyData);
  // BOOST_CHECK_EQUAL(keyName, Name("/location/8am/9am"));
  // auto eKeys = owner.getEncryptionKeys();
  // auto rightEKey = eKeys[keyName];
  // BOOST_CHECK_EQUAL_COLLECTIONS(rightEKey.begin(), rightEKey.end(),
  //                               keyBuffer.begin(), keyBuffer.end());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nac
} // namespace ndn
