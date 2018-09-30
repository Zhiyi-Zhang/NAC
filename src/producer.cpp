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
#include "data-enc-dec.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace nac {

Producer::Producer(const security::v2::Certificate& identityCert,
                   security::v2::KeyChain& keyChain)
  : m_cert(identityCert)
  , m_keyChain(keyChain)
{
}

std::tuple<shared_ptr<Data>, shared_ptr<Data>>
Producer::produce(const Name& name, const uint8_t* payload, size_t payloadLen,
                  const Data& eKeyData)
{
  // prepare
  auto eKeyContent = eKeyData.getContent();
  Block encryptedContent;
  Block encryptedCK;
  std::tie(encryptedContent, encryptedCK) = encryptDataContent(payload, payloadLen,
                                                               eKeyContent.value(),
                                                               eKeyContent.value_size());
  Name ckName = security::v2::extractIdentityFromCertName(m_cert.getName());
  ckName.append("CK").append(std::to_string(random::generateSecureWord32()));


  // data packet
  auto data = make_shared<Data>();
  data->setName(name);
  auto content = makeEmptyBlock(tlv::Content);
  auto ckNameBlock = ckName.wireEncode();
  content.push_back(ckNameBlock);
  content.push_back(encryptedContent);
  content.encode();
  data->setContent(content);
  m_keyChain.sign(*data, signingByCertificate(m_cert));


  // ck data packet
  // Naming Convention: /prefix/CK/<key-id>/ENC-BY/<access manager prefix>
  //                    /NAC/granularity/KEK/<key-id>
  auto ckData = make_shared<Data>();
  Name ckDataName = ckName;
  ckDataName.append(NAME_COMPONENT_BY).append(eKeyData.getName());
  ckData->setName(ckDataName);
  ckData->setContent(encryptedCK);
  m_keyChain.sign(*ckData, signingByCertificate(m_cert));
  return std::make_tuple(data, ckData);
}

// std::tuple<Name, Buffer>
// Producer::parseEKeyData(const Data& eKeyData)
// {
//   // Naming Convention: /prefix/NAC/granularity/KEK/<key-id>

//   int nac_index = 0;
//   for (size_t i = 0; i < eKeyData.getName().size(); i++) {
//     if (eKeyData.getName().get(i) == NAME_COMPONENT_NAC) {
//       nac_index = i;
//     }
//   }
//   if (nac_index == 0) {
//     BOOST_THROW_EXCEPTION(Error("Unrecognized incoming E-KEY Data Name"));
//   }

//   Name kekName = eKeyData.getName().getSubName(nac_index + 1);
//   auto content = eKeyData.getContent();
//   Buffer encKey(content.value(), content.value_size());
//   return std::make_tuple(kekName, encKey);
// }


} // namespace nac
} // namespace ndn
