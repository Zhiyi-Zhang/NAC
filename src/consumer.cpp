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
#include "data-enc-dec.hpp"
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nac {

shared_ptr<Interest>
Consumer::constructCKeyInterest(const Data& contentData)
{
  // Naming Convention: /prefix/CK/<key-id>/ENC-BY/<access manager prefix>
  //                    /NAC/granularity/KEK/<key-id>
  // Interest name: /prefix/CK/<key-id>
  auto contentBlock = contentData.getContent();
  contentBlock.parse();
  Name cKeyName(contentBlock.get(tlv::Name));
  auto request = make_shared<Interest>(cKeyName);
  request->setMustBeFresh(true);
  return request;
}

shared_ptr<Interest>
Consumer::constructDKeyInterest(const Data& ckData, const Name& consumerIdentity)
{
  int index = 0;
  for (size_t i = 0; i < ckData.getName().size(); i++) {
    if (ckData.getName().get(i) == NAME_COMPONENT_BY) {
      index = i;
    }
  }
  if (index == 0) {
    BOOST_THROW_EXCEPTION(Error("Unrecognized incoming Data Name"));
  }
  // /<access manager prefix>/NAC/granularity/KEK/<key-id>
  Name asymmetricKeyName = ckData.getName().getSubName(index + 1);
  auto asymmetricKeyId = ckData.getName().get(-1);

  // Name Convention: /<access manager prefix>/NAC/granularity/KDK/<key-id>/ENC-BY
  //                  consumer-identity/KEY/<key-id>

  Name interestName(asymmetricKeyName.getPrefix(-2));
  interestName.append(NAME_COMPONENT_D_KEY).append(asymmetricKeyId)
    .append(NAME_COMPONENT_BY)
    .append(consumerIdentity);
  auto request = make_shared<Interest>(interestName);
  request->setMustBeFresh(true);
  return request;
}


Buffer
Consumer::decryptContentData(const Data& contentData, const Data& cKeyData, const Buffer& dKey)
{
  Buffer content = decryptDataContent(contentData.getContent(), cKeyData.getContent(),
                                      dKey.data(), dKey.size());
  std::cerr << "Successfully decrypt the content data and get the content in plaintext \n";
  return content;
}


Buffer
Consumer::decryptDKeyData(const Data& dKeyData, const Buffer& identityPriKey)
{
  Buffer decKey = decryptDataContent(dKeyData.getContent(),
                                     identityPriKey.data(), identityPriKey.size());
  std::cerr << "Successfully decrypt the D-KEY data and get the decryption KEY\n";
  return decKey;
}

} // namespace nac
} // namespace ndn
