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

Consumer::Consumer(const security::v2::Certificate& identityCert,
                   const security::v2::Certificate& ownerCert,
                   const Buffer& decryptionKey,
                   Face& face,
                   uint8_t repeatAttempts)
  : m_cert(identityCert)
  , m_ownerCert(ownerCert)
  , m_identityDecKey(decryptionKey)
  , m_face(face)
  , m_repeatAttempts(repeatAttempts)
{
}


void
Consumer::onPayloadData(const Data& data, const Name& ownerPrefix,
                        const ConsumptionCallback& consumptionCb,
                        const ErrorCallback& errorCb)
{
  int index = 0;
  for (size_t i = 0; i < data.getName().size(); i++) {
    if (data.getName().get(i) == NAME_COMPONENT_BY) {
      index = i;
    }
  }
  if (index == 0) {
    errorCb("Unrecognized incoming Data Name");
    return;
  }

  Name asymmetricKeyName = data.getName().getSubName(index + 1);
  Buffer decKey;
  auto search = m_decKeys.find(asymmetricKeyName);
  if (search != m_decKeys.end()) {
    decKey = m_decKeys[asymmetricKeyName];
    try {
      auto payload = decryptDataContent(data.getContent(), decKey.data(), decKey.size());
      consumptionCb(payload);
      return;
    }
    catch (const std::exception& e) {
      errorCb("Cannot decrypt the payload: " + std::string(e.what()));
      return;
    }
  }

  Name interestName(ownerPrefix);
  interestName.append(security::v2::extractIdentityFromCertName(m_cert.getName()))
    .append(NAME_COMPONENT_D_KEY)
    .append(asymmetricKeyName);
  Interest request(interestName);
  request.setMustBeFresh(true);
  m_face.expressInterest(request,
                         std::bind(&Consumer::onDecryptionKeyData, this, _1, _2, data.getContent(),
                                   asymmetricKeyName, consumptionCb, errorCb),
                         std::bind(&Consumer::handleNack, this, _1, _2, errorCb),
                         std::bind(&Consumer::handleTimeout, this, _1, m_repeatAttempts,
                                   data.getContent(), asymmetricKeyName, consumptionCb, errorCb));
}

Buffer
Consumer::decryptDKeyData(const Data& data, const ErrorCallback& errorCb)
{
  Buffer decKey;
  try {
    decKey = decryptDataContent(data.getContent(),
                                m_identityDecKey.data(), m_identityDecKey.size());
    std::cerr << "Successfully decrypt the D-KEY data and get the decryption KEY" << std::endl;
    return decKey;
  }
  catch (const std::exception& e) {
    errorCb("Cannot decrypt the dec key sent from the owner: " + std::string(e.what()));
    return Buffer();
  }

}

void
Consumer::onDecryptionKeyData(const Interest& interest,
                              const Data& data,
                              const Block& encryptedContent,
                              const Name& asymmetricKeyName,
                              const ConsumptionCallback& consumptionCb,
                              const ErrorCallback& errorCb)
{
  if (!security::verifySignature(data, m_ownerCert)) {
    errorCb("Cannot verify the D-KEY Data signature");
    return;
  }

  Buffer decKey = decryptDKeyData(data, errorCb);
  if (decKey.size() == 0) {
    return;
  }
  try {
    auto payload = decryptDataContent(encryptedContent, decKey.data(), decKey.size());
    consumptionCb(payload);
    return;
  }
  catch (const std::exception& e) {
    errorCb("Cannot decrypt the payload: " + std::string(e.what()));
    return;
  }
}

void
Consumer::handleTimeout(const Interest& interest, int nRetrials,
                        const Block& encryptedContent,
                        const Name& asymmetricKeyName,
                        const ConsumptionCallback& consumptionCb,
                        const ErrorCallback& errorCb)
{
  if (nRetrials > 0) {
    Interest request = interest;
    request.refreshNonce();
    m_face.expressInterest(request,
                           std::bind(&Consumer::onDecryptionKeyData, this, _1, _2, encryptedContent,
                                     asymmetricKeyName, consumptionCb, errorCb),
                           std::bind(&Consumer::handleNack, this, _1, _2, errorCb),
                           std::bind(&Consumer::handleTimeout, this, _1, nRetrials - 1,
                                     encryptedContent, asymmetricKeyName, consumptionCb, errorCb));
  }
  else {
    errorCb("Got Timeout after requesting the decryption key from owner");
  }
}

void
Consumer::handleNack(const Interest& interest,
                     const lp::Nack& nack,
                     const ErrorCallback& errorCb)
{
  errorCb("Got NACK after requesting the decryption key from owner");
}

} // namespace nac
} // namespace ndn
