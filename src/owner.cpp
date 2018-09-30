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
#include "data-enc-dec.hpp"
#include "crypto/rsa.hpp"
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace nac {

Owner::Owner(const security::v2::Certificate& identityCert,
             security::v2::KeyChain& keyChain)
  : m_cert(identityCert)
  , m_keyChain(keyChain)
{
}

shared_ptr<Data>
Owner::generateDecKeyData(const Name& granularity,
                          const security::v2::Certificate& consumerCert)
{
  Buffer encKey = consumerCert.getPublicKey();
  Buffer payload;
  auto search = m_decKeys.find(granularity);
  if (search != m_decKeys.end()) {
    payload = m_decKeys[granularity];
  }
  else {
    RsaKeyParams params;
    payload = crypto::Rsa::generateKey(params);
    m_decKeys[granularity] = payload;
    m_encKeys[granularity] = crypto::Rsa::deriveEncryptKey(payload);
  }

  // Naming Convention: /prefix/NAC/granularity/KDK/<key-id>/ENC-BY
  //                    consumer-identity/KEY/<key-id>
  auto dKeyData = make_shared<Data>();
  Name name(security::v2::extractIdentityFromCertName(m_cert.getName()));
  name.append(NAME_COMPONENT_NAC).append(granularity).append(NAME_COMPONENT_D_KEY)
    .append(security::v2::extractKeyNameFromCertName(consumerCert.getName()));
  dKeyData->setName(name);
  dKeyData->setContent(encryptDataContentWithCK(payload.data(), payload.size(),
                                                encKey.data(), encKey.size()));
  m_keyChain.sign(*dKeyData, signingByCertificate(m_cert));
  return dKeyData;
}

shared_ptr<Data>
Owner::generateEncKeyData(const Name& granularity)
{
  Buffer payload;
  auto search = m_encKeys.find(granularity);
  if (search != m_encKeys.end()) {
    payload = m_encKeys[granularity];
  }
  else {
    RsaKeyParams params;
    auto decKey = crypto::Rsa::generateKey(params);
    m_decKeys[granularity] = decKey;
    m_encKeys[granularity] = crypto::Rsa::deriveEncryptKey(decKey);
    payload = m_encKeys[granularity];
  }

  // Naming Convention: /prefix/NAC/granularity/KEK/<key-id>
  auto eKeyData = make_shared<Data>();
  Name name(security::v2::extractIdentityFromCertName(m_cert.getName()));
  name.append(NAME_COMPONENT_NAC).append(granularity)
    .append(NAME_COMPONENT_E_KEY).append(std::to_string(random::generateSecureWord32()));;
  eKeyData->setName(name);
  eKeyData->setContent(makeBinaryBlock(tlv::Content, payload.data(), payload.size()));
  m_keyChain.sign(*eKeyData, signingByCertificate(m_cert));
  return eKeyData;
}


} // namespace nac
} // namespace ndn
