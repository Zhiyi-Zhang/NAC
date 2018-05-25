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

namespace ndn {
namespace nac {

Producer::Producer(const security::v2::Certificate& identityCert,
                   security::v2::KeyChain& keyChain)
  : m_cert(identityCert)
  , m_keyChain(keyChain)
{
}

void
Producer::produce(const Name& dataName, const uint8_t* payload, size_t payloadLen,
                  const Buffer& encryptionKey,
                  const SuccessCallback& onDataProduceCb, const ErrorCallback& errorCallback)
{
  Data data;
  data.setName(dataName);
  try {
    data.setContent(encryptDataContent(payload, payloadLen,
                                       encryptionKey.data(), encryptionKey.size()));
    m_keyChain.sign(data, signingByCertificate(m_cert));
    onDataProduceCb(data);
  }
  catch (const std::exception& e) {
    errorCallback(e.what());
  }
}


} // namespace nac
} // namespace ndn
