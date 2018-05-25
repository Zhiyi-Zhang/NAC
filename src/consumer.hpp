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

#ifndef NAC_CONSUMER_HPP
#define NAC_CONSUMER_HPP

#include "common.hpp"

namespace ndn {
namespace nac {

class Consumer
{
public:
  using ErrorCallback = function<void (const std::string&)>;
  using ConsumptionCallback = function<void (const Buffer&)>;

public:
  Consumer(const security::v2::Certificate& identityCert,
           const security::v2::Certificate& ownerCert,
           security::v2::KeyChain& keyChain, Face& face,
           uint8_t repeatAttempts = 3);

  /**
   * @brief The function will NOT verify the signature, application can first
   *        verify the data signature and then invoke the function.
   *        Will the decryption is missing, the function will send an Interest
   *        to fetch the corresponding decryption key Data
   *
   * @return the payload buffer
   */
  Buffer
  onPayloadData(const Data& data);

private:
  /**
   * @brief The function will verify the signature using owner's certificate
   * @return the decryption key buffer
   */
  Buffer
  onDecryptionKeyData(const Data& data);

private:
  security::v2::Certificate m_cert;
  security::v2::Certificate m_ownerCert;
  security::v2::KeyChain& m_keyChain;
  Face& m_face;
  uint8_t m_repeatAttempts;

  std::map<Name, Buffer> m_decryptionKeys;
};


} // namespace nac
} // namespace ndn

#endif // NAC_CONSUMER_HPP
