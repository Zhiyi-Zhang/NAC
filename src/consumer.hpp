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
#include <ndn-cxx/face.hpp>

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
           const Buffer& decryptionKey,
           Face& face,
           uint8_t repeatAttempts = 3);

  /**
   * @brief The function will NOT verify the signature, application can first
   *        verify the data signature and then invoke the function.
   *
   * @note When the decryption key is missing, the function will send an Interest
   *       to fetch the corresponding decryption key Data. The owner app should
   *       register the prefix to be able to answer the request Interest.
   *
   */
  void
  onPayloadData(const Data& data, const Name& ownerPrefix,
                const ConsumptionCallback& consumptionCb,
                const ErrorCallback& errorCb);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  /**
   * @brief The function will verify the signature using owner's certificate
   */
  void
  onDecryptionKeyData(const Interest& interest,
                      const Data& data,
                      const Block& encryptedContent,
                      const Name& asymmetricKeyName,
                      const ConsumptionCallback& consumptionCb,
                      const ErrorCallback& errorCb);

  Buffer
  decryptDKeyData(const Data& data, const ErrorCallback& errorCb);

  void
  handleTimeout(const Interest& interest, int nRetrials,
                const Block& encryptedContent,
                const Name& asymmetricKeyName,
                const ConsumptionCallback& consumptionCb,
                const ErrorCallback& errorCb);

  void
  handleNack(const Interest& interest,
             const lp::Nack& nack,
             const ErrorCallback& errorCb);

private:
  security::v2::Certificate m_cert;
  security::v2::Certificate m_ownerCert;
  Buffer m_identityDecKey;
  Face& m_face;
  uint8_t m_repeatAttempts;

  std::map<Name, Buffer> m_decKeys;
};


} // namespace nac
} // namespace ndn

#endif // NAC_CONSUMER_HPP
