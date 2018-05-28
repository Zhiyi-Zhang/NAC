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

/**
 * In NAC, the consumer consumes content Data packet carrying the encrypted content
 * produced by the producers. To decrypt the content, the consumer should learn D-KEY
 * from the system owner. D-KEY data is encrypted and the consumer will use its own
 * identity private key to decrypt the D-KEY
 */
class Consumer
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

public:
  /**
   * @brief Construct an Interest for the missing D-KEY
   * @note The function will NOT verify the signature, application should first
   *       verify the data signature and then invoke the function.
   * @note The returned Interest packet is supposed to fetch a D-KEY data from the
   *       owner. The app developer then should invoke Consumer::decryptDKeyData to
   *       get D-KEY buffer and then further use Consumer::decryptConentData to obtain
   *       the plaintext in the content Data
   *
   * @param contentData The Data packet carrying the encrypted content
   * @param ownerPrefix The name prefix of the data owner in the NAC system
   * @param consumerIdentity The consumer identity
   */
  static shared_ptr<Interest>
  constructDKeyInterest(const Data& contentData,
                        const Name& ownerPrefix, const Name& consumerIdentity);

  /**
   * @brief Decrypt the content Data using the @p decryption key
   * @note The function will NOT verify the signature, application should first
   *        verify the data signature and then invoke the function.
   * @note The decryption key can be obtained by function Consumer::decryptDKeyData
   *
   * @param contentData The Data packet carrying the encrypted content
   * @param dKey The D-KEY obtained from Consumer::decryptDKeyData
   */
  static Buffer
  decryptContentData(const Data& contentData, const Buffer& dKey);

  /**
   * @brief Decrypt the D-KEY Data provided by the data owner
   * @note The function will NOT verify the signature, application should first
   *       verify the data signature and then invoke the function.
   *
   * @param dKeyData The Data packet carrying the encrypted D-KEY
   * @param identityPriKey Consumer's identity private key (paired with consumer cert key)
   */
  static Buffer
  decryptDKeyData(const Data& dKeyData, const Buffer& identityPriKey);
};


} // namespace nac
} // namespace ndn

#endif // NAC_CONSUMER_HPP
