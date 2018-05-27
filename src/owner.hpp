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

#ifndef NAC_OWNER_HPP
#define NAC_OWNER_HPP

#include "common.hpp"

namespace ndn {
namespace nac {

class Owner
{
public:
  Owner(const security::v2::Certificate& identityCert,
        security::v2::KeyChain& keyChain);

  /**
   * @brief generate the encrypted decryption key for a consumer
   * Naming Convention:
   *   /prefix/consumer-identity/D-KEY/asymmeticKeyName
   */
  shared_ptr<Data>
  generateDecKeyData(const Name& prefix,
                     const Name& asymmeticKeyName,
                     const security::v2::Certificate& consumerCert);

  /**
   * @brief generate the encryption key Data packet
   * Naming Convention:
   *   /prefix/E-KEY/asymmeticKeyName
   */
  shared_ptr<Data>
  generateEncKeyData(const Name& prefix,
                     const Name& asymmeticKeyName);

  const std::map<Name, Buffer>
  getDecryptionKeys()
  {
    return m_decKeys;
  }

  const std::map<Name, Buffer>
  getEncryptionKeys()
  {
    return m_encKeys;
  }

private:
  security::v2::Certificate m_cert;
  security::v2::KeyChain& m_keyChain;

  std::map<Name, Buffer> m_encKeys;
  std::map<Name, Buffer> m_decKeys;
};


} // namespace nac
} // namespace ndn

#endif // NAC_OWNER_HPP
