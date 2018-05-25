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

#include "data-enc-dec.hpp"
#include "crypto/aes.hpp"
#include "crypto/rsa.hpp"

namespace ndn {
namespace nac {


Block
encryptDataContent(const uint8_t* payload, size_t payloadLen,
                   const uint8_t* key, size_t keyLen)
{
  // first create AES key and encrypt the payload
  AesKeyParams param;
  auto aesKey = crypto::Aes::generateKey(param);
  auto iv = crypto::Aes::generateIV();
  auto encryptedPayload = crypto::Aes::encrypt(aesKey.data(), aesKey.size(),
                                               payload, payloadLen, iv);

  // second use RSA key to encrypt the AES key
  auto encryptedAesKey = crypto::Rsa::encrypt(key, keyLen, aesKey.data(), aesKey.size());

  // create the content block
  auto content = makeEmptyBlock(tlv::Content);
  content.push_back(makeBinaryBlock(ENCRYPTED_PAYLOAD,
                                    encryptedPayload.data(), encryptedPayload.size()));

  content.push_back(makeBinaryBlock(ENCRYPTED_AES_KEY,
                                    encryptedAesKey.data(), encryptedAesKey.size()));

  content.push_back(makeBinaryBlock(INITIAL_VECTOR,
                                    iv.data(), iv.size()));
  return content;
}





}
}
