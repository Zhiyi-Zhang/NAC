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
encryptDataContentWithCK(const uint8_t* payload, size_t payloadLen,
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
  content.encode();
  return content;
}

std::tuple<Block, Block>
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

  // create encrypted content block
  auto encryptedBlock = makeBinaryBlock(ENCRYPTED_PAYLOAD,
                                        encryptedPayload.data(), encryptedPayload.size());
  encryptedBlock.encode();

  // create ck block
  auto CKBlock = makeEmptyBlock(tlv::Content);
  CKBlock.push_back(makeBinaryBlock(ENCRYPTED_AES_KEY,
                                    encryptedAesKey.data(), encryptedAesKey.size()));
  CKBlock.push_back(makeBinaryBlock(INITIAL_VECTOR,
                                    iv.data(), iv.size()));
  CKBlock.encode();
  return std::make_tuple(encryptedBlock, CKBlock);
}


Buffer
decryptDataContent(const Block& dataBlock,
                   const uint8_t* key, size_t keyLen)
{
  dataBlock.parse();
  Buffer iv(dataBlock.get(INITIAL_VECTOR).value(),
            dataBlock.get(INITIAL_VECTOR).value_size());
  Buffer encryptedAesKey(dataBlock.get(ENCRYPTED_AES_KEY).value(),
                         dataBlock.get(ENCRYPTED_AES_KEY).value_size());
  Buffer encryptedPayload(dataBlock.get(ENCRYPTED_PAYLOAD).value(),
                          dataBlock.get(ENCRYPTED_PAYLOAD).value_size());

  auto aesKey = crypto::Rsa::decrypt(key, keyLen, encryptedAesKey.data(), encryptedAesKey.size());
  auto payload = crypto::Aes::decrypt(aesKey.data(), aesKey.size(),
                                      encryptedPayload.data(), encryptedPayload.size(), iv);
  return payload;
}

Buffer
decryptDataContent(const Block& dataBlock, const Block& ckBlock,
                   const uint8_t* key, size_t keyLen)
{
  dataBlock.parse();
  ckBlock.parse();
  Buffer iv(ckBlock.get(INITIAL_VECTOR).value(),
            ckBlock.get(INITIAL_VECTOR).value_size());
  Buffer encryptedAesKey(ckBlock.get(ENCRYPTED_AES_KEY).value(),
                         ckBlock.get(ENCRYPTED_AES_KEY).value_size());
  Buffer encryptedPayload(dataBlock.get(ENCRYPTED_PAYLOAD).value(),
                          dataBlock.get(ENCRYPTED_PAYLOAD).value_size());

  auto aesKey = crypto::Rsa::decrypt(key, keyLen, encryptedAesKey.data(), encryptedAesKey.size());
  auto payload = crypto::Aes::decrypt(aesKey.data(), aesKey.size(),
                                      encryptedPayload.data(), encryptedPayload.size(), iv);
  return payload;
}

}
}
