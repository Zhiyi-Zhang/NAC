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

#ifndef NAC_DATA_ENC_DEC_HPP
#define NAC_DATA_ENC_DEC_HPP

#include "common.hpp"

namespace ndn {
namespace nac {

enum {
  ENCRYPTED_PAYLOAD = 130,
  ENCRYPTED_AES_KEY = 131,
  INITIAL_VECTOR = 132
};

/**
 * @brief Prepare an encrypted data content using an asymmetric enc key
 */
Block
encryptDataContent(const uint8_t* payload, size_t payloadLen,
                   const Name& keyName,
                   const uint8_t* key, size_t keyLen);

}
}

#endif // NAC_DATA_ENC_DEC_HPP
