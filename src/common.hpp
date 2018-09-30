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

#ifndef NAC_COMMON_HPP
#define NAC_COMMON_HPP

#include "config.hpp"

#ifdef HAVE_TESTS
#define VIRTUAL_WITH_TESTS virtual
#define PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define PROTECTED_WITH_TESTS_ELSE_PRIVATE protected
#else
#define VIRTUAL_WITH_TESTS
#define PUBLIC_WITH_TESTS_ELSE_PROTECTED protected
#define PUBLIC_WITH_TESTS_ELSE_PRIVATE private
#define PROTECTED_WITH_TESTS_ELSE_PRIVATE private
#endif

#include <cstddef>
#include <map>
#include <iostream>

#include <ndn-cxx/common.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/v2/certificate.hpp>

namespace ndn {
namespace nac {

using std::size_t;
using std::shared_ptr;

namespace tlv {
using namespace ndn::tlv;
} // namespace tlv

const ndn::name::Component NAME_COMPONENT_BY("ENC-BY");
const ndn::name::Component NAME_COMPONENT_E_KEY("KEK");
const ndn::name::Component NAME_COMPONENT_D_KEY("KDK");
const ndn::name::Component NAME_COMPONENT_NAC("NAC");

enum {
  ENCRYPTED_PAYLOAD = 630,
  ENCRYPTED_AES_KEY = 631,
  INITIAL_VECTOR = 632,
  CK_LOCATOR = 633
};


} // namespace nac
} // namespace ndn

#endif // NAC_COMMON_HPP
