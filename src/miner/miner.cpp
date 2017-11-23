// Copyright (c) 2014-2017, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
//----------------------------------------------------------------------------------------------------

/*!
 * \file miner.cpp - Core Worker
 * 
 * \brief Source file that defines Core Worker.
 */

/* Core Worker sends these two API to Core Manager to be forwarded to Server
  
  // Send nounce for each POW solution found
  {
    obj: core
    act: pow
    template: template number of this POW
    nonce: nonce for the solution
  }
  
  // Send notification when done searching through all the nonces
  {
    obj: core
    act: done
  }
*/
 
#include <sstream>
#include <numeric>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <iostream>
#include "miner.h"
#include "common/command_line.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "crypto/hash-ops.h"
#include "cryptonote_basic/difficulty.h"
//----------------------------------------------------------------------------------------------------

#define CORE_MANAGER_IP "127.0.0.1"
#define CORE_MANAGER_PORT 3000

#define DEBUG_MINER true
#define DEBUG_MINER_PRINT true

int main(int argc, char* argv[])
{ 
  // argv: template_no, nonce_from, nonce_to(excluding), difficulty, blobdata
  // call: cn_slow_hash to compute the hash and send POW via IPC to Core Manager
  uint32_t template_no = boost::lexical_cast<uint32_t>(args[0]);
  uint32_t nonce_from = boost::lexical_cast<uint32_t>(args[1]);
  uint32_t nonce_to = boost::lexical_cast<uint32_t>(args[2]);
  uint64_t difficulty = boost::lexical_cast<uint64_t>(args[3]);
  
  // blob is a result of get_block_hashing_blob(const block& b) call as defined in 
  // cryptonote_basic/cryptonote_format_utils.cpp
  // blob is std::string
  /* struct block_header is defined in cryptonote_basic/cryptonote_basic.h
  struct block_header
  {
    uint8_t major_version;
    uint8_t minor_version;
    uint64_t timestamp;
    crypto::hash  prev_id;
    uint32_t nonce;

    BEGIN_SERIALIZE()
      VARINT_FIELD(major_version)
      VARINT_FIELD(minor_version)
      VARINT_FIELD(timestamp)
      FIELD(prev_id)
      FIELD(nonce)
    END_SERIALIZE()
  };*/

  if (sizeof(args[4]) >= 512)
  {
    cout << "Fatal, malformed blob received!" << ENDL;
    return 0;
  }
  memcpy(blob, args[4], sizeof(args[4]));
  
  crypto::hash hash_result;
  
  for (uint32_t nonce = nonce_from; nonce < nonce_to; nonce++)
  {
    // Set nounce in blob
    if (DEBUG_MINER_PRINT)
    {
      cout << "Testing blob:" << blob << ENDL;
    }
    
    crypto::cn_slow_hash(blob, sizeof(blob), hash_result);
    
    if(check_hash(hash_result, difficulty))
    {
      cout << "Found nonce:" << nonce << " hash:" << hash_result << ENDL;
      
      if (DEBUG_MINER) continue;
      
      // Send POW via IPC over to Core Manager, to be forwarded to Node Agent and P2P Node
      rapidjson::Document json;
      json.SetObject();
      rapidjson::Value value_str(rapidjson::kStringType);
      rapidjson::Value value_num(rapidjson::kNumberType);
      
      value_str.SetString("core", sizeof("core"));
      json.AddMember("obj", value_str, json.GetAllocator());
    
      value_str.SetString("pow", sizeof("pow"));
      json.AddMember("act", value_str, json.GetAllocator());

      value_num.SetInt(template_no);
      json.AddMember("template", value_num, json.GetAllocator());

      value_num.SetInt(nonce);
      json.AddMember("nonce", value_num, json.GetAllocator());
    
      // Serialize the JSON object
      rapidjson::StringBuffer buffer;
      rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
      json.Accept(writer);
    
      boost::asio::io_service ios;
      boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(CORE_MANAGER_IP), CORE_MANAGER_PORT);
      boost::asio::ip::tcp::socket socket(ios);
      socket.connect(endpoint);
    
      boost::array<char, 1000> buf;
      std::string stringified = buffer.GetString();
      std::copy(stringified.begin(), stringified.end(), buf.begin());
      boost::system::error_code error;
      socket.write_some(boost::asio::buffer(buf, stringified.size()), error);
      socket.close();
    }  
  }
  
  if (DEBUG_MINER) return 0;
  
  // Before quit, send notification to Core Manager
  rapidjson::Document json;
  json.SetObject();
  rapidjson::Value value_str(rapidjson::kStringType);
  
  value_str.SetString("core", sizeof("core"));
  json.AddMember("obj", value_str, json.GetAllocator());

  value_str.SetString("done", sizeof("done"));
  json.AddMember("act", value_str, json.GetAllocator());

  // Serialize the JSON object
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  json.Accept(writer);

  boost::asio::io_service ios;
  boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(CORE_MANAGER_IP), CORE_MANAGER_PORT);
  boost::asio::ip::tcp::socket socket(ios);
  socket.connect(endpoint);

  boost::array<char, 1000> buf;
  std::string stringified = buffer.GetString();
  std::copy(stringified.begin(), stringified.end(), buf.begin());
  boost::system::error_code error;
  socket.write_some(boost::asio::buffer(buf, stringified.size()), error);
  socket.close();

  return 0;
}
