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

/*!
 * \file miner.cpp - Core Worker
 * 
 * \brief Source file that defines miner class.
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
//----------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{ 
  // argv: blobdata, nonce_from, nonce_to(excluding), difficulty
  // call: cn_slow_hash to compute the hash and send POW via IPC to Core Manager

  // send via IPC over to Core Manager, to be forwarded to Node Agent and P2P Node
  rapidjson::Document json;
  json.SetObject();
  rapidjson::Value value(rapidjson::kStringType);

  value.SetString("core", sizeof("core"));
  json.AddMember("obj", value, json.GetAllocator());

  value.SetString("pow", sizeof("pow"));
  json.AddMember("act", value, json.GetAllocator());

  // Serialize the JSON object
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  json.Accept(writer);

  boost::asio::io_service ios;
  boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 3000);
  boost::asio::ip::tcp::socket socket(ios);
  socket.connect(endpoint);

  boost::array<char, 10000> buf;
  std::string stringified = buffer.GetString();
  std::copy(stringified.begin(), stringified.end(), buf.begin());
  boost::system::error_code error;
  socket.write_some(boost::asio::buffer(buf, stringified.size()), error);
  socket.close();
		  
  return 0;
}
