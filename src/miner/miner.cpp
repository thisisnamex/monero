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
  
  // Send nounce for each solution found
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
	nonce_from: 
  }
*/
 
#include <sstream>
#include <numeric>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <iostream>
#include <ctype.h>

#include "miner.h"
#include "common/command_line.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "cryptonote_basic/difficulty.h"
#include "string_coding.h"

using namespace epee;

//----------------------------------------------------------------------------------------------------

#define CORE_MANAGER_IP "127.0.0.1"
#define CORE_MANAGER_PORT 3000

#define DEBUG_MINER false

void hexdump(void *pAddressIn, long  lSize);
void blob_set_nonce(char *blob, uint32_t nonce);

int main(int argc, char* argv[])
{ 
  // argv: template_no, nonce_from, nonce_to(excluding), difficulty, blobdata
  // call: cn_slow_hash to compute the hash and send POW via IPC to Core Manager
  uint32_t template_no = boost::lexical_cast<uint32_t>(argv[1]);
  uint32_t nonce_from = boost::lexical_cast<uint32_t>(argv[2]);
  uint32_t nonce_to = boost::lexical_cast<uint32_t>(argv[3]);
  
  // accepted POW for share
  uint64_t pool_difficulty = boost::lexical_cast<uint64_t>(argv[4]);
  // difficulty for coin reward
  uint64_t target_difficulty = boost::lexical_cast<uint64_t>(argv[5]);
  
  // blob is a result of get_block_hashing_blob(const block& b) call as defined in 
  // cryptonote_basic/cryptonote_format_utils.cpp
  // blob is std::string
  
  if (sizeof(argv[6]) >= 512)
  {
    std::cerr << "Fatal, malformed blob received!" << ENDL;
    return 0;
  }
  
  char blob[512];
  std::string blob_bin = string_encoding::base64_decode(argv[6]);
  memcpy(blob, blob_bin.c_str(), blob_bin.length());
  
  if (DEBUG_MINER)
  {
    // hex dump the binary blob
    std::cerr << "hexdump of blob input:" << ENDL;
    hexdump(blob, blob_bin.length());
  }
  
  crypto::hash hash_result;
  int blob_length = blob_bin.length();
  
  int pool_difficulty_solution_count = 0;
  
  for (uint32_t nonce = nonce_from; nonce < nonce_to; nonce++)
  {
    // Set nounce in blob
	blob_set_nonce(blob, nonce);
	
    if (DEBUG_MINER)
    {
      std::cerr << "Testing blob:" << ENDL;
      hexdump(blob, blob_bin.length());
    }
    
    crypto::cn_slow_hash(blob, blob_length, hash_result);
		
    if (DEBUG_MINER)
    {
      std::cerr << "hash_result:" << ENDL;
	  hexdump(hash_result.data, 32);
    }
	
	if(cryptonote::check_hash(hash_result, pool_difficulty))
    {
      if (DEBUG_MINER)
      {
        std::cerr << "Found pool_difficulty nonce:" << nonce << " hash:" << hash_result << ENDL;
      }
      
      if (DEBUG_MINER) {
	    std::cout << nonce << ENDL;
	  }
	  
	  pool_difficulty_solution_count ++;
	  
	} else continue;
	
	if(cryptonote::check_hash(hash_result, target_difficulty))
    {
      if (DEBUG_MINER)
      {
        std::cerr << "Found nonce:" << nonce << " hash:" << hash_result << ENDL;
      }
      
      if (DEBUG_MINER) {
	    std::cout << nonce << ENDL;
	  }
      
      // Foudn gold! Send  IPC over to Core Manager, to be forwarded to Node Agent and P2P Node
      rapidjson::Document json;
      json.SetObject();
      rapidjson::Value value_str(rapidjson::kStringType);
      rapidjson::Value value_num(rapidjson::kNumberType);
      
      value_str.SetString("core", strlen("core"));
      json.AddMember("obj", value_str, json.GetAllocator());
    
      value_str.SetString("eureka", strlen("eureka"));
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
  
  if (DEBUG_MINER) {
    std::cerr << "Done assigned work." << ENDL;
  }
  
  // Before quit, send notification to Core Manager
  rapidjson::Document json;
  json.SetObject();
  rapidjson::Value value_str(rapidjson::kStringType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  
  value_str.SetString("core", strlen("core"));
  json.AddMember("obj", value_str, json.GetAllocator());

  value_str.SetString("done", strlen("done"));
  json.AddMember("act", value_str, json.GetAllocator());
  
  value_num.SetInt(nonce_from);
  json.AddMember("nonce_from", value_num, json.GetAllocator());
  
  value_num.SetInt(pool_difficulty_solution_count);
  json.AddMember("count", value_num, json.GetAllocator());

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

//----------------------------------------------------------------------------------------------------
void blob_set_nonce(char *blob, uint32_t nonce)
{
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

  // Sample blobs:
  // get_block_hashing_blob nonce:3161993101 blob:Bgap3NvQBYX3w3mmJ4W9Ud2vg8SXMWn5hT5w2MO9Ui/SVLJX+2CtjS94vCqYs/yYBZtUbgFbnZDc4H2PNMSo8vX6whrCAJkuWEhsAg==
  // get_block_hashing_blob nonce:3161993102 blob:Bgap3NvQBYX3w3mmJ4W9Ud2vg8SXMWn5hT5w2MO9Ui/SVLJX+2Ctji94vCqYs/yYBZtUbgFbnZDc4H2PNMSo8vX6whrCAJkuWEhsAg==
  
  blob[39] =	   (nonce) & 0x00FF;
  blob[40] =  (nonce >> 8) & 0x00FF;
  blob[41] = (nonce >> 16) & 0x00FF;
  blob[42] = (nonce >> 24) & 0x00FF;
}

void hexdump(void *pAddressIn, long  lSize)
{
 char szBuf[100];
 long lIndent = 1;
 long lOutLen, lIndex, lIndex2, lOutLen2;
 long lRelPos;
 struct { char *pData; unsigned long lSize; } buf;
 unsigned char *pTmp,ucTmp;
 unsigned char *pAddress = (unsigned char *)pAddressIn;

   buf.pData   = (char *)pAddress;
   buf.lSize   = lSize;

   while (buf.lSize > 0)
   {
      pTmp     = (unsigned char *)buf.pData;
      lOutLen  = (int)buf.lSize;
      if (lOutLen > 16)
          lOutLen = 16;

      // create a 64-character formatted output line:
      sprintf(szBuf, " >                            "
                     "                      "
                     "    %08lX", pTmp-pAddress);
      lOutLen2 = lOutLen;

      for(lIndex = 1+lIndent, lIndex2 = 53-15+lIndent, lRelPos = 0;
          lOutLen2;
          lOutLen2--, lIndex += 2, lIndex2++
         )
      {
         ucTmp = *pTmp++;

         sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
         if(!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
         szBuf[lIndex2] = ucTmp;

         if (!(++lRelPos & 3))     // extra blank after 4 bytes
         {  lIndex++; szBuf[lIndex+2] = ' '; }
      }

      if (!(lRelPos & 3)) lIndex--;

      szBuf[lIndex  ]   = '<';
      szBuf[lIndex+1]   = ' ';

      fprintf(stderr, "%s\n", szBuf);

      buf.pData   += lOutLen;
      buf.lSize   -= lOutLen;
   }
}
