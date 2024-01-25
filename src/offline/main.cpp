// Copyright (c) 2021-2022, Dynex Developers
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
// Parts of this project are originally copyright by:
// Copyright (c) 2012-2016, The DynexCN developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero project
// Copyright (c) 2014-2018, The Forknote developers
// Copyright (c) 2018, The TurtleCoin developers
// Copyright (c) 2016-2018, The Karbowanec developers
// Copyright (c) 2017-2022, The CROAT.community developers

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <math.h>
#include <stdbool.h>
#include <locale.h>
#include "memory.h"
#include <chrono>
#include <map>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
//#include <nvml.h>
#include <assert.h>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <cstdint>
#include <bitset>

#include "../Common/StringTools.h"
#include "../Mnemonics/electrum-words.h"
#include "../DynexCNCore/DynexCNTools.h"
#include "../Common/Base58.h"
#include "../crypto/crypto.h"
extern "C"
{
	#include "../crypto/keccak.h"
}

#define TX_EXTRA_PADDING_MAX_COUNT          255
#define TX_EXTRA_NONCE_MAX_COUNT            255
#define TX_EXTRA_TAG_PADDING                0x00
#define TX_EXTRA_TAG_PUBKEY                 0x01
#define TX_EXTRA_NONCE                      0x02
#define TX_EXTRA_MERGE_MINING_TAG           0x03
#define TX_EXTRA_NONCE_PAYMENT_ID           0x00
#define TX_EXTRA_FROM_ADDRESS               0x04 
#define TX_EXTRA_TO_ADDRESS                 0x05 
#define TX_EXTRA_AMOUNT                     0x06 
#define TX_EXTRA_TXKEY                      0x07

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////////////
/// string handler functions
///////////////////////////////////////////////////////////////////////////////////////////////////////////

template<class T>
std::string podToHex(const T& s) {
  return toHex(&s, sizeof(s));
}

std::vector<char> HexToBytes(const std::string& hex) {
  std::vector<char> bytes;

  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    char byte = (char) strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }

  return bytes;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Crypto functions & definitions
///////////////////////////////////////////////////////////////////////////////////////////////////////////

const uint64_t ADDRESS_PREFIX = 185ULL;

struct AccountPublicAddress {
  Crypto::PublicKey spendPublicKey;
  Crypto::PublicKey viewPublicKey;
};

struct AccountKeys {
  AccountPublicAddress address;
  Crypto::SecretKey spendSecretKey;
  Crypto::SecretKey viewSecretKey;
};

struct KeyPair {
  Crypto::PublicKey publicKey;
  Crypto::SecretKey secretKey;
};

using BinaryArray = std::vector<uint8_t>;

std::string getAccountAddressAsString(uint64_t prefix, const AccountPublicAddress& adr) {
	BinaryArray ba;	
	for (int i=0; i<32; i++) ba.push_back(adr.spendPublicKey.data[i]);
	for (int i=0; i<32; i++) ba.push_back(adr.viewPublicKey.data[i]);
	return Tools::Base58::encode_addr(prefix, Common::asString(ba));
}

bool parseAccountAddressString(uint64_t& prefix, AccountPublicAddress& adr, const std::string& str) {
    std::string data;
    Tools::Base58::decode_addr(str, prefix, data);
    for (int i=0; i<32; i++) adr.spendPublicKey.data[i] = data[i];
    for (int i=0; i<32; i++) adr.viewPublicKey.data[i] = data[i+32];
    return true;
}

struct TransactionOutputInformation {
  // output info
  uint8_t  type;
  uint64_t amount;
  uint32_t globalOutputIndex;
  uint32_t outputInTransaction;

  // transaction info
  Crypto::Hash transactionHash;
  Crypto::PublicKey transactionPublicKey;

  union {
    Crypto::PublicKey outputKey;         // Type: Key 
    uint32_t requiredSignatures; 				 // Type: Multisignature
  };
};


///////////////////////////////////////////////////////////////////////////////////////////////////////////
/// generate address function
///////////////////////////////////////////////////////////////////////////////////////////////////////////
AccountKeys generate_address() {
	AccountKeys account;
	std::cout << "[INFO] GENERATING DETERMINISTIC ADDRESS..." << std::endl;

  // spend keys:
  Crypto::SecretKey second;
  Crypto::generate_keys(account.address.spendPublicKey, account.spendSecretKey);

	// view keys:
	keccak((uint8_t *)&account.spendSecretKey, sizeof(Crypto::SecretKey), (uint8_t *)&second, sizeof(Crypto::SecretKey));
  Crypto::generate_deterministic_keys(account.address.viewPublicKey, account.viewSecretKey, second);

  // mnemonicseed:
  std::string electrum_words;
  Crypto::ElectrumWords::bytes_to_words(account.spendSecretKey, electrum_words,"English");
  std::cout << "passphrase      : " << electrum_words << std::endl;

  // tracking wallet:
  std::cout << "Address         : " << getAccountAddressAsString(ADDRESS_PREFIX, account.address) << std::endl;
  std::cout << "spendPublicKey  : " << Common::podToHex(account.address.spendPublicKey) << std::endl;
  std::cout << "viewPublicKey   : " << Common::podToHex(account.address.viewPublicKey) << std::endl;
  std::cout << "spendSecretKey  : " << Common::podToHex(account.spendSecretKey) << std::endl;
  std::cout << "viewSecretKey   : " << Common::podToHex(account.viewSecretKey) << std::endl;
  std::cout << "tracking key    : " << Common::podToHex(account.address.spendPublicKey) << Common::podToHex(account.address.viewPublicKey) << "0000000000000000000000000000000000000000000000000000000000000000" << Common::podToHex(account.viewSecretKey) << std::endl; // spentSecretKey is 32 bytes x 0x00

  // output to file
  ofstream filesk ("secretkeys.txt");
  if (filesk.is_open())
  {
    filesk << "Address         : " << getAccountAddressAsString(ADDRESS_PREFIX, account.address) << std::endl;
		filesk << "spendPublicKey  : " << Common::podToHex(account.address.spendPublicKey) << std::endl;
		filesk << "viewPublicKey   : " << Common::podToHex(account.address.viewPublicKey) << std::endl;
		filesk << "spendSecretKey  : " << Common::podToHex(account.spendSecretKey) << std::endl;
		filesk << "viewSecretKey   : " << Common::podToHex(account.viewSecretKey) << std::endl;
    filesk.close();
  }
  
  // output tracking key:
  ofstream filetracking ("trackingkey.txt");
  if (filetracking.is_open())
  {
    filetracking << "Address         : " << getAccountAddressAsString(ADDRESS_PREFIX, account.address) << std::endl;
    filetracking << "tracking key    : " << Common::podToHex(account.address.spendPublicKey) << Common::podToHex(account.address.viewPublicKey) << "0000000000000000000000000000000000000000000000000000000000000000" << Common::podToHex(account.viewSecretKey) << std::endl;
    filetracking.close();
  }


  //

	return account;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////
/// signtransfer function
///////////////////////////////////////////////////////////////////////////////////////////////////////////

KeyPair generateKeyPair() {
	KeyPair k;
	Crypto::generate_keys(k.publicKey, k.secretKey);
	return k;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////
/// paymentid functions
///////////////////////////////////////////////////////////////////////////////////////////////////////////

bool parsePaymentId(const std::string& paymentIdString, Crypto::Hash& paymentId) {
  return Common::podFromHex(paymentIdString, paymentId);
}

bool addExtraNonceToTransactionExtra(std::vector<uint8_t>& tx_extra, const BinaryArray& extra_nonce) {
  if (extra_nonce.size() > TX_EXTRA_NONCE_MAX_COUNT) {
    return false;
  }

  size_t start_pos = tx_extra.size();
  tx_extra.resize(tx_extra.size() + 2 + extra_nonce.size());
  //write tag
  tx_extra[start_pos] = TX_EXTRA_NONCE;
  //write len
  ++start_pos;
  tx_extra[start_pos] = static_cast<uint8_t>(extra_nonce.size());
  //write data
  ++start_pos;
  memcpy(&tx_extra[start_pos], extra_nonce.data(), extra_nonce.size());
  return true;
}

void setPaymentIdToTransactionExtraNonce(std::vector<uint8_t>& extra_nonce, const Crypto::Hash& payment_id) {
  extra_nonce.clear();
  extra_nonce.push_back(TX_EXTRA_NONCE_PAYMENT_ID);
  const uint8_t* payment_id_ptr = reinterpret_cast<const uint8_t*>(&payment_id);
  std::copy(payment_id_ptr, payment_id_ptr + sizeof(payment_id), std::back_inserter(extra_nonce));
}

std::string convertPaymentId(const std::string& paymentIdString) {
  if (paymentIdString.empty()) {
    return "";
  }

  Crypto::Hash paymentId;
  if (!parsePaymentId(paymentIdString, paymentId)) {
    std::stringstream errorStr;
    errorStr << "Payment id has invalid format: \"" + paymentIdString + "\", expected 64-character string";
    throw std::runtime_error(errorStr.str());
  }

  std::vector<uint8_t> extra;
  DynexCN::BinaryArray extraNonce;
  setPaymentIdToTransactionExtraNonce(extraNonce, paymentId);
  if (!addExtraNonceToTransactionExtra(extra, extraNonce)) {
    std::stringstream errorStr;
    errorStr << "Something went wrong with payment_id. Please check its format: \"" + paymentIdString + "\", expected 64-character string";
    throw std::runtime_error(errorStr.str());
  }

  return std::string(extra.begin(), extra.end());
}

bool sign_transfer(const std::string address, const uint64_t amount, const std::string paymentid, const std::string keyfile, const std::string outfile, const std::string secretvk, const std::string publicvk, const std::string secretsk, const std::string publicsk, const uint64_t fee) {

  // convert keys to key format:
	Crypto::SecretKey viewSecretKey; for (int i=0; i<32; i++) viewSecretKey.data[i] = HexToBytes(secretvk)[i];
	Crypto::PublicKey viewPublicKey; for (int i=0; i<32; i++) viewPublicKey.data[i] = HexToBytes(publicvk)[i];
	Crypto::SecretKey spendSecretKey; for (int i=0; i<32; i++) spendSecretKey.data[i] = HexToBytes(secretsk)[i];
	Crypto::PublicKey spendPublicKey; for (int i=0; i<32; i++) spendPublicKey.data[i] = HexToBytes(publicsk)[i];

	// convert destination address 'address'to keys:
	uint64_t prefix = ADDRESS_PREFIX;
	AccountPublicAddress destination;
	parseAccountAddressString(prefix, destination, address);
	std::cout << "[INFO] signing the following transfer:" << std::endl;
	std::cout << "       recipient : " << address << std::endl;
	std::cout << "                   -> public spendkey : " << Common::podToHex(destination.spendPublicKey) << std::endl;
	std::cout << "                   -> public viewkey  : " << Common::podToHex(destination.viewPublicKey) << std::endl;
	std::cout << "       amount    : " << amount << " nanoDNX"<< std::endl;
	std::cout << "       fee       : " << fee << " nanoDNX"<< std::endl;
	std::cout << "       paymentid : " << paymentid << std::endl;
	std::cout << "       keyfile   : " << keyfile << std::endl;
	std::cout << "       outfile   : " << outfile << std::endl;
	std::cout << "       secretvk  : " << Common::podToHex(viewSecretKey) << std::endl;
	std::cout << "       publicvk  : " << Common::podToHex(viewPublicKey)<< std::endl;
	std::cout << "       secretsk  : " << Common::podToHex(spendSecretKey)<< std::endl;
	std::cout << "       publicsk  : " << Common::podToHex(spendPublicKey)<< std::endl;

	// load ouput keys from file:
	std::cout << "[INFO] Loading " << keyfile << "..." << std::endl;
	std::vector<TransactionOutputInformation> outputs;
  
  std::ifstream fout(keyfile);
  if (fout.is_open()) {
    int num_outs;
    fout.read(reinterpret_cast<char*>(&num_outs), sizeof(num_outs));
    std::cout << "[INFO] Reading " << num_outs << " outputs..." << std::endl;
    for (int i=0; i<num_outs; i++) {
    			TransactionOutputInformation output;
          fout.read(reinterpret_cast<char*>(&output.amount), sizeof(output.amount));
          fout.read(reinterpret_cast<char*>(&output.globalOutputIndex), sizeof(output.globalOutputIndex));
          fout.read(reinterpret_cast<char*>(&output.outputInTransaction), sizeof(output.outputInTransaction));
          fout.read(reinterpret_cast<char*>(&output.transactionHash), sizeof(output.transactionHash));
          fout.read(reinterpret_cast<char*>(&output.transactionPublicKey), sizeof(output.transactionPublicKey));
          fout.read(reinterpret_cast<char*>(&output.outputKey), sizeof(output.outputKey));
          fout.read(reinterpret_cast<char*>(&output.requiredSignatures), sizeof(output.requiredSignatures));
          outputs.push_back(output);
          std::cout << "READ" << std::endl;
    }
    fout.close();
  } else {
  	   std::cout << "[ERROR] File " << keyfile << " not found." << std::endl;
  	   return false;
  }

  //print outputs:
  for (const auto& t : outputs) {
      //std::cout << "type : " << t.type << std::endl;
      std::cout << "amount : " << t.amount << std::endl;
      std::cout << "globalOutputIndex : " << t.globalOutputIndex << std::endl;
      std::cout << "outputInTransaction : " << t.outputInTransaction << std::endl;
      std::cout << "transactionHash : " << Common::podToHex(t.transactionHash) << std::endl;
      std::cout << "transactionPublicKey : " << Common::podToHex(t.transactionPublicKey) << std::endl;
      std::cout << "outputKey : " << Common::podToHex(t.outputKey) << std::endl;
      std::cout << "requiredSignatures : " << t.requiredSignatures << std::endl;
      std::cout << std::endl;
  }

  // choose outputs to use:
  std::vector<TransactionOutputInformation> outputs_selected;
  std::vector<Crypto::PublicKey> outputs_selected_keys;
  uint64_t foundMoney = 0;
  uint64_t neededMoney = amount + fee;
  while (foundMoney < neededMoney && !outputs.empty()) {
  	   TransactionOutputInformation output = outputs.front();
  	   outputs_selected.push_back(output);
  	   outputs_selected_keys.push_back(output.outputKey);
  	   foundMoney += output.amount;
  	   outputs.erase(outputs.begin()); 
  }

  std::cout << "[INFO] Total " << outputs_selected.size() << " selected outputs to spend: " << foundMoney << " (needed " << neededMoney << ")" << std::endl;

  if (foundMoney < neededMoney) {
  	  std::cout << "[ERROR] Insufficient funds." << std::endl;
  	  return false;
  }

  // construct transaction:
  std::ofstream ftxout(outfile);
  if (ftxout.is_open()) {
		  DynexCN::Transaction tx;

		  tx.inputs.clear();
		  tx.outputs.clear();
		  tx.signatures.clear();
		  
		  tx.version = 1;
		  ftxout.write(reinterpret_cast<char*>(&tx.version), sizeof(tx.version));

		  tx.unlockTime = 0;
		  ftxout.write(reinterpret_cast<char*>(&tx.unlockTime), sizeof(tx.unlockTime));

		  Crypto::SecretKey tx_key;
		  KeyPair txkey = generateKeyPair();
		  tx_key = txkey.secretKey;

		  // extra:
		  std::string extraString;
		  
		  // paymentId?
		  extraString = convertPaymentId(paymentid);

		  // public key:
		  extraString.append(sizeof(char), TX_EXTRA_TAG_PUBKEY);
		  for (int i=0; i<32; i++)
		    extraString.append(sizeof(char), txkey.publicKey.data[i]);  
		  
		  // from_address:
		  extraString.append(sizeof(char), TX_EXTRA_FROM_ADDRESS);
		  for (int i=0; i<32; i++)
		    extraString.append(sizeof(char), spendPublicKey.data[i]);  
		  for (int i=0; i<32; i++)
		    extraString.append(sizeof(char), viewPublicKey.data[i]); 
		
		  std::cout << "extraString: " << Common::podToHex(extraString) << std::endl;
		  
		  // to_address:
		  extraString.append(sizeof(char), TX_EXTRA_TO_ADDRESS);
		  for (int i=0; i<32; i++)
		    extraString.append(sizeof(char), destination.spendPublicKey.data[i]);  
		  for (int i=0; i<32; i++)
		    extraString.append(sizeof(char), destination.viewPublicKey.data[i]); 
		  
		  // amount:
		  uint8_t amt[8];
		  amt[7] = uint8_t(amount >> 8*7);
		  amt[6] = uint8_t(amount >> 8*6);
		  amt[5] = uint8_t(amount >> 8*5);
		  amt[4] = uint8_t(amount >> 8*4);
		  amt[3] = uint8_t(amount >> 8*3);
		  amt[2] = uint8_t(amount >> 8*2);
		  amt[1] = uint8_t(amount >> 8*1);
		  amt[0] = uint8_t(amount >> 8*0);
		  extraString.append(sizeof(char), TX_EXTRA_AMOUNT);
		  for (int i=0; i<8; i++)
		    extraString.append(sizeof(char), amt[i]);  

		  // txkey:
		  extraString.append(sizeof(char), TX_EXTRA_TXKEY);
		  for (int i=0; i<32; i++)
    		extraString.append(sizeof(char), tx_key.data[i]);

			tx.extra.assign(extraString.begin(), extraString.end());
    	
    	int extrasize = tx.extra.size();
    	ftxout.write(reinterpret_cast<char*>(&extrasize), sizeof(extrasize));
    	for (int i=0; i<extrasize; i++)
          ftxout.write(reinterpret_cast<char*>(&tx.extra[i]), sizeof(tx.extra[i]));

    	std::cout     << "version          : " << tx.version << std::endl;
  		std::cout     << "unlockTime       : " << tx.unlockTime << std::endl;
  		std::cout     << "extra            : " << Common::podToHex(tx.extra) << std::endl;
  		std::cout     << "extra size       : " << tx.extra.size() << std::endl;
		  
			//fill inputs:
		  struct input_generation_context_data {
		  	KeyPair in_ephemeral;
		  };
		  std::vector<input_generation_context_data> in_contexts;
		  uint64_t summary_inputs_money = 0;
		 	
		 	std::vector<Crypto::KeyImage> images;
		 	int num_ins = outputs_selected.size();
		 	ftxout.write(reinterpret_cast<char*>(&num_ins), sizeof(num_ins));

		  for (auto src_entry : outputs_selected) {
		  	  
		  	  //generate_key_image:
		  	  in_contexts.push_back(input_generation_context_data());
		  	  KeyPair& in_ephemeral = in_contexts.back().in_ephemeral;
		  	  Crypto::KeyImage img;
		  	  Crypto::KeyDerivation recv_derivation;
		  	  bool r = Crypto::generate_key_derivation(src_entry.transactionPublicKey, viewSecretKey, recv_derivation);
		  	  if (!r) {
		  	  		std::cout << "[ERROR] Failed to generate key derivation" << std::endl;
		  	  		return false;
		  	  }
		  	  r = Crypto::derive_public_key(recv_derivation, src_entry.outputInTransaction, spendPublicKey, in_ephemeral.publicKey);
		  	  if (!r) {
		  	  		std::cout << "[ERROR] Failed to derive public key" << std::endl;
		  	  		return false;	
		  	  }
		  	  Crypto::derive_secret_key(recv_derivation, src_entry.outputInTransaction, spendSecretKey, in_ephemeral.secretKey);
		  	  Crypto::generate_key_image(in_ephemeral.publicKey, in_ephemeral.secretKey, img);
		  	  // add to inputs:
		  	  //TransactionInput input;
		  	  DynexCN::KeyInput input;
		  	  input.amount = src_entry.amount;
		  	  input.keyImage = img;
		  	  images.push_back(img);
		  	  input.outputIndexes.push_back(src_entry.globalOutputIndex);
		  	  tx.inputs.push_back(input);
		  	  
		  	  summary_inputs_money += input.amount;
		  	  
		  	  ftxout.write(reinterpret_cast<char*>(&input.amount), sizeof(input.amount));
          ftxout.write(reinterpret_cast<char*>(&input.keyImage), sizeof(input.keyImage));
		  	  std::cout << "input - amount   : " << input.amount << std::endl;
		  	  std::cout << "input - keyimage : " << Common::podToHex(input.keyImage) << std::endl;
		  	  int num_indices = input.outputIndexes.size();
          ftxout.write(reinterpret_cast<char*>(&num_indices), sizeof(num_indices));
		  	  for (auto index : input.outputIndexes) {
		  	  		std::cout << "input outputIndex " << index << std::endl;
		  	  		ftxout.write(reinterpret_cast<char*>(&index), sizeof(index));
		  	  }
		  }

		  // outputs:
		  uint64_t summary_outputs_money = 0;

		  int num_outs = 2;
      ftxout.write(reinterpret_cast<char*>(&num_outs), sizeof(num_outs));

			// output: amount (in nanoDNX)
		  Crypto::KeyDerivation derivation;
		  Crypto::PublicKey out_eph_public_key;
		  size_t output_index = 0;
		  bool r = Crypto::generate_key_derivation(destination.viewPublicKey, txkey.secretKey, derivation);
		  if (!r) {
		  		std::cout << "[ERROR] Failed to generate key derivation" << std::endl;
		  		return false;	
		  }
			r = Crypto::derive_public_key(derivation, output_index, destination.spendPublicKey, out_eph_public_key);
			if (!r) {
		  		std::cout << "[ERROR] Failed to derive public key" << std::endl;
		  		return false;	
		  }
		  //TransactionOutput output;
		  DynexCN::TransactionOutput output;
		  output.amount = amount;
		  //TransactionOutputTarget tk;
		  DynexCN::KeyOutput tk;
		  tk.key = out_eph_public_key;
		  output.target = tk;
		  tx.outputs.push_back(output);
		  output_index++;
		  summary_outputs_money += amount;

		  ftxout.write(reinterpret_cast<char*>(&output.amount), sizeof(output.amount));
		  ftxout.write(reinterpret_cast<char*>(&out_eph_public_key), sizeof(out_eph_public_key));
		  std::cout << "output - amount  : " << output.amount << std::endl;
		  std::cout << "output - target key : " << Common::podToHex(out_eph_public_key) << std::endl;

		  // output: change
		  if (summary_inputs_money > (amount+fee)) {
		  		uint64_t change = summary_inputs_money - amount - fee;
		  		Crypto::KeyDerivation derivation2;
				  Crypto::PublicKey out_eph_public_key2;
				  bool r = Crypto::generate_key_derivation(viewPublicKey, txkey.secretKey, derivation2);
				  if (!r) {
				  		std::cout << "[ERROR] Failed to generate key derivation" << std::endl;
				  		return false;	
				  }
					r = Crypto::derive_public_key(derivation2, output_index, spendPublicKey, out_eph_public_key2);
					if (!r) {
				  		std::cout << "[ERROR] Failed to derive public key" << std::endl;
				  		return false;	
				  }
				  DynexCN::TransactionOutput output2;
				  output2.amount = change;
				  //TransactionOutputTarget tk2;
				  DynexCN::KeyOutput tk2;
				  tk2.key = out_eph_public_key2;
				  output2.target = tk2;
				  tx.outputs.push_back(output2);
				  summary_outputs_money += change;
				  
				  ftxout.write(reinterpret_cast<char*>(&output2.amount), sizeof(output2.amount));
		  		ftxout.write(reinterpret_cast<char*>(&out_eph_public_key2), sizeof(out_eph_public_key2));
				  std::cout << "output - amount  : " << output2.amount << std::endl;
				  std::cout << "output - target key : " << Common::podToHex(out_eph_public_key2) << std::endl;
		  }

		  std::cout << "[INFO] Total inputs  : " << summary_inputs_money << std::endl;
		  std::cout << "[INFO] Total outputs : " << summary_outputs_money << std::endl;

		  if ((summary_inputs_money-fee)!=summary_outputs_money) {
		  		std::cout << "[ERROR] input / output amounts mismatch" << std::endl;
				  return false;
		  }
		  
		  // generate ring signatures
		  Crypto::Hash tx_prefix_hash;
		  DynexCN::getObjectHash(*static_cast<DynexCN::TransactionPrefix*>(&tx), tx_prefix_hash);
		  std::cout << "tx_prefix_hash : " << Common::podToHex(tx_prefix_hash) << std::endl;

		  size_t i = 0;
		  for (auto output_selected : outputs_selected_keys) {
				  std::vector<const Crypto::PublicKey*> keys_ptrs;
				  keys_ptrs.push_back(&output_selected);
					//std::cout << "keys_ptrs: " << Common::podToHex(output_selected) << std::endl;
				  
				  tx.signatures.push_back(std::vector<Crypto::Signature>());
				  std::vector<Crypto::Signature>& sigs = tx.signatures.back();
				  sigs.resize(1);
					//std::cout << "tx_prefix_hash : " << Common::podToHex(tx_prefix_hash) << std::endl;
					//std::cout << "keyimage : " << Common::podToHex(images[i]) << std::endl;
					//std::cout << "secretKey : " << Common::podToHex(in_contexts[i].in_ephemeral.secretKey) << std::endl;
					//std::cout << "realOutput: " << 0 << std::endl;

				  generate_ring_signature(tx_prefix_hash, images[i], keys_ptrs, in_contexts[i].in_ephemeral.secretKey, 0, sigs.data());
					//std::cout << "Ring Signature: " << Common::podToHex(sigs.front()) << std::endl;

				  i++;
			}

		  int num_sig = tx.signatures.size();
      ftxout.write(reinterpret_cast<char*>(&num_sig), sizeof(num_sig));
      for (auto signatures : tx.signatures) {
          int num_sig_sub = signatures.size();
          ftxout.write(reinterpret_cast<char*>(&num_sig_sub), sizeof(num_sig_sub));
          for (auto signature : signatures) {
              ftxout.write(reinterpret_cast<char*>(&signature), sizeof(signature));
          }
      }

      for (auto signatures : tx.signatures) {
	        std::cout << "signature(s)        : ";
	        for (auto signature : signatures) std::cout << Common::podToHex(signature) << ", ";
	        std::cout << std::endl;
	    }

	    // tx_key:
	    ftxout.write(reinterpret_cast<char*>(&txkey.secretKey), sizeof(txkey.secretKey));

		  // transaction created.
		  ftxout.close();
	}


	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////
/// command line handler
///////////////////////////////////////////////////////////////////////////////////////////////////////////

char* getCmdOption(char** begin, char** end, const std::string& option)
{
	char** itr = std::find(begin, end, option);
	if (itr != end && ++itr != end)
	{
		return *itr;
	}
	return 0;
}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
	return std::find(begin, end, option) != end;
}

int main(int argc, char** argv) {

	std::cout << "[INFO] ---------------------------------------------------------" << std::endl;
	std::cout << "[INFO] Dynex Offline Signature Client" << std::endl;
	std::cout << "[INFO] ---------------------------------------------------------" << std::endl;

	//help command?
	if (cmdOptionExists(argv, argv + argc, "-h")) {
		std::cout << "HELP" << std::endl;
		std::cout << "usage: offlinesignature [options]" << std::endl;
		std::cout << std::endl;
		std::cout << "-generateaddress                                                generates a DNX address" << std::endl;
		std::cout << "-signtransfer -address <ADDRESS> -amount <AMOUNT> -keyfile <KEYFILE> -outfile <OUTFILE> -secretvk <SECRET VIEWKEY> -publicvk <PUBLIC VIEWKEY> -secretsk <SECRET SPENDKEY> -publicsk <PUBLIC SPENDKEY> (-paymentid <PAYMENTID>) (-fee <FEE>)   creates and signes a transaction" << std::endl;
		return EXIT_SUCCESS;
	}

  std::string address = "";
	uint64_t amount = 0;
	std::string paymentid = "";
	std::string keyfile = "";
	std::string outfile = "";
	std::string secretvk = "";
	std::string publicvk = "";
	std::string secretsk = "";
	std::string publicsk = "";
	uint64_t fee = 100000;
	bool signtransfer = false;

	if (cmdOptionExists(argv, argv + argc, "-generateaddress")) {
		AccountKeys account = generate_address();
	}

	if (cmdOptionExists(argv, argv + argc, "-signtransfer")) {
		signtransfer = true;
	}

	char* Caddress = getCmdOption(argv, argv + argc, "-address");
	if (Caddress) {
		address = Caddress;
	}
	char* Cpaymentid = getCmdOption(argv, argv + argc, "-paymentid");
	if (Cpaymentid) {
		paymentid = Cpaymentid;
	}
	char* Ckeyfile = getCmdOption(argv, argv + argc, "-keyfile");
	if (Ckeyfile) {
		keyfile = Ckeyfile;
	}
	char* Coutfile = getCmdOption(argv, argv + argc, "-outfile");
	if (Coutfile) {
		outfile = Coutfile;
	}
	char* Camount = getCmdOption(argv, argv + argc, "-amount");
	if (Camount) {
		double amount_entered = atof(Camount);
		amount = (uint64_t)(amount_entered*1000000000);
	}
	char* Cfee = getCmdOption(argv, argv + argc, "-fee");
	if (Cfee) {
		double fee_entered = atof(Cfee);
		fee = (uint64_t)(fee_entered*1000000000);
	}
	char* _secretvk = getCmdOption(argv, argv + argc, "-secretvk");
	if (_secretvk) {
		secretvk = _secretvk;
	}
	char* _publicvk = getCmdOption(argv, argv + argc, "-publicvk");
	if (_publicvk) {
		publicvk = _publicvk;
	}
	char* _secretsk = getCmdOption(argv, argv + argc, "-secretsk");
	if (_secretsk) {
		secretsk = _secretsk;
	}
	char* _publicsk = getCmdOption(argv, argv + argc, "-publicsk");
	if (_publicsk) {
		publicsk = _publicsk;
	}

  //transfer?
	if (signtransfer) {
		if (address=="") {
			std::cout << "[ERROR] invalid address" << std::endl;
			return EXIT_FAILURE;
		}
		if (keyfile=="") {
			std::cout << "[ERROR] invalid keyfile" << std::endl;
			return EXIT_FAILURE;
		}
		if (outfile=="") {
			std::cout << "[ERROR] invalid outfile" << std::endl;
			return EXIT_FAILURE;
		}
		if (secretvk=="") {
			std::cout << "[ERROR] secret viewkey missing" << std::endl;
			return EXIT_FAILURE;
		}
		if (publicvk=="") {
			std::cout << "[ERROR] public viewkey missing" << std::endl;
			return EXIT_FAILURE;
		}
		if (secretsk=="") {
			std::cout << "[ERROR] secret spendkey missing" << std::endl;
			return EXIT_FAILURE;
		}
		if (publicsk=="") {
			std::cout << "[ERROR] public spendkey missing" << std::endl;
			return EXIT_FAILURE;
		}
		if (amount<=0) {
			std::cout << "[ERROR] invalid amount" << std::endl;
			return EXIT_FAILURE;
		}

		if (!sign_transfer(address, amount, paymentid, keyfile, outfile, secretvk, publicvk, secretsk, publicsk, fee)) {
				std::cout << "[ERROR] while trying to send transaction" << std::endl;
		}
	}

	return EXIT_SUCCESS;
}
