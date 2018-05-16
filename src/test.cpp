#include "test.h"
#include "backupheader.h"
#include "crypto.h"
#include <array>
#include <iostream>
#include <sstream>
#include <vector>

/**
 * Some functions for testing the decrypting routine.
 * Source:
 * https://github.com/wireapp/wire-ios-cryptobox/blob/develop/WireCryptoboxTests/ChaCha20EncryptionTests.swift
 */

using namespace std;
const char *header =
    "V0JVSQAAAQ8CgQ/"
    "ikb7pIkWDhhDkY7uMxemLjGnPNJ2ohITEekzYAzAxygPF36PpKw9HXrGZWg==";

// https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
static std::vector<char> base64_decode(const std::string &in) {

  std::vector<char> out;

  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++)
    T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] =
        i;

  int val = 0, valb = -8;
  for (unsigned char c : in) {
    if (T[c] == -1)
      break;
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

template <typename T, int N>
bool assert_array(const DynamicArray<T> &a, const std::array<T, N> &b) {
  if (a.size() != N)
    return false;
  for (int i = 0; i < N; i++) {
    auto ela = a[i];
    auto elb = b[i];
    if (ela != elb)
      return false;
  }
  return true;
}

bool test_header() {
  auto header_data = base64_decode(header);
  Bytes buffer(header_data);
  BackupHeader header(std::move(buffer));
  const std::array<unsigned char, 16> SALT{
      {15, 2, 129, 15, 226, 145, 190, 233, 34, 69, 131, 134, 16, 228, 99, 187}};
  if (!assert_array<unsigned char, 16>(header.entries().salt.to_unsigned(),
                                       SALT)) {
    return false;
  }
  const std::array<unsigned char, 32> UUHASH{
      {140, 197, 233, 139, 140, 105, 207, 52,  157, 168, 132,
       132, 196, 122, 76,  216, 3,   48,  49,  202, 3,   197,
       223, 163, 233, 43,  15,  71,  94,  177, 153, 90}};
  return assert_array<unsigned char, 32>(
      header.entries().uuidhash.to_unsigned(), UUHASH);
}

struct membuf : std::streambuf {
  membuf(char *begin, char *end) { this->setg(begin, begin, end); }
};

bool test_msg() {
  auto msg = base64_decode(
      "V0JVSQAAAT5xxW76YX91IgLvJwXeC5x+q/"
      "8To15mBzbsA6rc5Dzf7xRyWH+LYv+bscKxj3c7Fl7trr/"
      "9qt78lgA5ZtyjK7d2ZBdSYl4HLskPjyUIseTjAZjGKt+7MEXp8aVBey8ooGep");
  auto password = "1235678";

  membuf buf(msg.data(), msg.data() + msg.size());
  istream inp(&buf);
  auto outp = ostringstream();

  decrypt(inp, outp, Password{password, ""});
  return outp.str() == "123456789";
}

/// Do some little tests for decrypting-routine
void test() {
  if (test_header()) {
    cout << "Header correct " << endl;
  } else {
    cout << "Incorrect header parsing" << endl;
  }
  if (test_msg()) {
    cout << "MSG correct " << endl;
  } else {
    cout << "MSG incorrect" << endl;
  }
}
