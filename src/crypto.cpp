#include "crypto.h"
#include <iostream>

#include <sodium/crypto_secretstream_xchacha20poly1305.h>

const uint64_t BUFFER_SIZE = 1024 * 1024;

#define fail(descr)                                                            \
  debug(descr);                                                                \
  throw CryptoException(descr);

int decrypt(std::istream &input, std::ostream &output, Password password) {
  // Read the header
  auto buffer = DynamicArray<char>(BackupHeader::size_of_all_field());
  input.read(buffer.ptr(), buffer.size());
  if (static_cast<uint64_t>(input.gcount()) !=
      BackupHeader::size_of_all_field()) {
    fail("Cannot read enough data for decoding header");
  }

  BackupHeader header(std::move(buffer));
  if (header.entries().platform != "WBUI" || header.entries().version != 1) {
    std::cerr << "Unsupported file, expect errors" << std::endl;
  }
  // derive key
  auto key = header.deriveKey(password);

  // init crypto header
  crypto_secretstream_xchacha20poly1305_state state;
  memset(&state, 0, sizeof(state));

  unsigned char chachaheader[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  input.read((char *)chachaheader,
             crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  if (input.gcount() !=
      static_cast<streamsize>(
          crypto_secretstream_xchacha20poly1305_headerbytes())) {
    fail("Cannot read enough data for decoding crypto parameter");
  }
  
#ifdef VERBOSE
  debug("Chachaheader: ");
  for (unsigned int i = 0;
       i < crypto_secretstream_xchacha20poly1305_HEADERBYTES; i++) {
    debug("%02X ", *(chachaheader + i));
  }
#endif

  if (crypto_secretstream_xchacha20poly1305_init_pull(
          &state, chachaheader, key.password.ptr_unsigned_const()) != 0) {
    fail("Cannot init xchacha20poly1305\n");
  }

  // No idea why this is not zero before. But we have to turn this first byte
  // to zero! Without nothing will work.
  // (Some debugging time was needed to turn this out)
  state.nonce[0] = 0;

  // Decrypting routine
  auto msgBuffer = DynamicArray<char>(BUFFER_SIZE);
  auto cipherBufferSize =
      BUFFER_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
  auto cipherBuffer = DynamicArray<char>(cipherBufferSize);
  unsigned char tag = 0;

  auto totalBytesWritten = 0;
  auto bytesWritten = -1;
  auto bytesRead = -1;

  while (true) {
    input.read(cipherBuffer.ptr(), cipherBuffer.size());
    bytesRead = input.gcount();
    if (bytesRead == 0)
      continue;

    unsigned long long messageLength = msgBuffer.size();
    unsigned long long cipherLength = bytesRead;
    if (crypto_secretstream_xchacha20poly1305_pull(
            &state, msgBuffer.ptr_unsigned(), &messageLength, &tag,
            cipherBuffer.ptr_unsigned(), cipherLength, nullptr, 0) != 0) {
      fail("Cannot decrypt xchacha20poly1305\n");
    }

    auto beg = output.tellp();
    output.write(msgBuffer.ptr(), messageLength);
    bytesWritten = output.tellp() - beg;
    totalBytesWritten += bytesWritten;

    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
      break;
    }

    if (bytesRead <= 0 || bytesWritten <= 0) {
      break;
    }
  }

  if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
    fail("Expected xchacha20poly1305 to be at final tag\n");
  }

  if (bytesRead < 0 || bytesWritten < 0) {
    fail("No bytes read or written\n");
  }

  return totalBytesWritten;
}
