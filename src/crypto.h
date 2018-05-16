#ifndef CRYPTO_H
#define CRYPTO_H

#include "backupheader.h"
#include <exception>
#include <istream>

/**
 * Decrypts the data from input to output using the given password.
 * @param input A stream which gives the encrypted data
 * @param output A stream where the encrypted data should be written at
 * @param password The password for decrypting
 * @return The lenght of the written data
 */
int decrypt(std::istream &input, std::ostream &output, Password password);

class CryptoException : public std::exception {
private:
  std::string _text;

public:
  inline CryptoException(std::string &&text) : _text(text) {}
  inline virtual const char *what() const throw() { return _text.c_str(); }
};

#endif // CRYPTO_H
