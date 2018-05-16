#ifndef BACKUPHEADER_H
#define BACKUPHEADER_H
#include "utils.h"
#include <any>
#include <string>

using namespace std;

using UUID = string;
using Bytes = DynamicArray<char>;

/**
 *  Password for derive the key from
 */
struct Password {
  string password;
  // Not needed for decrypting.
  // Used for validating that the backup was made
  // for the same user.
  UUID uuid;
};

/**
 * Key used for XChacha20-Poly1305-Stream
 */
struct Key {
  Key();
  Key(string password, Bytes &&salt);
  Bytes password;
  Bytes salt;
};

/**
 * Describes an entry of the backup header
 */
class HeaderFieldDescription {
public:
  virtual uint64_t size() const = 0;
  virtual ~HeaderFieldDescription() {}
  virtual std::any decode(Bytes &&data) const = 0;
  virtual string name() const = 0;
};

/**
 * Holds information needed for decrypting
 */
struct BackupHeaderEntries {
  string platform;
  string emptySpace;
  uint16_t version;
  Bytes salt;
  Bytes uuidhash;
  inline BackupHeaderEntries(const BackupHeaderEntries &other)
      : platform(other.platform), emptySpace(other.emptySpace),
        version(other.version), salt(other.salt.clone()),
        uuidhash(other.uuidhash.clone()) {}
  BackupHeaderEntries() = default;
};

/**
 * Information about the Wire-specific-Header.
 */
class BackupHeader {
private:
  Bytes hash(const UUID &uuid, const Bytes &salt) const;

  BackupHeaderEntries _entries;

public:
  /**
   * Parse the header using the given `buffer`
   */
  BackupHeader(Bytes &&buffer);
  /**
   * Derive the key which can decrypt the data using the
   * given `password`
   * @param password The password the data was encrypted with
   * @return The key which can decrypt the data
   */
  Key deriveKey(const Password &password) const;

  /**
   * Returns the values of the header entries
   */
  BackupHeaderEntries entries() const;

  /**
   * Returns the size of all header entries.
   * This is the number of bytes which should be read
   * and can be given to the constructor.
   * @return The size of all entries
   */
  static uint64_t size_of_all_field();
};

class HeaderException : public std::exception {
private:
  std::string _text;

public:
  inline HeaderException(std::string &&text) : _text(text) {}
  inline virtual const char *what() const throw() { return _text.c_str(); }
};
#endif // BACKUPHEADER_H
