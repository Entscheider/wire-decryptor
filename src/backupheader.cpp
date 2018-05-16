#include "backupheader.h"
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <vector>

#define fail(descr)                                                            \
  debug(descr);                                                                \
  throw HeaderException(descr);

/// Describes a bytes-field in header
class ByteDescr : public HeaderFieldDescription {
private:
  uint64_t _size;
  string _name;

public:
  ByteDescr(uint64_t size, string name) : _size(size), _name(name) {}
  uint64_t size() const override { return _size; }
  std::any decode(Bytes &&data) const override {
    return make_any<Bytes>(std::move(data));
  }

  std::string name() const { return _name; }
};

/// Describes a string-field in header
class StringDescr : public HeaderFieldDescription {
private:
  uint64_t _size;
  string _name;

public:
  StringDescr(uint64_t size, string name) : _size(size), _name(name) {}
  uint64_t size() const override { return _size; }
  std::any decode(Bytes &&data) const override {
    return make_any<string>(data.as_str());
  }
  std::string name() const { return _name; }
};

/// Describes a type-field in header (big endian)
template <typename T> class TypeBEDescr : public HeaderFieldDescription {
private:
  string _name;

public:
  TypeBEDescr(string name) : _name(name) {}
  uint64_t size() const override { return sizeof(T); }
  std::any decode(Bytes &&data) const override {
    return make_any<T>(data.as_type_be<T>());
  }
  std::string name() const { return _name; }
};

/// The descriptions of the current fields of the header
static std::array<HeaderFieldDescription *, 5> HeaderList = {
    new StringDescr(4, "platform"), new ByteDescr(1, "empty"),
    new TypeBEDescr<uint16_t>("version"), new ByteDescr(16, "salt"),
    new ByteDescr(32, "uuid")};

Bytes BackupHeader::hash(const UUID &uuid, const Bytes &salt) const {
  const int hashSize = 32;
  auto hash = DynamicArray<char>(hashSize);
  if (crypto_pwhash_argon2i(hash.ptr_unsigned(), hashSize, uuid.c_str(),
                            uuid.length(), salt.ptr_unsigned_const(),
                            crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE,
                            crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE,
                            crypto_pwhash_argon2i_ALG_ARGON2I13) != 0) {
    fail("Cannot computer hash\n");
  }
  return hash;
}

BackupHeader::BackupHeader(Bytes &&buffer) {
  if (static_cast<uint64_t>(buffer.size()) < size_of_all_field()) {
    throw HeaderException("Buffer is too small");
  }

  int idx = 0;
  for (auto el : HeaderList) {
    auto len = el->size();
    auto res = el->decode(buffer.copy_sub(idx, idx + len));
    auto name = el->name();
    if (name == "platform") {
      _entries.platform = any_cast<string>(res);
    } else if (name == "version") {
      _entries.version = any_cast<uint16_t>(res);
    } else if (name == "salt") {
      _entries.salt = any_cast<Bytes>(res);
    } else if (name == "uuid") {
      _entries.uuidhash = any_cast<Bytes>(res);
    }
    idx += len;
  }

  debug("Platform %s, version %d\n", _entries.platform.c_str(),
        _entries.version);
}

Key BackupHeader::deriveKey(const Password &password) const {
#if 0
    if (hash(password.uuid, _entries.salt) != _entries.uuidhash){
        // TODO: Throw exception
        debug("UUID mismatch (not a problem)\n");
        //return Key();
    }
#endif
  return Key(password.password, _entries.salt.clone());
}

BackupHeaderEntries BackupHeader::entries() const { return _entries; }

uint64_t BackupHeader::size_of_all_field() {
  uint64_t res = 0;
  for (auto el : HeaderList) {
    res += el->size();
  }
  return res;
}

Key::Key() {}

template <typename T, int N> constexpr int as(T (&)[N]) { return N; }

Key::Key(string password, Bytes &&_salt) : salt(std::move(_salt)) {
  auto buffer = Bytes(crypto_secretstream_xchacha20poly1305_KEYBYTES);
  if (crypto_pwhash_argon2i(buffer.ptr_unsigned(), buffer.size(),
                            password.c_str(), password.length(),
                            salt.ptr_unsigned(),
                            crypto_pwhash_argon2i_OPSLIMIT_MODERATE,
                            crypto_pwhash_argon2i_MEMLIMIT_MODERATE,
                            crypto_pwhash_argon2i_ALG_ARGON2I13) != 0) {
    fail("Cannot derive key\n");
  }
#if 0
    debug("Salt: ");
    for(int i=0; i<salt.size();i++){
        debug("%02X ", *(salt.ptr_unsigned()+i));
    }
    debug("\nKey: ");
    for(int i=0; i<buffer.size();i++){
        debug("%02X ", *(buffer.ptr_unsigned_const()+i));
    }
    debug("\n");
#endif
  this->password = std::move(buffer);
}
