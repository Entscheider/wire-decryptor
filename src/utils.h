#ifndef UTILS_H
#define UTILS_H

#include <cstring>
#include <memory>
#include <stdio.h>
#include <type_traits>
#include <vector>

#define debug(...) fprintf(stderr, __VA_ARGS__)

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define IS_BIG_ENDIAN
#endif

template <typename T> T swap_endian(T el) {
  // TODO: I'm sure there are faster implementation, but this is just enough for
  // now
  auto res = new char[sizeof(T)];
  auto cur = reinterpret_cast<char *>(&el);
  for (size_t i = 0; i < sizeof(T); i++) {
    res[i] = cur[sizeof(T) - 1 - i];
  }
  return *reinterpret_cast<T *>(res);
}

using namespace std;

/**
 * DynamicArray capsules an array of type T.
 * Additionaly it contains some helper function
 * to intepret its content.
 */
template <typename T> class DynamicArray {
public:
  /**
   * Initializes an empty DynamicArray
   */
  DynamicArray() : _size(0), _data(nullptr) {}

  /**
   * Initializes an array of the given `size` and sets
   * its content to 0
   * @param size the size of this array
   */
  DynamicArray(unsigned int size) : _size(size) {
    _data = std::unique_ptr<T[]>(new T[size]);
    memset(_data.get(), 0, size);
  }

  /**
   * Takes ownership of the given `array`
   * @param array The array
   * @param size The size of array
   */
  DynamicArray(T *array, unsigned int size) : _size(size) {
    _data = std::unique_ptr<T[]>(array);
  }

  /**
   * Move the array from `other` to initialize this DynamicArray
   * @param other The other DynamicArray, which content should be moved.
   */
  DynamicArray(DynamicArray<T> &&other) : _size(other._size) {
    _data = std::move(other._data);
    other._size = 0;
  }

  /**
   * Copy the array from `other` to initialize this DynamicArray
   * @param other The other DynamicArray, which content should be copied.
   */
  DynamicArray(const DynamicArray<T> &other) : _size(other._size) {
    char *tmp = (char *)malloc(other.size() * sizeof(T));
    memcpy(tmp, other.ptr_const(), _size);
    _data = std::unique_ptr<T[]>(tmp);
  }

  /**
   * Copy the content of a vector<T> to initialize this array
   * @param other The vector with the content
   */
  DynamicArray(const vector<T> &other) : _size(other.size()) {
    auto tmp = new T[_size];
    std::copy(other.begin(), other.end(), tmp);
    _data = std::unique_ptr<T[]>(tmp);
  }

  /**
   * Moves the array from `other` to this
   * @param other Another DynamicArray which content should be moved
   * @return a reference to this DynamicArray
   */
  DynamicArray<T> &operator=(DynamicArray<T> &&other) {
    _data = std::move(other._data);
    _size = other._size;
    other._size = 0;
    return *this;
  }

  T &operator[](int idx) { return *(_data.get() + idx); }

  const T &operator[](int idx) const { return *(_data.get() + idx); }

  /**
   * Returns the raw array. The content will be moved, so that
   * this DynamicArray-Object is not usable anymore after this
   * operation.
   * @return  The raw array.
   */
  T *release() {
    _size = 0;
    return _data.release();
  }

  /**
   * Returns a pointer to the array. DynamicArray retains the array.
   * @return A pointer to the array
   */
  T *ptr() { return _data.get(); }

  /**
   * Returns a const pointer to the array. DynamicArray retains the array.
   * @return A const pointer to the array
   */
  const T *ptr_const() const { return _data.get(); }

  /**
   * Interprets the array of type T as an array of the signed variant of T.
   * A pointer to this signed-value array will be returned.
   * @return A pointer to the array of the signed type
   */
  typename std::make_signed<T>::type *ptr_signed() {
    return reinterpret_cast<typename std::make_signed<T>::type *>(ptr());
  }

  /**
   * Const variant of `ptr_signed()`
   * @return A const pointer to the array of the signed type
   */
  const typename std::make_signed<T>::type *ptr_signed_const() const {
    return reinterpret_cast<const typename std::make_signed<T>::type *>(
        ptr_const());
  }

  /**
   * Interprets the array of type T as an array of the unsigned variant of T.
   * A pointer to this unsigned-value array will be returned.
   * @return A pointer to the array of the signed type
   */
  typename std::make_unsigned<T>::type *ptr_unsigned() {
    return reinterpret_cast<typename std::make_unsigned<T>::type *>(ptr());
  }

  /**
   * Const variant of `ptr_unsigned()`
   * @return A const pointer to the array of the unsigned type
   */
  const typename std::make_unsigned<T>::type *ptr_unsigned_const() const {
    return reinterpret_cast<const typename std::make_unsigned<T>::type *>(
        ptr_const());
  }

  int size() const { return _size; }

  bool is_empty() const { return _size == 0; }

  /**
   * Returns a DynamicArray of the signed type of T.
   * The array will be the same just the data will be reinterpret
   * to be of the signed type.
   * The returned array takes the ownership, so this object is
   * not usable anymore.
   * @return A new DynamicArray of the signed type
   */
  DynamicArray<typename std::make_signed<T>::type> to_signed() {
    auto size = _size;
    auto data =
        reinterpret_cast<typename std::make_signed<T>::type *>(release());
    return DynamicArray<typename std::make_signed<T>::typ>(data, size);
  }

  /**
   * Returns a DynamicArray of the unsigned type of T.
   * The array will be the same just the data will be reinterpret
   * to be of the unsigned type.
   * The returned array takes the ownership, so this object is
   * not usable anymore.
   * @return A new DynamicArray of the signed type
   */
  DynamicArray<typename std::make_unsigned<T>::type> to_unsigned() {
    auto size = _size;
    auto data =
        reinterpret_cast<typename std::make_unsigned<T>::type *>(release());
    return DynamicArray<typename std::make_unsigned<T>::type>(data, size);
  }

  /**
   * Returns a DynamicArray which contains a subset of this DynamicArray.
   * This subset will be copied for that.
   * @param beg The start of the subset (beginning at 0)
   * @param end The end of the subset (exclusive)
   * @return  A new DynamicArray which holds a subset
   */
  DynamicArray<T> copy_sub(unsigned int beg, unsigned int end) {
    if (beg < 0 || end > _size) {
      throw std::invalid_argument("Invalid values for beg or end");
    }
    auto res = new T[end - beg];
    memset(res, 0, end - beg);
    std::copy(ptr() + beg, ptr() + end, res);
    return DynamicArray<T>(res, end - beg);
  }

  /**
   * Interprets the content as a string and returns it
   * @return The content as string
   */
  string as_str() const { return string(ptr_const(), 0, _size); }

  /**
   * Interpret the content of this array as a value
   * of type N, which was saved in little endian format.
   */
  template <typename N> N as_type_le() const {
#ifndef IS_BIG_ENDIAN
    return as_type_native<N>();
#else
    return swap_endian(as_type_native<N>());
#endif
  }

  /**
   * Interpret the content of this array as a value
   * of type N, which was saved in the local format of this cpu.
   */
  template <typename N> N as_type_native() const {
    if (_size != sizeof(N)) {
      throw std::invalid_argument("cannot cast, size of array is invalid ");
    }
    return *reinterpret_cast<N *>(_data.get());
  }

  /**
   * Interpret the content of this array as a value
   * of type N, which was saved in big endian format.
   */
  template <typename N> N as_type_be() const {
#ifdef IS_BIG_ENDIAN
    return as_type_native<N>();
#else
    return swap_endian(as_type_native<N>());
#endif
  }

  bool operator==(const DynamicArray<T> &other) {
    // TODO: Faster implementation
    if (other._size != _size)
      return false;
    for (unsigned int i = 0; i < _size; i++) {
      if (_data[i] != other._data[i])
        return false;
    }
    return true;
  }
  bool operator!=(const DynamicArray<T> &other) { return !operator==(other); }

  DynamicArray<T> clone() const {
    auto res = new T[_size];
    std::copy(_data.get(), _data.get() + _size, res);
    return DynamicArray<T>(res, _size);
  }

private:
  unsigned int _size;
  unique_ptr<T[]> _data;
};

#endif // UTILS_H
