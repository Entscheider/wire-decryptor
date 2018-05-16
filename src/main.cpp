#include "crypto.h"
#include <exception>
#include <fstream>
#include <iostream>
#include <sodium.h>

using namespace std;

#ifdef TEST
#include "test.h"

int main(int argc, char **argv) {
  if (sodium_init() < 0) {
    cerr << "Unable to initialize crypto" << endl;
    return -1;
  }

  test();
  return 0;
}
#else
int main(int argc, char **argv) {
  if (sodium_init() < 0) {
    cerr << "Unable to initialize crypto" << endl;
    return -1;
  }

  if (argc != 4) {
    cout << argv[0] << " input-file output-file password" << endl;
    return -1;
  }

  auto inp = argv[1];
  auto outp = argv[2];
  auto pass = argv[3];
  auto uuid = "";
  if (argc == 5) {
    uuid = argv[4];
  }

  auto i = ifstream(inp);
  auto o = ofstream(outp);

  Password p{string(pass), uuid};
  try {
    cout << "Start decrypting" << endl;
    decrypt(i, o, p);
    cout << "Decrypting sucessfully" << endl;
  } catch (exception &e) {
    cerr << "Failure: " << e.what() << endl;
  }
}
#endif
