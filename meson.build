project('wire-backup-decrypter' ,'cpp',
	default_options : ['cpp_std=c++17'])
sodium = dependency('libsodium', version : '>=1.0.16')
src = ['src/main.cpp', 'src/test.cpp', 'src/crypto.cpp', 'src/backupheader.cpp']
executable('decrypt', sources: src, dependencies: [sodium])
