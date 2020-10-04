# Serialize/deserialize data: 
Context ID (16 bit), DCN Address (32 bit), TCP ID (32 bit)
```C++
/*
Discovery trigger message (84 bits)
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 0 0 1 0|     DA DCN Context ID         |     DA DCN Address
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
             DA DCN Address             |     Local TCP-ID 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
              Local TCP-ID              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/
```
# Build
## GCC
```bash
g++ --std=c++17 -o pack84 pack84.cpp
```
## CMAKE
```bash
mkdir build
cd build
cmake ..
make
```
## msys2/mingw
```bash
g++ --std=c++17 -o pack84 pack84.cpp -lws2_32
```
## MSVC (cl)
```bash
cl /std:c++17 pack84.cpp ws2_32.lib
```
# Run
```bash
./pack84 <16-bits Context ID> <32-bits DCN Address> <32-bits Local TCP-ID>
```
Example:
```bash
./pack84 0x4321 0x87654321 0xfedcba98
```
