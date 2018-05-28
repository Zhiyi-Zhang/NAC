NAC (Name-based Access Control over NDN)
========================================

This is a refactored version of NAC by Zhiyi Zhang (zhiyi@cs.ucla.edu).
The new NAC decouples the application scenarios and the library functionality.

The library has two main parts:

* Crypto support part (./src/crypto)

  * RSA support (depend on [ndn-cxx](https://github.com/named-data/ndn-cxx))
  * AES_CBC support (depend on [ndn-cxx](https://github.com/named-data/ndn-cxx))

* NAC functionality (./src)

  * Owner: generate E-KEY (producers use E-KEY to generate encrypted Content) and D-KEY (consumers use D-KEY to decrypt content)
  * Producer: generate encrypted content Data packets
  * Consumer: consume content Data packets

Install and Compile NAC
=======================

1. Clone the github repo
```
git clone https://github.com/Zhiyi-Zhang/NAC.git
```

2. Compile from source
```
cd NAC
./waf configure
./waf
```

In the `./waf configure` step, the script will check all the required dependencies.
If any dependency is missing, please install the dependency first and redo the `./waf configure`.

All the dependencies are listed here:
* [ndn-cxx](https://github.com/named-data/ndn-cxx)
* BOOST (Given that ndn-cxx also depends on BOOST, thus if you successfully install the ndn-cxx, then you are all set :D )

3. Install the library
```
./waf install
```

Use NAC
=======
Link NAC when you compile your code.
After perform `./waf install` described in the last section, you can directly use pkg-config to link the NAC library.
```
CFLAGS+= `pkg-config --cflags nac`
LDFLAGS+= `pkg-config --libs nac`
```

All functions in Owner, Producer, Consumer classes are well commented, so have fun :D.

Bug Report
==========
You can send a email to me (zhiyi@cs.ucla.edu)