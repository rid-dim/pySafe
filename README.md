safenet
----

Build Status master:

|Linux/OS X|Windows|Docs|
|:--------:|:-----:|:----:|
|[![Build Status](https://travis-ci.org/rid-dim/pySafe.svg?branch=master)](https://travis-ci.org/rid-dim/pySafe?branch=master)|[![Build status](https://ci.appveyor.com/api/projects/status/qyx4b75u9mxrla1g/branch/master?svg=true)](https://ci.appveyor.com/project/rid-dim/pysafe/branch/master)|[![docs](https://readthedocs.org/projects/pysafe/badge/?version=master)](http://pysafe.readthedocs.io/en/master)|

Build Status dev:

|Linux/OS X|Windows|Docs|
|:--------:|:-----:|:----:|
|[![Build Status](https://travis-ci.org/rid-dim/pySafe.svg?branch=dev)](https://travis-ci.org/rid-dim/pySafe?branch=dev)|[![Build status](https://ci.appveyor.com/api/projects/status/qyx4b75u9mxrla1g/branch/dev?svg=true)](https://ci.appveyor.com/project/rid-dim/pysafe/branch/dev)|[![docs](https://readthedocs.org/projects/pysafe/badge/?version=dev)](http://pysafe.readthedocs.io/en/dev)|


A Python interface for the C FFI API of the SAFE Network (www.maidsafe.net)
---

contributors: rid-dim, duncankushnir

The design goal of pySafe is to provide a full python interface to SAFE network, via the SAFE binaries.

The package (will) include an importable and installable module, as well as utilities to generate the bindings and hopefully eventually some example applications beyond 'hello world'.

Designed to be minimally dependent, however the following modules are not included in the base python install:

-cffi, py-cid, multihash  

We use features that currently require python 3.6+ . With enough interest, we could probably back port it, but this will depend on our chosen asynchronous implementation.

Under heavy development - so please don't criticize but just open a pull request ;)


Installing into an environment
---

First, clone the repo.  We are currently working to find an acceptable PyPi name to enable pip/easy install


- On linux, running upg_local.sh will pip update your local environment to the current pySafe state (any python prog can import pySafe, sym-linked to the development directory):

- sh ./upg_local.sh

- On Windows: upg_local.bat (we now feature Windows compatibility)

- On Mac: well, the way localization is coded should work, but we need someone to compile the binaries on mac and test!

Contributing
----

If you want to help us and work together with us on this project you can just join [our telegram channel](https://t.me/pySafe) or [get in touch with us in the dev forum](https://forum.safedev.org/) or you just open a pull request / contact us on github :)

The more people get involved, the easier it is to utilize safe and the more powerful this library gets the better for freedom of humanity =) Together we work on creating a peoples internet where everybody wins and access to knowledge and freedom of speech are no privileges but universal rights of every human.
