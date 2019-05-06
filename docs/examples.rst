example apps
============

we're written some very basic examples to show how pySafe can already be used to interact with the `SAFE Network`_

some bacis usage examples can be seen here:

- simple `chat example`_
- `uploading some mutable data to safe`_ and generating an xor link for it
- `uploading some immutable data to safe`_


.. _chat example: https://github.com/rid-dim/pySafe/blob/dev/examples/crappyChat_reloaded.ipynb
.. _SAFE Network: https://safenetwork.tech/
.. _uploading some mutable data to safe: https://github.com/rid-dim/pySafe/blob/dev/examples/drop_data_to_random_mutable.ipynb
.. _uploading some immutable data to safe: https://github.com/rid-dim/pySafe/blob/dev/safenetConnection_v04_immutable.ipynb


yet missing examples
====================

we'd like to add some other examples (but didn't manage to do so yet - so if you want to
chime in and like our ideas (or just have your own idea of an example app) feel
free to add it and just open a pull request!

some ideas you might want to test/implement to support this library

- thankscoin implementation in python
- SAFE dns name resolution in python
- alternative dns system (petname system) for safe in python
- alternative authenticator implementation (launcher style - local rpc/rest server that exposes the API functions through a simpler to contact interface than the c api provided by maidsafe
- simple file-synchronization app
- looking into https://github.com/home-assistant/home-assistant and (if possible) make it run with safe
- alternative messenger app interacting with Maidsafes messenger demo app