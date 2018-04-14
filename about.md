Programming goals
-----

For now, we try a flat structure.. the project is simple enough at present that we probably don't need sub modules

The structure is still fluid: At present, this is on a 'simplest thing that works' basis for the following goals.
- pypi available
- pip installable
- multi platform (windows/linux/mac 64/32bit)
- compilable is a goal, but there is no use compiling until there is a fully working 'server' inside the project. Until then the design is to be imported and used in other projects.  A bundled server implementation would ideally be made in a seperate directory like /examples/ to keep the project modularized


Other thoughts about design:
----------------------------

should we split it up into authenticator / application or just make one module that uses both libs and can act as both ..?
(actually it is kind of hard to find a motivation to have it split ...)
  (DUNCAN: to have useful functionality we need both in the same package)



TODO's are in tasklist.md
---