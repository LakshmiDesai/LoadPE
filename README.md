
MemoryModule 0.0.3 released

Much time has passed since the last version, so I¡¯m pleased to announce the release of MemoryModule 0.0.3.

MemoryModule is a library that can be used to load a DLL completely from memory ¨C without storing on the disk first.

Changes since 0.0.2:

    fixed compilation issues with gcc
    added mingw makefile
    added support for 64bit DLLs
    fixed compilation issue when using Vista SDK?
    fixed wrong checking of result from LoadLibrary for errors (issue #2)
    minor code cleanup
