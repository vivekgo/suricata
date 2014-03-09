Files Modified:
detect-luajit-extensions.c
Description: Added new projections for functions defined in global-var.h and global-hashmap-repetition.h

---------------------------------------------------------------------------------
Files Created:

global-var.h, global-var.c
Description: Support for global string and integer variables, functions are projected into lua (mapping in detect-luajit-extensions.c)

uthash.h
Description: Standard hash map library - provides support for hash map

hash-functions.h
hash-functions.c
Description: Contains 10 hash functions

global-bloomfilter.h
global-bloomfilter.c
Description: Support for bloom filter using all hash functions defined in hash-functions.c

global-hashmap-repetition.h
global-hashmap-repetition.c
Description: Special data-structure HashMap of bloomfilters and hashmaps used for repetition of similar requests heuristics (mapping in detect-luajit-extensions.c)


json-logger.h
json-logger.c
Description: Support for creating json object in C


