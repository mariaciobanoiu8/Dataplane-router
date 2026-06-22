#ifndef _TRIE_H_
#define _TRIE_H_

#include "lib.h"

struct trie{
    struct trie *children[2];
    struct route_table_entry *entry;
};

struct trie *create_trie();
void insert_node(struct trie *root, struct route_table_entry *entry);
struct route_table_entry *search(struct trie *root, uint32_t ip);

#endif