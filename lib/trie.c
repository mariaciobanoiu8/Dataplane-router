#include <arpa/inet.h>

#include "lib.h"
#include "trie.h"

// creeaza un nou nod in trie
struct trie *create_trie()
{
    struct trie *new_trie = malloc(sizeof(struct trie));
    new_trie->entry = NULL;
    new_trie->children[0] = NULL;
    new_trie->children[1] = NULL;

    return new_trie;
}

// insereaza o ruta in trie
void insert_node(struct trie *root, struct route_table_entry *entry)
{
    uint32_t copy = ntohl(entry->mask);

    int nr_bits = 0;

    // calculam cati biti de 1 are masca
    for (int i = 0; i < 32; i++)
        if ((copy >> (31 - i)) & 1)
            nr_bits++;

    struct trie *current = root;

    // parcurgem prefixul
    for (int i = 0; i < nr_bits; i++)
    {
        int bit = (ntohl(entry->prefix) >> (31 - i)) & 1;

        if (current->children[bit] == NULL)
            current->children[bit] = create_trie();

        // coboram in trie
        current = current->children[bit];
    }

    // salvam ruta
    current->entry = entry;
}

// cauta cea mai buna ruta
struct route_table_entry *search(struct trie *root, uint32_t ip)
{
    struct route_table_entry *best = NULL;
    struct trie *current = root;

    for (int i = 0; i < 32; i++)
    {
        // salvam ruta curenta
        if (current->entry != NULL)
            best = current->entry;

        int bit = (ntohl(ip) >> (31 - i)) & 1;

        // daca nu mai exista copii, ne oprim
        if (current->children[bit] == NULL)
            break;

        // continuam in trie
        current = current->children[bit];
    }
    if (current->entry != NULL)
        best = current->entry;
    return best;
}