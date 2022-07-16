#include <common/list.h>
#include <stdint.h>
#include <stdio.h>

void list_init(struct list_head* head) {
    head->next = head;
    head->prev = head;
}

int list_empty(struct list_head* head) {
    return (head->next == head);
}

void list_remove(struct list_head *node) {
    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = NULL;
    node->prev = NULL;
}

void list_push(struct list_head* head, struct list_head *node) {
    node->next = head->next;
    node->prev = head;
    node->next->prev = node;
    node->prev->next = node;
}

void list_append(struct list_head* head, struct list_head *node) {
    struct list_head *tail = head->prev;
    list_push(tail, node);
}

struct list_head *list_pop(struct list_head* head) {
    if (head->next == head) {
        return NULL;
    }
    struct list_head *node = head->next;
    list_remove(node);
    return node;
}
