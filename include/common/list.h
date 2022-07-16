#pragma once
#include <common/macro.h>

struct list_head {
    struct list_head *prev;
    struct list_head *next;
};

void list_init(struct list_head *head);
int list_empty(struct list_head *head);
void list_remove(struct list_head *node);
void list_push(struct list_head *head , struct list_head *node);
void list_append(struct list_head *head , struct list_head *node);
struct list_head *list_pop(struct list_head *node);

#define for_each_in_list(elem, type, field, head) \
	for (elem = container_of((head)->next, type, field); \
	     &((elem)->field) != (head); \
	     elem = container_of(((elem)->field).next, type, field))
