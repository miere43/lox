#include <stdio.h>
#include <string.h>

#include "object.h"
#include "common.h"
#include "memory.h"
#include "vm.h"
#include "value.h"

#define ALLOCATE_OBJ(type, objectType) \
	(type*)allocateObject(sizeof(type), objectType)

static Obj* allocateObject(size_t size, ObjType objectType) {
	Obj* obj = (Obj*)reallocate(NULL, 0, size);
	obj->type = objectType;
	obj->next = vm.objects;
	vm.objects = obj;
	return obj;
}

static ObjString* allocateString(const char* chars, int length) {
	ObjString* string = ALLOCATE_OBJ(ObjString, OBJ_STRING);
	string->chars = (char*)chars;
	string->length = length;
	return string;
}

ObjString* takeString(const char* chars, int length) {
	return allocateString(chars, length);
}

ObjString* copyString(const char* chars, int length) {
	char* heapChars = ALLOCATE(char, length + 1);
	memcpy(heapChars, chars, length);
	heapChars[length] = '\0';
	return allocateString(heapChars, length);
}

void printObject(Value value) {
	switch (OBJ_TYPE(value)) {
		case OBJ_STRING:
			printf("%s", AS_CSTRING(value));
			break;
	}
}