#pragma once

#include "common.h"
#include "value.h"

typedef enum {
	OBJ_STRING,
} ObjType;

#define OBJ_TYPE(value) (AS_OBJ(value)->type)

#define IS_STRING(value) isObjType(value, OBJ_STRING)

#define AS_STRING(value) ((ObjString*)AS_OBJ(value))
#define AS_CSTRING(value) (((ObjString*)AS_OBJ(value))->chars)

struct Obj {
	ObjType type;
	struct Obj* next;
};

static inline bool isObjType(Value value, ObjType type) {
	return IS_OBJ(value) && AS_OBJ(value)->type == type;
}

struct ObjString {
	Obj obj;
	int length;
	char* chars;
};

ObjString* takeString(const char* chars, int length);
ObjString* copyString(const char* chars, int length);
void printObject(Value value);
