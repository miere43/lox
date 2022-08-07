#include <stdio.h>
#include <string.h>

#include "object.h"
#include "table.h"
#include "common.h"
#include "memory.h"
#include "vm.h"
#include "value.h"

#define ALLOCATE_OBJ(type, objectType) \
	(type*)allocateObject(sizeof(type), objectType)

static Obj* allocateObject(size_t size, ObjType objectType) {
	Obj* obj = (Obj*)reallocate(NULL, 0, size);
	obj->type = objectType;
	obj->isMarked = false;
	obj->next = vm.objects;
	vm.objects = obj;
	return obj;
}

static ObjString* allocateString(const char* chars, int length, uint32_t hash) {
	ObjString* string = ALLOCATE_OBJ(ObjString, OBJ_STRING);
	string->chars = (char*)chars;
	string->length = length;
	string->hash = hash;	
	push(OBJ_VAL(string));
	tableSet(&vm.strings, string, NIL_VAL);
	pop();
	return string;
}

static uint32_t hashString(const char* key, int length) {
	uint32_t hash = 2166136261u;
	for (int i = 0; i < length; i++) {
		hash ^= (uint8_t)key[i];
		hash *= 16777619;
	}
	return hash;
}

ObjString* takeString(char* chars, int length) {
	uint32_t hash = hashString(chars, length);
	ObjString* interned = tableFindString(&vm.strings, chars, length, hash);
	if (interned != NULL) {
		FREE_ARRAY(char, chars, length + 1);
		return interned;
	}
	return allocateString(chars, length, hash);
}

ObjString* copyString(const char* chars, int length) {
	uint32_t hash = hashString(chars, length);
	ObjString* interned = tableFindString(&vm.strings, chars, length, hash);
	if (interned != NULL) {
		return interned;
	}
	char* heapChars = ALLOCATE(char, length + 1);
	memcpy(heapChars, chars, length);
	heapChars[length] = '\0';
	return allocateString(heapChars, length, hash);
}

static void printFunction(ObjFunction* function) {
	if (function->name == NULL) {
		printf("<script>");
		return;
	}

	printf("<fn %s>", function->name->chars);
}

void printObject(Value value) {
	switch (OBJ_TYPE(value)) {
		case OBJ_CLASS:
			printf("%s", AS_CLASS(value)->name->chars);
			break;
		
		case OBJ_CLOSURE:
			printFunction(AS_CLOSURE(value)->function);
			break;
		
		case OBJ_FUNCTION:
			printFunction(AS_FUNCTION(value));
			break;

		case OBJ_NATIVE:
			printf("<native fn>");
			break;
		
		case OBJ_STRING:
			printf("%s", AS_CSTRING(value));
			break;

		case OBJ_UPVALUE:
			printf("upvalue");
			break;

		case OBJ_INSTANCE:
			printf("%s instance", AS_INSTANCE(value)->klass->name->chars);
			break;

		case OBJ_BOUND_METHOD:
			printFunction(AS_BOUND_METHOD(value)->method->function);
			break;
	}
}

ObjFunction* newFunction() {
	ObjFunction* func = ALLOCATE_OBJ(ObjFunction, OBJ_FUNCTION);
	func->arity = 0;
	func->upvalueCount = 0;
	func->name = NULL;
	initChunk(&func->chunk);
	return func;
}

ObjNative* newNative(NativeFn function) {
	ObjNative* native = ALLOCATE_OBJ(ObjNative, OBJ_NATIVE);
	native->function = function;
	return native;
}

ObjClosure* newClosure(ObjFunction* function) {
	ObjUpvalue** upvalues = ALLOCATE(ObjUpvalue*, function->upvalueCount);
	for (int i = 0; i < function->upvalueCount; ++i) {
		upvalues[i] = NULL;
	}
	
	ObjClosure* closure = ALLOCATE_OBJ(ObjClosure, OBJ_CLOSURE);
	closure->function = function;
	closure->upvalues = upvalues;
	closure->upvalueCount = function->upvalueCount;
	return closure;
}

ObjUpvalue* newUpvalue(Value* slot) {
	ObjUpvalue* upvalue = ALLOCATE_OBJ(ObjUpvalue, OBJ_UPVALUE);
	upvalue->location = slot;
	upvalue->next = NULL;
	upvalue->closed = NIL_VAL;
	return upvalue;
}

ObjClass* newClass(ObjString* name) {
	ObjClass* klass = ALLOCATE_OBJ(ObjClass, OBJ_CLASS);
	klass->name = name;
	initTable(&klass->methods);
	return klass;
}

ObjInstance* newInstance(ObjClass* klass) {
	ObjInstance* instance = ALLOCATE_OBJ(ObjInstance, OBJ_INSTANCE);
	instance->klass = klass;
	initTable(&instance->fields);
	return instance;
}

ObjBoundMethod* newBoundMethod(Value receiver, ObjClosure* method) {
	ObjBoundMethod* bound = ALLOCATE_OBJ(ObjBoundMethod, OBJ_BOUND_METHOD);
	bound->receiver = receiver;
	bound->method = method;
	return bound;
}
