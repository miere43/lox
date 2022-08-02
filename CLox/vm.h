#pragma once

#include "object.h"
#include "chunk.h"
#include "table.h"

#define FRAMES_MAX 64
#define STACK_MAX (FRAMES_MAX * UINT8_COUNT)

typedef struct {
	ObjFunction* function;
	uint8_t* ip;
	Value* slots;
} CallFrame;

typedef struct {
	Chunk* chunk;
	uint8_t* ip;
	CallFrame frames[FRAMES_MAX];
	int frameCount;
	Value stack[STACK_MAX];
	Value* stackTop;
	Table globals;
	Table strings;
	Obj* objects;
} VM;

typedef enum {
	INTERPRET_OK,
	INTERPRET_COMPILE_ERROR,
	INTERPRET_RUNTIME_ERROR,
} InterpretResult;

void initVM();
void freeVM();
InterpretResult interpret(const char* source);
void push(Value value);
Value pop();

extern VM vm;
