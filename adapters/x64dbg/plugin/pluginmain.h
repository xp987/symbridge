#pragma once

// x64dbg SDK. Include dirs (SDK root and SDK/jansson) are set by CMake.
#include "bridgemain.h"
#include "_plugins.h"
#include "_scriptapi_label.h"
#include "_scriptapi_comment.h"
#include "_scriptapi_module.h"
#include "jansson.h"

#define PLUGIN_NAME "symbridge"
#define PLUGIN_VERSION 2

// x64dbg plugin entry points (exported from the .dp64).
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct);
extern "C" __declspec(dllexport) bool plugstop();
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct);
