/**
 * Wrapper for android GraphicBuffer class
 * Allowing access to android GraphicBuffer class to share
 * data between GPU and CPU
 *
 * Copyright 2013 Thinstuff Technologies GmbH
 * Copyright 2013 Armin Novak <anovak@thinstuff.at>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <dlfcn.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>

#include "android_graphic_buffer_wrapper.h"

#define ANDROID_LIBUI "libui.so"

#if 0 
#define ERROR(...) do { \
	fprintf(stderr, "[ERROR %s:%d]:", __func__, __LINE__); \
	fprintf(stderr, " " __VA_ARGS__); \
	fprintf(stderr, "\n"); \
} while(0)

#define WARN(...) do { \
	fprintf(stderr, "[WARN %s:%d]:", __func__, __LINE__); \
	fprintf(stderr, " " __VA_ARGS__); \
	fprintf(stderr, "\n"); \
} while(0)

#define INFO(...) do {\
	fprintf(stderr, "[INFO %s:%d]:", __func__, __LINE__); \
	fprintf(stderr, " " __VA_ARGS__); \
	fprintf(stderr, "\n"); \
} while(0)

#define DEBUG(...) do { \
	fprintf(stderr, "[INFO %s:%d]:", __func__, __LINE__); \
	fprintf(stderr, " " __VA_ARGS__); \
	fprintf(stderr, "\n"); \
} while(0)
#else
#define ERROR(...) do { } while(0) 
#define WARN(...) do { } while(0) 
#define INFO(...) do { } while(0) 
#define DEBUG(...) do { } while(0) 
#endif

typedef void (*t_ctor)(void*);
typedef	void (*t_ctor_wh)(void *, uint32_t, uint32_t, uint32_t,
		uint32_t);
typedef	void (*t_ctor_from_window)(void *, ANativeWindowBuffer *,
		bool);
typedef	void (*t_ctor_from_handle)(void *, uint32_t, uint32_t,
		uint32_t, uint32_t, uint32_t, native_handle_t *, bool);

typedef	void (*t_dtor)(void *);

typedef	int (*t_init_check)(void *);

typedef	int (*t_reallocate)(void *handle, uint32_t w, uint32_t h,
	uint32_t f, uint32_t usage);

typedef	int (*t_lock)(void *handle, uint32_t usage, void **vaddr);
typedef	int (*t_lock_surface)(void *handle, EGLSurface *surface,
	uint32_t usage);
typedef	int (*t_unlock)(void *handle);

typedef	ANativeWindowBuffer *(*t_get_native_buffer)(void *handle);

typedef	int (*t_get_index)(void *);
typedef	void (*t_set_index)(void *, int);

typedef	void (*t_dump)(void *handle);

typedef struct
{
	void *dlhandle;

	t_ctor 		ctor;
	t_ctor_wh ctor_wh;
	t_ctor_from_window ctor_from_window;
	t_ctor_from_handle ctor_from_handle;

	t_dtor dtor;

	t_init_check init_check;

	t_reallocate reallocate;
	
	t_lock lock;
	t_lock_surface lock_surface;

	t_unlock unlock;

	t_get_native_buffer get_native_buffer;

	t_get_index get_index;
	t_set_index set_index;

	t_dump dump;

	void *instance;
} t_agbw_handle;

enum
{
	SYM_CTOR = 0,
	SYM_CTOR_WH,
	SYM_CTOR_HDL,
	SYM_CTOR_WINDOW,
	SYM_DTOR,
	SYM_INIT_CHECK,
	SYM_REALLOCATE,
	SYM_LOCK,
	SYM_LOCK_SURFACE,
	SYM_UNLOCK,
	SYM_GET_NATIVE,
	SYM_SET_INDEX,
	SYM_GET_INDEX,
	SYM_DUMP
};

static const char *agbw_symbols[] =
{
	"_ZN7android13GraphicBufferC1Ev",
	"_ZN7android13GraphicBufferC1Ejjij",
	"_ZN7android13GraphicBufferC1EjjijjP13native_handleb",
	"_ZN7android13GraphicBufferC1EP19ANativeWindowBufferb",
	"_ZN7android13GraphicBufferD1Ev",
	"_ZNK7android13GraphicBuffer9initCheckEv",
	"_ZN7android13GraphicBuffer10reallocateEjjij",
	"_ZN7android13GraphicBuffer4lockEjPPv",
	"_ZN7android19GraphicBufferMapper4lockEPK13native_handleiRKNS_4RectEPPv",
	"_ZN7android13GraphicBuffer6unlockEv",
	"_ZNK7android13GraphicBuffer15getNativeBufferEv",
	"_ZN7android13GraphicBuffer8setIndexEi",
	"_ZNK7android13GraphicBuffer8getIndexEv",
	"_ZN7android22GraphicBufferAllocator15dumpToSystemLogEv"
};

static void dump_pointer(const t_agbw_handle *hdl)
{
	INFO("hdl                   = %p", hdl);
	if (hdl)
	{
		INFO("hdl->dlhandle         = %p", hdl->dlhandle);
		INFO("hdl->ctor             = %p", hdl->ctor);
		INFO("hdl->ctor_wh          = %p", hdl->ctor_wh);
		INFO("hdl->ctor_from_window = %p", hdl->ctor_from_window);
		INFO("hdl->ctor_from_handle = %p", hdl->ctor_from_handle);
		INFO("hdl->dtor             = %p", hdl->dtor);
		INFO("hdl->init_check       = %p", hdl->init_check);
		INFO("hdl->reallocate       = %p", hdl->reallocate);
		INFO("hdl->lock             = %p", hdl->lock);
		INFO("hdl->lock_surface     = %p", hdl->lock_surface);
		INFO("hdl->unlock           = %p", hdl->unlock);
		INFO("hdl->get_native_buffer= %p", hdl->get_native_buffer);
		INFO("hdl->get_index        = %p", hdl->get_index);
		INFO("hdl->set_index        = %p", hdl->set_index);
		INFO("hdl->dump             = %p", hdl->dump);
	}
}

static bool handle_valid(const t_agbw_handle *hdl)
{
	bool rc = true;

	DEBUG("");

	dump_pointer(hdl);

	if (!hdl)
		rc = false;
	if (!hdl->instance)
		rc = false;
	if (!hdl->dlhandle)
		rc = false;
	if (!hdl->ctor)
		rc = false;
	if (!hdl->ctor_wh)
		rc = false;
	if (!hdl->ctor_from_window)
		rc = false;
	if (!hdl->ctor_from_handle)
		rc = false;
	if (!hdl->dtor)
		rc = false;
	if (!hdl->lock)
		rc = false;
	if (!hdl->lock_surface)
		rc = false;
	if (!hdl->unlock)
		rc = false;
	if (!hdl->get_native_buffer)
		rc = false;
	if (!hdl->get_index)
		rc = false;
	if (!hdl->set_index)
		rc = false;
	if (!hdl->dump)
		rc = false;

	assert(rc);

	return rc;
}

static void unload_function_pointer(t_agbw_handle *hdl)
{
	int rc;

	DEBUG("hdl=%p", handle);

	dump_pointer(hdl);

	if (hdl)
	{
		if (hdl->dlhandle)
		{
			rc = dlclose(hdl->dlhandle);
			if (rc)
				ERROR("[dlclose]: %s", dlerror());

			memset(hdl, 0, sizeof(t_agbw_handle));
		}

		if (hdl->instance)
			free(hdl->instance);

		free(hdl);
	}
}

static t_agbw_handle *load_function_pointer(void)
{
	t_agbw_handle *hdl = (t_agbw_handle*)calloc(sizeof(t_agbw_handle), 1);
	
	DEBUG("hdl=%p", hdl);

	if (!hdl)
	{
		ERROR("[calloc]: hdl=%p, %s", hdl, strerror(errno));
		goto cleanup;
	}

	hdl->dlhandle = dlopen(ANDROID_LIBUI, RTLD_LAZY);
	if (!hdl->dlhandle)
	{
		ERROR("[dlopen]: %s");
		goto cleanup;
	}

	hdl->ctor = (t_ctor)dlsym(hdl->dlhandle, agbw_symbols[SYM_CTOR]);
	if (!hdl->ctor)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_CTOR]);
		goto cleanup;
	}

	hdl->ctor_wh = (t_ctor_wh)dlsym(hdl->dlhandle, agbw_symbols[SYM_CTOR_WH]);
	if (!hdl->ctor_wh)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_CTOR_WH]);
		goto cleanup;
	}

	hdl->ctor_from_window = (t_ctor_from_window)dlsym(hdl->dlhandle,
			agbw_symbols[SYM_CTOR_WINDOW]);
	if (!hdl->ctor_from_window)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_CTOR_WINDOW],
				dlerror());
		goto cleanup;
	}

	hdl->ctor_from_handle = (t_ctor_from_handle)dlsym(hdl->dlhandle,
			agbw_symbols[SYM_CTOR_HDL]);
	if (!hdl->ctor_from_handle)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_CTOR_HDL],
				dlerror());
		goto cleanup;
	}

	hdl->dtor = (t_dtor)dlsym(hdl->dlhandle, agbw_symbols[SYM_DTOR]);
	if (!hdl->dtor)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_DTOR]);
		goto cleanup;
	}

	hdl->init_check = (t_init_check)dlsym(hdl->dlhandle,
			agbw_symbols[SYM_INIT_CHECK]);
	if (!hdl->init_check)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_INIT_CHECK]);
		goto cleanup;
	}

	hdl->reallocate = (t_reallocate)dlsym(hdl->dlhandle,
			agbw_symbols[SYM_REALLOCATE]);
	if (!hdl->reallocate)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_REALLOCATE]);
		goto cleanup;
	}

	
	hdl->lock = (t_lock)dlsym(hdl->dlhandle, agbw_symbols[SYM_LOCK]);
	if (!hdl->lock)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_LOCK]);
		goto cleanup;
	}

	hdl->lock_surface = (t_lock_surface)dlsym(hdl->dlhandle,
			agbw_symbols[SYM_LOCK_SURFACE]);
	if (!hdl->lock_surface)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_LOCK_SURFACE]);
		goto cleanup;
	}

	hdl->unlock = (t_unlock)dlsym(hdl->dlhandle, agbw_symbols[SYM_UNLOCK]);
	if (!hdl->unlock)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_UNLOCK]);
		goto cleanup;
	}

	hdl->get_native_buffer = (t_get_native_buffer)dlsym(hdl->dlhandle,
			agbw_symbols[SYM_GET_NATIVE]);
	if (!hdl->get_native_buffer)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_GET_NATIVE]);
		goto cleanup;
	}

	hdl->get_index = (t_get_index)dlsym(hdl->dlhandle,
			agbw_symbols[SYM_GET_INDEX]);
	if (!hdl->get_index)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_GET_INDEX]);
		goto cleanup;
	}

	hdl->set_index = (t_set_index)dlsym(hdl->dlhandle,
			agbw_symbols[SYM_SET_INDEX]);
	if (!hdl->set_index)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_SET_INDEX]);
		goto cleanup;
	}


	hdl->dump = (t_dump)dlsym(hdl->dlhandle, agbw_symbols[SYM_DUMP]);
	if (!hdl->dump)
	{
		ERROR("[dlsym] [%s]: %s", dlerror(), agbw_symbols[SYM_DUMP]);
		goto cleanup;
	}

	hdl->instance = calloc(sizeof(int), 4096);
	if (!hdl->instance)
	{
		ERROR("[calloc]: hdl->instance=%p, %s", hdl->instance, strerror(errno));
		goto cleanup;
	}

	dump_pointer(hdl);

	return hdl;

cleanup:
	unload_function_pointer(hdl);

	return NULL;
}

void *agbw_new(void)
{
	t_agbw_handle *hdl = load_function_pointer();
	
	DEBUG("hdl=%p", hdl);

	if (!hdl)
		goto cleanup;

	hdl->ctor(hdl->instance);
	dump_pointer(hdl);

	return hdl;

cleanup:
	unload_function_pointer(hdl);
	return NULL;
}

void *agbw_new_wh(uint32_t w, uint32_t h, uint32_t format, uint32_t usage)
{
	t_agbw_handle *hdl = load_function_pointer();
	
	DEBUG("hdl=%p", hdl);

	if (!hdl)
		return NULL;

	hdl->ctor_wh(hdl->instance, w, h, format, usage);

	return hdl;
}

void *agbw_new_from_window(ANativeWindowBuffer *buffer, bool keep_ownership)
{
	t_agbw_handle *hdl = load_function_pointer();
	
	DEBUG("hdl=%p", hdl);

	if (!hdl)
		return NULL;

	hdl->ctor_from_window(hdl->instance, buffer, keep_ownership);

	return hdl;
}

void *agbw_new_from_handle(uint32_t w, uint32_t h, uint32_t format,
	uint32_t usage, uint32_t stride, native_handle_t *handle,
	bool keep_ownership)
{
	t_agbw_handle *hdl = load_function_pointer();
	
	DEBUG("hdl=%p", hdl);

	if (!hdl)
		return NULL;

	hdl->ctor_from_handle(hdl->instance, w, h, format, usage,
			stride, handle,	keep_ownership);

	return hdl;
}

void agbw_free(void *handle)
{
	t_agbw_handle *hdl = (t_agbw_handle*)handle;
	
	DEBUG("hdl=%p", handle);

	if (handle_valid(hdl))
	{
		hdl->dtor(hdl->instance);

		unload_function_pointer(hdl);
	}
}

int agbw_init_check(void *handle)
{
	int status;
	t_agbw_handle *hdl = (t_agbw_handle*)handle;

	DEBUG("hdl=%p", handle);
	
	if (handle_valid(hdl))
		status = hdl->init_check(hdl->instance);

	return status;
}

int agbw_reallocate(void *handle, uint32_t w, uint32_t h,
		uint32_t f, uint32_t usage)
{
	int status;
	t_agbw_handle *hdl = (t_agbw_handle*)handle;

	DEBUG("hdl=%p", handle);

	if (handle_valid(hdl))
		status = hdl->reallocate(hdl->instance, w, h, f, usage);

	return status;
}


int agbw_lock(void *handle, uint32_t usage, void **vaddr)
{
	int status;
	t_agbw_handle *hdl = (t_agbw_handle*)handle;

	DEBUG("hdl=%p", handle);

	if (handle_valid(hdl))
		status = hdl->lock(hdl->instance, usage, vaddr);

	return status;
}

int agbw_lock_surface(void *handle, EGLSurface *surface, uint32_t usage)
{
	int status;
	t_agbw_handle *hdl = (t_agbw_handle*)handle;

	DEBUG("hdl=%p", handle);

	if (handle_valid(hdl))
		status = hdl->lock_surface(hdl->instance, surface, usage);

	return status;
}

int agbw_unlock(void *handle)
{
	int status;
	t_agbw_handle *hdl = (t_agbw_handle*)handle;

	DEBUG("hdl=%p", handle);

	if (handle_valid(hdl))
		status = hdl->unlock(hdl->instance);

	return status;
}

ANativeWindowBuffer * agbw_get_native_buffer(void *handle)
{
	ANativeWindowBuffer *rc = NULL;
	t_agbw_handle *hdl = (t_agbw_handle*)handle;

	DEBUG("hdl=%p", handle);

	if (handle_valid(hdl))
		rc = hdl->get_native_buffer(hdl->instance);

	return rc;
}

void agbw_set_index(void *handle, int index)
{
	t_agbw_handle *hdl = (t_agbw_handle*)handle;

	DEBUG("hdl=%p", handle);

	if (handle_valid(hdl))
		hdl->set_index(hdl->instance, index);
}

int agbw_get_index(void *handle)
{
	int rc = -1;
	t_agbw_handle *hdl = (t_agbw_handle*)handle;

	DEBUG("hdl=%p", handle);

	if (handle_valid(hdl))
		rc = hdl->get_index(hdl->instance);

	return rc;
}

void agbw_dump_allocations_to_system_log(void *handle)
{
	t_agbw_handle *hdl = (t_agbw_handle*)handle;

	DEBUG("hdl=%p", handle);

	if (handle_valid(hdl))
		hdl->dump(hdl->instance);
}

