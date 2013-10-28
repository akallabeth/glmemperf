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

#ifndef ANDROID_GRAPHIC_BUFFER_WRAPPER_H_
#define ANDROID_GRAPHIC_BUFFER_WRAPPER_H_

#ifdef __cplusplus /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <android/native_window.h>

/* Copied from Android's gralloc.h */
enum gfxImageUsage {
    /* buffer is never read in software */
    GRALLOC_USAGE_SW_READ_NEVER = 0x00000000,
    /* buffer is rarely read in software */
    GRALLOC_USAGE_SW_READ_RARELY = 0x00000002,
    /* buffer is often read in software */
    GRALLOC_USAGE_SW_READ_OFTEN = 0x00000003,
    /* mask for the software read values */
    GRALLOC_USAGE_SW_READ_MASK = 0x0000000F,

    /* buffer is never written in software */
    GRALLOC_USAGE_SW_WRITE_NEVER = 0x00000000,
    /* buffer is never written in software */
    GRALLOC_USAGE_SW_WRITE_RARELY = 0x00000020,
    /* buffer is never written in software */
    GRALLOC_USAGE_SW_WRITE_OFTEN = 0x00000030,
    /* mask for the software write values */
    GRALLOC_USAGE_SW_WRITE_MASK = 0x000000F0,

    /* buffer will be used as an OpenGL ES texture */
    GRALLOC_USAGE_HW_TEXTURE = 0x00000100,
    /* buffer will be used as an OpenGL ES render target */
    GRALLOC_USAGE_HW_RENDER = 0x00000200,
    /* buffer will be used by the 2D hardware blitter */
    GRALLOC_USAGE_HW_2D = 0x00000400,
		GRALLOC_USAGE_HW_COMPOSER = 0x00000800, 

    /* buffer will be used with the framebuffer device */
    GRALLOC_USAGE_HW_FB = 0x00001000,
    /* mask for the software usage bit-mask */
    GRALLOC_USAGE_HW_MASK = 0x00071F00,

		GRALLOC_USAGE_HW_CAMERA_WRITE = 0x00020000,
		GRALLOC_USAGE_HW_CAMERA_READ = 0x00040000, 
		GRALLOC_USAGE_HW_CAMERA_ZSL = 0x00060000,
		GRALLOC_USAGE_HW_CAMERA_MASK = 0x00060000,
		GRALLOC_USAGE_EXTERNAL_DISP = 0x00002000, 
		GRALLOC_USAGE_PROTECTED = 0x00004000,
		GRALLOC_USAGE_HW_VIDEO_ENCODER = 0x00010000,

    /* implementation-specific private usage flags */
    GRALLOC_USAGE_PRIVATE_0 = 0x10000000,
    GRALLOC_USAGE_PRIVATE_1 = 0x20000000,
    GRALLOC_USAGE_PRIVATE_2 = 0x40000000,
    GRALLOC_USAGE_PRIVATE_3 = 0x80000000,
    GRALLOC_USAGE_PRIVATE_MASK = 0xF0000000,
};

/* Copied from GraphicBuffer.h */
enum {
	USAGE_SW_READ_NEVER     = GRALLOC_USAGE_SW_READ_NEVER,
	USAGE_SW_READ_RARELY    = GRALLOC_USAGE_SW_READ_RARELY,
	USAGE_SW_READ_OFTEN     = GRALLOC_USAGE_SW_READ_OFTEN,
	USAGE_SW_READ_MASK      = GRALLOC_USAGE_SW_READ_MASK,
 
	USAGE_SW_WRITE_NEVER    = GRALLOC_USAGE_SW_WRITE_NEVER,
	USAGE_SW_WRITE_RARELY   = GRALLOC_USAGE_SW_WRITE_RARELY,
	USAGE_SW_WRITE_OFTEN    = GRALLOC_USAGE_SW_WRITE_OFTEN,
	USAGE_SW_WRITE_MASK     = GRALLOC_USAGE_SW_WRITE_MASK,

	USAGE_SOFTWARE_MASK     = USAGE_SW_READ_MASK|USAGE_SW_WRITE_MASK,

	USAGE_PROTECTED         = GRALLOC_USAGE_PROTECTED,

	USAGE_HW_TEXTURE        = GRALLOC_USAGE_HW_TEXTURE,
	USAGE_HW_RENDER         = GRALLOC_USAGE_HW_RENDER,
	USAGE_HW_2D             = GRALLOC_USAGE_HW_2D,
	USAGE_HW_COMPOSER       = GRALLOC_USAGE_HW_COMPOSER,
	USAGE_HW_VIDEO_ENCODER  = GRALLOC_USAGE_HW_VIDEO_ENCODER,
	USAGE_HW_MASK           = GRALLOC_USAGE_HW_MASK
};

#define ANativeWindowBuffer void
#define native_handle_t void

void *agbw_new(void);
void *agbw_new_wh(uint32_t w, uint32_t h, uint32_t format, uint32_t usage);
void *agbw_new_from_window(ANativeWindowBuffer *buffer, bool keep_ownership);
void *agbw_new_from_handle(uint32_t w, uint32_t h, uint32_t format,
		uint32_t usage, uint32_t stride, native_handle_t *handle,
		bool keep_ownership);

void agbw_free(void *handle);

int agbw_init_check(void *handle);

int agbw_reallocate(void *handle, uint32_t w, uint32_t h,
		uint32_t f, uint32_t usage);

int agbw_lock(void *handle, uint32_t usage, void **vaddr);
int agbw_lock_surface(void *handle, EGLSurface *surface,
		uint32_t usage);
int agbw_unlock(void *handle);

ANativeWindowBuffer * agbw_get_native_buffer(void *handle);

void agbw_set_index(void *handle, int index);
int agbw_get_index(void *handle);

void agbw_dump_allocations_to_system_log(void *handle);

#ifdef __cplusplus /* If this is a C++ compiler, end C linkage */
}
#endif

#endif
