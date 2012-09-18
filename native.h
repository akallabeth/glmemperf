/**
 * OpenGL ES 2.0 memory performance estimator
 * Copyright (C) 2010 Nokia
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * \author Sami Kyöstilä <sami.kyostila@nokia.com>
 *
 * Native windowing
 */
#include <EGL/egl.h>

#if defined(__cplusplus)
extern "C" {
#endif

/**
 *  Create a native display
 */
EGLBoolean nativeCreateDisplay(EGLNativeDisplayType *pNativeDisplay);

/**
 *  Destroy a native display
 */
void nativeDestroyDisplay(EGLNativeDisplayType nativeDisplay);

/**
 *  Create a native window
 *
 *  @param nativeDisplay                Native display handle
 *  @param dpy                          EGL display handle
 *  @param config                       Configuration to be used with the window
 *  @param title                        Window title
 *  @param width                        Window width in pixels
 *  @param height                       Window height in pixels
 *  @param nativeWindow                 Output: new window handle
 */
EGLBoolean nativeCreateWindow(EGLNativeDisplayType nativeDisplay, EGLDisplay dpy,
                              EGLConfig config, const char *title, int width, 
                              int height, EGLNativeWindowType *nativeWindow);

/**
 *  Destroy a native window
 *
 *  @param nativeDisplay                Native display handle
 *  @param nativeWindow                 Window to destroy
 */
void nativeDestroyWindow(EGLNativeDisplayType nativeDisplay, EGLNativeWindowType nativeWindow);

/**
 *  Check that a native window is suitable for performance measurement
 *  purposes. For example, a window which is drawn through composition may have
 *  a performance overhead compared to a direct rendered window.
 *
 *  @param nativeDisplay                Native display handle
 *  @param nativeWindow                 Window to verify
 */
EGLBoolean nativeVerifyWindow(EGLNativeDisplayType nativeDisplay,
                              EGLNativeWindowType nativeWindow);

/**
 *  Create a native pixmap
 *
 *  @param nativeDisplay                Native display handle
 *  @param dpy                          EGL display handle
 *  @param config                       Configuration to be used with the pixmap
 *  @param width                        Pixmap width in pixels
 *  @param height                       Pixmap height in pixels
 *  @param nativePixmap                 Output: new pixmap handle
 */
EGLBoolean nativeCreatePixmap(EGLNativeDisplayType nativeDisplay,
                              EGLDisplay dpy, EGLConfig config,
                              int width, int height, EGLNativePixmapType *nativePixmap);

/**
 *  Destroy a native pixmap
 */
void nativeDestroyPixmap(EGLNativeDisplayType nativeDisplay, EGLNativePixmapType nativePixmap);

void nativeGetScreenSize(EGLNativeDisplayType nativeDisplay, int* width, int* height);

#if defined(__cplusplus)
}
#endif
