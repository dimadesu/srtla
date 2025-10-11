/*
 * android_compat.h - Android compatibility layer for SRTLA
 * 
 * Minimal compatibility macros to make SRTLA work on Android
 * while preserving all original functionality
 */

#ifndef ANDROID_COMPAT_H
#define ANDROID_COMPAT_H

#ifdef ANDROID
#include <android/log.h>

// Redirect standard output to Android logging
#undef printf
#undef fprintf
#define printf(...) __android_log_print(ANDROID_LOG_INFO, "SRTLA", __VA_ARGS__)
#define fprintf(stderr, ...) __android_log_print(ANDROID_LOG_ERROR, "SRTLA", __VA_ARGS__)

// Android doesn't always have access to /dev/urandom in the same way
// We'll handle this in the patched functions
#endif // ANDROID

#endif // ANDROID_COMPAT_H