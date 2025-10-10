# Android patches for SRTLA

This branch contains minimal Android compatibility patches for the SRTLA sender.

## Changes from upstream:

1. **android_compat.h** - Android compatibility macros
2. **srtla_send.c** - Add JNI entry point and Android support
3. **Makefile** - Add Android build targets

## Usage:

```c
// JNI function to start SRTLA
int srtla_start_android(const char* listen_port, const char* srtla_host, 
                       const char* srtla_port, const char* ips_file);
```

Original main() function preserved for desktop builds.