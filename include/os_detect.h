#ifndef OS_DETECT_H
#define OS_DETECT_H

#ifdef _WIN32
  #define THIS_IS_WINDOWS_32
  #ifdef _WIN64
    #define THIS_IS_WINDOWS_64
  #endif
#elif __APPLE__
  #include "TargetConditionals.h"
  #if TARGET_IPHONE_SIMULATOR
    #define THIS_IS_IOS_SIMULATOR
  #elif TARGET_OS_IPHONE
    #define THIS_IS_IOS
  #elif TARGET_OS_MAC
    #define THIS_IS_OS_X
  #else
    #error "Unknown Apple OS"
  #endif
#elif __CYGWIN__
  #define THIS_IS_CYGWIN
#elif __linux__
  #define THIS_IS_LINUX
#elif __unix__
  #define THIS_IS_UNIX
#elif defined(_POSIX_VERSION)
  #define THIS_IS_POSIX
#else
  #error "Unknown OS"
#endif



#endif
