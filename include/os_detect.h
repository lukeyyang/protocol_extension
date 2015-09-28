#ifndef OS_DETECT_H
#define OS_DETECT_H

#ifdef __APPLE__
  #include "TargetConditionals.h"
  #if TARGET_OS_MAC
    #define THIS_IS_OS_X
  #endif
#elif __linux
  #define THIS_IS_LINUX
#endif


#endif
