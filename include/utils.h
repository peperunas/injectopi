#pragma once
#include <Windows.h>

#if DBG
#define DBG_INFO(_x_)                                                          \
  do {                                                                         \
    printf("\t[*] ");                                                          \
    printf _x_;                                                                \
  } while (0)
#define DBG_WARN(_x_)                                                          \
  do {                                                                         \
    printf("[!] ");                                                            \
    printf _x_;                                                                \
  } while (0)
#define DBG_ERROR(_x_)                                                         \
  do {                                                                         \
    printf("[-] ");                                                            \
    printf _x_;                                                                \
  } while (0)
#define DBG_SUCC(_x_)                                                          \
  do {                                                                         \
    printf("[+] ");                                                            \
    printf _x_;                                                                \
  } while (0)
#else
#define DBG_INFO(_x_)
#define DBG_WARN(_x_)
#define DBG_ERROR(_x_)
#define DBG_SUCC(_x_)
#endif

#if DBG
#define WDBG_INFO(_x_)                                                         \
  do {                                                                         \
    wprintf(L"\t[*] ");                                                        \
    wprintf _x_;                                                               \
  } while (0)
#define WDBG_WARN(_x_)                                                         \
  do {                                                                         \
    wprintf(L"[!] ");                                                          \
    wprintf _x_;                                                               \
  } while (0)
#define WDBG_ERROR(_x_)                                                        \
  do {                                                                         \
    wprintf(L"[-] ");                                                          \
    wprintf _x_;                                                               \
  } while (0)
#define WDBG_SUCC(_x_)                                                         \
  do {                                                                         \
    wprintf(L"[+] ");                                                          \
    wprintf _x_;                                                               \
  } while (0)
#else
#define WDBG_INFO(_x_)
#define WDBG_WARN(_x_)
#define WDBG_ERROR(_x_)
#define WDBG_SUCC(_x_)
#endif

typedef struct _BASE_RELOCATION_ENTRY {
  WORD Offset : 12;
  WORD Type : 4;
} BASE_RELOCATION_ENTRY;

// FUNCTIONS

/**
 * @brief      Gets the optional header.
 *
 * @param      read_proc  The read proc
 *
 * @return     The optional header.
 */
extern "C" IMAGE_OPTIONAL_HEADER32 GetOptHdr(unsigned char *read_proc);