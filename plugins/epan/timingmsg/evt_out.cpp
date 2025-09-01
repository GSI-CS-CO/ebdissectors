
#define __STDC_FORMAT_MACROS
#define __STDC_CONSTANT_MACROS

#include <iostream>
#include <iomanip>

#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include "CommonFunctions.h"
#include "evt_out.h"

using namespace std;
using namespace saftlib;

#ifdef __cplusplus
extern "C" {
#endif

// Inside this "extern C" block, I can implement functions in C++, which will externally 
//   appear as C functions (which means that the function IDs will be their names, unlike
//   the regular C++ behavior, which allows defining multiple functions with the same name
//   (overloading) and hence uses function signature hashing to enforce unique IDs),


// this will be called, in case we are snooping for events
void createSnoopString(char* buf, uint buflen, uint32_t pmode, uint64_t id, uint64_t param, uint64_t deadline, uint64_t captured, uint16_t flags)
{
  saftlib::Time deadlineT = makeTimeTAI(deadline);
  uint64_t ts;
  UTC_to_TAI(captured, TAI_is_UTCleap(deadline), &ts);
  saftlib::Time capturedT = makeTimeTAI(ts);

  std::string s = "tDeadline: ";
  s += tr_formatDate(deadlineT, pmode);
  s += tr_formatDate(capturedT, pmode);
  s += tr_formatActionEvent(id, pmode);
  s += tr_formatActionParam(param, 0xFFFFFFFF, pmode);


  if ((capturedT - deadlineT) < -5000000)   flags |= 1<<0; // late if diff < -5ms
  if ((capturedT - deadlineT) > 4294967296) flags |= 2<<0; // early if diff > 4s
  s += tr_formatActionFlags(flags, capturedT - deadlineT - 4096, pmode);
  s += '\n';
  if (s.size() < buflen) { strcpy(buf, s.c_str());}
} // on_action


#ifdef __cplusplus
}
#endif