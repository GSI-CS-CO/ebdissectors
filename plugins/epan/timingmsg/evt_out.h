#ifndef _EVT_OUT_H_ 
#define _EVT_OUT_H_

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif
 
void createSnoopString(char* buf, uint buflen, uint32_t pmode, uint64_t id, uint64_t param, uint64_t deadline, uint64_t captured, uint16_t flags);

#ifdef __cplusplus
}
#endif


#endif



