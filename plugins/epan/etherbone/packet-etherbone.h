#ifndef _PACKET_ETHERBONE_H
#define _PACKET_ETHERBONE_H

#include "config.h"

#include <epan/packet.h>

#define etherbone_PORT 0XEBD0


static int proto_etherbone = -1;
static int hf_eb_magic = -1;
static int hf_eb_hdr = -1;
static int hf_eb_probeflag = -1;
static int hf_eb_presponseflag = -1;
static int hf_eb_noreadflag = -1;
static int hf_eb_version = -1;
static int hf_wb_hdr = -1;
static int hf_wb_datwidth = -1;
static int hf_wb_adrwidth = -1;
static int hf_probe_id = -1;
static int hf_padding = -1;


static gint ett_eb = -1;
static gint ebrt_eb = -1;
static gint ebrec_eb = -1;


static int recf_hdr = -1;
static int recf_bcaflag = -1;
static int recf_rcaflag = -1;
static int recf_rffflag = -1;
static int recf_cycflag = -1;
static int recf_wcaflag = -1;
static int recf_wffflag = -1;
static int recf_be = -1;


static int recf_wrcnt = -1;
static int recf_rdcnt = -1;

static int recf_wrbaseadr8 = -1;
static int recf_wrbaseadr16 = -1;
static int recf_wrbaseadr32 = -1;
static int recf_wrbaseadr64 = -1;
static int recf_data8 = -1;
static int recf_data16 = -1;
static int recf_data32 = -1;
static int recf_data64 = -1;

static int recf_rdbaseadr8 = -1;
static int recf_rdbaseadr16 = -1;
static int recf_rdbaseadr32 = -1;
static int recf_rdbaseadr64 = -1;

static int recf_padding = -1;


#define EB_HDR_PROBE_FLAG       0x01
#define EB_HDR_PRESPONSE_FLAG   0x02
#define EB_HDR_NOREAD_FLAG      0x04
#define EB_HDR_VERSION          0xF0
#define WB_HDR_ADRW             0xF0
#define WB_HDR_DATW             0x0F
#define EB_REC_HDR_LEN          4
#define EB_REC_HDR_BCA_FLAG     0x80000000
#define EB_REC_HDR_RCA_FLAG     0x40000000
#define EB_REC_HDR_RFF_FLAG     0x20000000
#define EB_REC_HDR_CYC_FLAG     0x08000000
#define EB_REC_HDR_WCA_FLAG     0x04000000
#define EB_REC_HDR_WFF_FLAG     0x02000000
#define EB_REC_HDR_BE_FLAG      0x00FF0000
#define EB_REC_HDR_WRCNT        0x0000FF00
#define EB_REC_HDR_RDCNT        0x000000FF

 
    static int* const rechdrbits[] = {
        &recf_bcaflag,
        &recf_rcaflag,
        &recf_rffflag,
        &recf_cycflag,
        &recf_wcaflag,
        &recf_wffflag,
        &recf_be,
        &recf_wrcnt,
        &recf_rdcnt,
        NULL
    };

static const value_string packettypenames[] = {
{ 1, "Probe request" },
{ 2, "Probe response" },
{ 0, "Data" }
};

static const value_string bitwidthnames[] = {
{ 0x0, "None" },
{ 0x1, "8" },
{ 0x2, "16" },
{ 0x3, "16/8" },
{ 0x4, "32" },
{ 0x5, "32/8" },
{ 0x6, "32/16" },
{ 0x7, "32/16/8" },
{ 0x8, "64" },
{ 0x9, "64/8" },
{ 0xa, "64/16" },
{ 0xb, "64/16/8" },
{ 0xc, "64/32" },
{ 0xd, "64/32/8" },
{ 0xe, "64/32/16" },
{ 0xf, "64/32/16/8" }
};

static int* const recWrAdrWidth[] = {
        &recf_wrbaseadr8,
        &recf_wrbaseadr16,
        &recf_wrbaseadr32,
        &recf_wrbaseadr64,
        NULL
    };
static int* const recDataWidth[] = {
        &recf_data8,
        &recf_data16,
        &recf_data32,
        &recf_data64,
        NULL
    };


static int* const recRdAdrWidth[] = {
        &recf_rdbaseadr8,
        &recf_rdbaseadr16,
        &recf_rdbaseadr32,
        &recf_rdbaseadr64,
        NULL
    };

guint8 log2_8bit(guint8 val);

static int
dissect_etherbone(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

void
proto_reg_handoff_etherbone(void);



#endif