#include "config.h"
#include "packet-etherbone.h"

#include <stdio.h>
#include <epan/packet.h>

proto_tree* addEbRecord(proto_tree *root _U_, tvbuff_t *tvb, gint *pOffs, const gint alignment, const gint rec_alignment, const char * name ) {
    
    proto_tree *retTree, *wrTree, *rdTree;
    guint8 wrcnt=tvb_get_guint8(tvb, *pOffs + 2);
    guint8 rdcnt=tvb_get_guint8(tvb, *pOffs + 3);
    gint lOffs = *pOffs;

    gint len = EB_REC_HDR_LEN + (wrcnt ? (1+wrcnt+rec_alignment)*alignment : 0) + (rdcnt ? (1+rdcnt)*alignment : 0); //if there are write/read operations, the first 32b field is the adress/return address
    
    retTree = proto_tree_add_subtree(root, tvb, *pOffs, len, ebrt_eb, NULL, name);
   
    proto_tree_add_bitmask(retTree , tvb, *pOffs+0, recf_hdr, ebrec_eb, rechdrbits, ENC_BIG_ENDIAN);
    lOffs += alignment;

    if(wrcnt) {
        wrTree = proto_tree_add_subtree(retTree, tvb, lOffs, (1+wrcnt)*alignment, ebrt_eb, NULL, "Writes");
        proto_tree_add_item(wrTree, *recWrAdrWidth[2], tvb, lOffs, alignment, ENC_BIG_ENDIAN);
        lOffs += alignment;
        for (gint i = 0; i < wrcnt; i++){
            proto_item *pi = proto_tree_add_item(wrTree, *recDataWidth[2], tvb, lOffs, alignment, ENC_BIG_ENDIAN);
            proto_item_prepend_text(pi, "%3u   ", i);
            lOffs += alignment;
        }       
    }

    if(rdcnt) {
        rdTree = proto_tree_add_subtree(retTree, tvb, lOffs, (1+rdcnt)*alignment, ebrt_eb, NULL, "Reads");
        proto_tree_add_item(rdTree, *recRdAdrWidth[2], tvb, lOffs, alignment, ENC_BIG_ENDIAN);
        lOffs += alignment;
        for (gint i = 0; i < rdcnt; i++){
            proto_item *pi = proto_tree_add_item(rdTree, *recDataWidth[2], tvb, lOffs, alignment, ENC_BIG_ENDIAN);
            proto_item_prepend_text(pi, "%3u   ", i);
            lOffs += alignment;
        } 
    }
   
  /*
    for (gint i = 0; i < wrcnt; i++){

    }
    */
    //if(rdcnt) proto_tree *retTree = proto_tree_add_subtree(root, tvb, *pOffs+alignment, *pOffs+(1+rdcnt)*alignment, ebrt_eb, NULL, "Writes");

    *pOffs += len;
    return retTree;    
}



static int
dissect_etherbone(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    
    //////////////////////// EB HEADER start /////////////////////////
    gint offset = 0;
    guint16 magic_word = tvb_get_guint16(tvb, 0, ENC_BIG_ENDIAN); //Header Magic Word


    guint8 packet_type = tvb_get_guint8(tvb, 2) & (EB_HDR_PROBE_FLAG | EB_HDR_PRESPONSE_FLAG); //Header Probe Flags


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EB");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    if (magic_word != 0x4e6f) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bad EB Magic word 0x%2x", magic_word);
        return -1;
    }    
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
    val_to_str(packet_type, packettypenames, "Type unknown (0x%2x)"));


    proto_item *ti = proto_tree_add_item(tree, proto_etherbone, tvb, 0, -1, ENC_NA);
    proto_tree *eb_tree = proto_item_add_subtree(ti, ett_eb);
    proto_tree_add_item(eb_tree, hf_eb_magic, tvb, 0, 2, ENC_BIG_ENDIAN);
    offset += 2;
    
    static int* const ebhdrbits[] = {
        &hf_eb_version,
        &hf_eb_noreadflag,
        &hf_eb_presponseflag,
        &hf_eb_probeflag,
        NULL
    };

    proto_tree_add_bitmask(eb_tree, tvb, offset, hf_eb_hdr, ett_eb, ebhdrbits, ENC_BIG_ENDIAN);
    offset += 1;

    static int* const wbhdrbits[] = {
        &hf_wb_adrwidth,
        &hf_wb_datwidth,
        NULL
    };

    proto_tree_add_bitmask(eb_tree, tvb, offset, hf_wb_hdr, ett_eb, wbhdrbits, ENC_BIG_ENDIAN);
    offset += 1;

/*
    //FIXME: EB spec says we pad to 64b alignment after header to allow for probe identifiers, but it seems we don't.
    //What's it gonna be? if we decide to use it, uncomment this code block.
  
    proto_tree_add_item(eb_tree, (packet_type !=0 ? hf_probe_id : hf_padding) , tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
*/
    
    //////////////////////// EB HEADER end /////////////////////////

    //////////////////////// EB RECORD(s) start /////////////////////////
    if (packet_type == 0) {

        proto_tree *rectree = proto_tree_add_subtree(eb_tree, tvb, offset, -1, ebrt_eb, NULL, "Records");
        char buf[20];
        gint i = 0;
        while (tvb_captured_length_remaining(tvb, offset)) {
            sprintf(buf, "Record %3u", i++ );
            addEbRecord(rectree, tvb, (gint*)&offset, 4, 0, buf);
        }
    }
    //while(tvb_captured_length_remaining(tvb, offset)) {
        
    //}

    //////////////////////// EB RECORD(s) end /////////////////////////

    return tvb_captured_length(tvb);
}





void
proto_reg_handoff_etherbone(void)
{
    static dissector_handle_t etherbone_handle;

    etherbone_handle = create_dissector_handle(dissect_etherbone, proto_etherbone);
    dissector_add_uint("udp.port", etherbone_PORT, etherbone_handle);
}



void
proto_register_etherbone(void)
{
    static hf_register_info hf[] = {
         
            {&hf_eb_magic,
                { "Magic", "etherbone.magic",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&hf_eb_hdr,
                { "EB Info", "etherbone.ebhdr",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },


            {&hf_eb_probeflag,
                { "Probe request", "etherbone.ebhdr.probe",
                FT_BOOLEAN, 8,
                NULL, EB_HDR_PROBE_FLAG,
                NULL, HFILL}
            },

            {&hf_eb_presponseflag,
                { "Probe response", "etherbone.ebhdr.presponse",
                FT_BOOLEAN, 8,
                NULL, EB_HDR_PRESPONSE_FLAG,
                NULL, HFILL}
            },

            {&hf_eb_noreadflag,
                { "No reply", "etherbone.ebflags.noread",
                FT_BOOLEAN, 8,
                NULL, EB_HDR_NOREAD_FLAG,
                NULL, HFILL}
            },

            {&hf_eb_version,
                { "Protocol Version", "etherbone.ebflags.version",
                FT_UINT8, BASE_DEC,
                NULL, EB_HDR_VERSION,
                NULL, HFILL}
            },

            {&hf_wb_hdr,
                { "WB bitwidth", "etherbone.wbhdr",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&hf_wb_adrwidth,
                { "Adr", "etherbone.wbhdr.adrwidth",
                FT_UINT8, BASE_HEX,
                VALS(bitwidthnames), WB_HDR_ADRW,
                NULL, HFILL}
            }, 

            {&hf_wb_datwidth,
                { "Data", "etherbone.wbhdr.datwidth",
                FT_UINT8, BASE_HEX,
                VALS(bitwidthnames), WB_HDR_DATW,
                NULL, HFILL}
            },

            //in eb spec, but apparently not implemented
            {&hf_probe_id,
                { "Probe ID", "etherbone.probeid",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            //in eb spec, but apparently not implemented
            {&hf_padding,
                { "Padding to 64b alignment", "etherbone.padding",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            }      
        
    };


    static hf_register_info recf[] = {
         
             {&recf_hdr,
                { "Record Header", "ebrec.hdr",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_bcaflag,
                { "ReplyToCfgSpace", "ebrec.hdr.bca",
                FT_BOOLEAN, 8,
                NULL, EB_REC_HDR_BCA_FLAG,
                NULL, HFILL}
            },

            {&recf_rcaflag,
                { "ReadFromCfgSpace", "ebrec.hdr.rca",
                FT_BOOLEAN, 8,
                NULL, EB_REC_HDR_RCA_FLAG,
                NULL, HFILL}
            },

            {&recf_rffflag,
                { "ReadFIFO", "ebrec.hdr.rff",
                FT_BOOLEAN, 8,
                NULL, EB_REC_HDR_RFF_FLAG,
                NULL, HFILL}
            },

            {&recf_cycflag,
                { "DropCycle", "ebrec.hdr.cyc",
                FT_BOOLEAN, 8,
                NULL, EB_REC_HDR_CYC_FLAG,
                NULL, HFILL}
            },

            {&recf_wcaflag,
                { "WriteToCfgSpace", "ebrec.hdr.wca",
                FT_BOOLEAN, 8,
                NULL, EB_REC_HDR_WCA_FLAG,
                NULL, HFILL}
            },

            {&recf_wffflag,
                { "WriteFIFO", "ebrec.hdr.wff",
                FT_BOOLEAN, 8,
                NULL, EB_REC_HDR_WFF_FLAG,
                NULL, HFILL}
            },

            {&recf_be,
                { "Byteenable", "ebrec.hdr.be",
                FT_UINT8, BASE_HEX,
                NULL, EB_REC_HDR_BE_FLAG,
                NULL, HFILL}
            },

            {&recf_wrcnt,
                { "Writes", "ebrec.cnt.wr",
                FT_UINT8, BASE_DEC,
                NULL, EB_REC_HDR_WRCNT,
                NULL, HFILL}
            },

            {&recf_rdcnt,
                { "Reads", "ebrec.cnt.rd",
                FT_UINT8, BASE_DEC,
                NULL, EB_REC_HDR_RDCNT,
                NULL, HFILL}
            },

            {&recf_wrbaseadr8,
                { "Write Base Adress", "ebrec.wr.baseadr8",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_wrbaseadr16,
                { "Write Base Adress", "ebrec.wr.baseadr16",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_wrbaseadr32,
                { "Write Base Adress", "ebrec.wr.baseadr32",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_wrbaseadr64,
                { "Write Base Adress", "ebrec.wr.baseadr64",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_data8,
                { "Data", "ebrec.wr.data8",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_data16,
                { "Data", "ebrec.wr.data16",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_data32,
                { "Data", "ebrec.wr.data32",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_data64,
                { "Data", "ebrec.wr.data64",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_rdbaseadr8,
                { "Readback Adress", "ebrec.rd.baseadr8",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_rdbaseadr16,
                { "Readback Adress", "ebrec.rd.baseadr16",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_rdbaseadr32,
                { "Readback Adress", "ebrec.rd.baseadr32",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_rdbaseadr64,
                { "Readback Adress", "ebrec.rd.baseadr64",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            //in eb spec, but apparently not implemented
            {&recf_padding,
                { "Padding to 64b alignment", "ebrec.padding",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            }      
        
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_eb
    };

    static gint *ebrt[] = {
        &ebrt_eb
    };

    static gint *ebrec[] = {
        &ebrec_eb
    };



    proto_etherbone = proto_register_protocol (
        "Etherbone Protocol", /* name       */
        "etherbone",      /* short name */
        "eb"       /* abbrev     */
    );

    proto_register_field_array(proto_etherbone, hf, array_length(hf));
    proto_register_field_array(proto_etherbone, recf, array_length(recf));
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_subtree_array(ebrt, array_length(ebrt));
    proto_register_subtree_array(ebrec, array_length(ebrec));
}