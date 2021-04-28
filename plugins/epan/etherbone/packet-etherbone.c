#include "config.h"
#include "packet-etherbone.h"

#include <stdio.h>
#include <epan/packet.h>

proto_tree* addEbRecord(proto_tree *root _U_, tvbuff_t *tvb, gint *pOffs, const gint adrSelBit, const gint datSelBit, const char * name ) {
    
    //calculate alignments. Possibly better placed in the caller function because its the same for alle records in a packet, but that'd inflate the func sig big time.
    const gint adrWidth = 1 << adrSelBit; 
    const gint datWidth = 1 << datSelBit;
    const gint tmpAlignment  = (adrWidth > datWidth ? adrWidth : datWidth); //Alignment is max of adr and data width ..
    const gint alignment = tmpAlignment > 2 ? tmpAlignment : 2; // ... but at least 2 bytes
    const gint rec_alignment = (alignment > 4 ? alignment : 4); // record alignment is Alignment or at least 4 byte

    proto_tree *retTree, *wrTree, *rdTree;

    //get read and write op count beforehand 
    guint8 wrcnt=tvb_get_guint8(tvb, *pOffs + 2); 
    guint8 rdcnt=tvb_get_guint8(tvb, *pOffs + 3);
    

    //If 64b (8B) alignment is selected, the buffer offset we were given must be padded to alignment. -> Add 4 to address if alignment is 8B
    if (alignment == 8)  *pOffs += 4;

    //make local offsset copy
    gint lOffs = *pOffs;    

    //calculate total record length. if there are write/read operations, the first 32b field is the adress/return address
    gint len = rec_alignment + (wrcnt ? (1+wrcnt)*alignment : 0) + (rdcnt ? (1+rdcnt)*alignment : 0);

    //create the base tree for this record to return later
    retTree = proto_tree_add_subtree(root, tvb, *pOffs, len, ebrt_eb, NULL, name);
    proto_tree_add_bitmask(retTree , tvb, *pOffs+0, recf_hdr, ebrec_eb, rechdrbits, ENC_BIG_ENDIAN); //add header
    lOffs += rec_alignment;

    if(wrcnt) {
        //if there are write ops, create write subrtee, add base address and then handle the write operations
        wrTree = proto_tree_add_subtree(retTree, tvb, lOffs, (1+wrcnt)*alignment, ebrt_eb, NULL, "Writes");
        proto_tree_add_item(wrTree, *recWrAdrWidth[adrSelBit], tvb, lOffs+alignment-adrWidth, adrWidth, ENC_BIG_ENDIAN);
        lOffs += alignment;
        
        for (gint i = 0; i < wrcnt; i++){
            proto_item *pi = proto_tree_add_item(wrTree, *recDataWidth[datSelBit], tvb, lOffs+alignment-datWidth, datWidth, ENC_BIG_ENDIAN);
            proto_item_prepend_text(pi, "%3u   ", i);
            lOffs += alignment;
        }     
    }

    if(rdcnt) {
        //if there are read ops, create read subrtee, add readback address and then handle the read operations
        rdTree = proto_tree_add_subtree(retTree, tvb, lOffs, (1+rdcnt)*alignment, ebrt_eb, NULL, "Reads");
        proto_tree_add_item(rdTree, *recRdAdrWidth[adrSelBit], tvb, lOffs+alignment-adrWidth, adrWidth, ENC_BIG_ENDIAN);

        lOffs += alignment;
        for (gint i = 0; i < rdcnt; i++){
            proto_item *pi = proto_tree_add_item(rdTree, *recDataWidth[datSelBit], tvb, lOffs+alignment-datWidth, datWidth, ENC_BIG_ENDIAN);
            proto_item_prepend_text(pi, "%3u   ", i);
            lOffs += alignment;
        } 
    }
   
   //adjust the offset we were given by the record length we just dissected
    *pOffs += len;
    return retTree; //return the tree for this record
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
    //if packet wasnt a probe, we'll need this info later to get the selected widths for record dissection
    guint8 adrWidth = tvb_get_guint8(tvb, offset) >> 4;
    guint8 datWidth = tvb_get_guint8(tvb, offset) & 0x0f;
    offset += 1;
    
    //////////////////////// EB HEADER end /////////////////////////

    //////////////////////// EB RECORD(s) start /////////////////////////
    if (packet_type == 0) {
        //if the set bitwidth for address or data is 0, this EB data packet is bad and cannot be further decoded 
        if (adrWidth == 0 || datWidth == 0) return 0;

        proto_tree *rectree = proto_tree_add_subtree(eb_tree, tvb, offset, -1, ebrt_eb, NULL, "Records");

        char buf[30];
        gint i = 0;
        while (tvb_captured_length_remaining(tvb, offset)) {
            //add running record number and write/read op count to descriptor
            sprintf(buf, "#%03u (W%3u R%3u)", i++, tvb_get_guint8(tvb, offset + 2), tvb_get_guint8(tvb, offset + 3) );
            //dissect the record
            addEbRecord(rectree, tvb, (gint*)&offset, log2_8bit(adrWidth), log2_8bit(datWidth), buf);
        }
    }
    //////////////////////// EB RECORD(s) end /////////////////////////

    return tvb_captured_length(tvb);
}

//the specialized version. 8 bit check, val != 0
guint8 log2_8bit(guint8 val) {
    for (guint8 i = 0; i < 8; i++) {
        if (val & (1<<i)) return i;
    }
    return -1;
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
                { "Data", "ebrec.dat.data8",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_data16,
                { "Data", "ebrec.dat.data16",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_data32,
                { "Data", "ebrec.dat.data32",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL}
            },

            {&recf_data64,
                { "Data", "ebrec.dat.data64",
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