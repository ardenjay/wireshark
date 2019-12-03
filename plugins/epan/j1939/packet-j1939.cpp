extern "C" {

#include "config.h"

#include <inttypes.h>
#include <epan/packet.h>
#include <epan/address_types.h>
#include <epan/to_str.h>

#include "packet-socketcan.h"

// For BAM reassemble
#include <epan/reassemble.h>

void proto_register_j1939(void);
void proto_reg_handoff_j1939(void);
}

#include <Diagnosis/Frames/DM1.h>
#include <FMS/TellTale/FMS1Frame.h>
#include <GenericFrame.h>
#include <J1939DataBase.h>
#include <J1939Factory.h>
#include <J1939Frame.h>
#include <SPN/SPNNumeric.h>
#include <SPN/SPNStatus.h>
#include <SPN/SPNString.h>
#include <Transport/BAM/BamReassembler.h>
#include <iostream>

#ifndef DATABASE_PATH
#define DATABASE_PATH "/etc/j1939/frames.json"
#endif

using namespace std;
using namespace J1939;

static int dissect_J1939(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				  void *data);
void dissect_generic_frame(tvbuff_t *tvb, proto_tree *j1939_tree,
						   proto_item *ti, GenericFrame *genFrame);
void dissect_fms1_frame(tvbuff_t *tvb, proto_tree *j1939_tree, proto_item *ti,
						const FMS1Frame *fms1Frame);
void dissect_dm1_frame(tvbuff_t *tvb, proto_tree *j1939_tree, proto_item *ti,
					   const DM1 *dm1Frame);

static int hf_j1939_can_id = -1;
static int hf_j1939_priority = -1;
static int hf_j1939_pgn = -1;
static int hf_j1939_data_page = -1;
static int hf_j1939_extended_data_page = -1;
static int hf_j1939_pdu_format = -1;
static int hf_j1939_pdu_specific = -1;
static int hf_j1939_src_addr = -1;
static int hf_j1939_dst_addr = -1;
static int hf_j1939_group_extension = -1;
static int hf_j1939_data = -1;

static int hf_j1939_frame = -1;
static int hf_j1939_spn = -1;
static int hf_j1939_dtc = -1;
static int hf_j1939_fmi = -1;
static int hf_j1939_oc = -1;

static int hf_j1939_blockId = -1;

static int proto_j1939 = -1;
static gint ett_j1939 = -1;
static gint ett_j1939_can = -1;
static gint ett_j1939_dtc = -1;
static gint ett_j1939_message = -1;

static gint ett_bam_fragment = -1;
static gint ett_bam_fragments = -1;
static gint hf_bam_fragments = -1;
static gint hf_bam_fragment = -1;
static gint hf_bam_fragment_overlap = -1;
static gint hf_bam_fragment_overlap_conflict = -1;
static gint hf_bam_fragment_multiple_tails = -1;
static gint hf_bam_fragment_too_long_fragment = -1;
static gint hf_bam_fragment_error = -1;
static gint hf_bam_fragment_count = -1;
static gint hf_bam_reassembled_in = -1;
static gint hf_bam_reassembled_length = -1;
static gint hf_bam_reassembled_data = -1;

static dissector_handle_t j1939_handle;

static reassembly_table bam_reassembly_table;

static int j1939_address_type = -1;

static const fragment_items bam_frag_items = {
	&ett_bam_fragment,
	&ett_bam_fragments,
	&hf_bam_fragments,
	&hf_bam_fragment,
	&hf_bam_fragment_overlap,
	&hf_bam_fragment_overlap_conflict,
	&hf_bam_fragment_multiple_tails,
	&hf_bam_fragment_too_long_fragment,
	&hf_bam_fragment_error,
	&hf_bam_fragment_count,
	&hf_bam_reassembled_in,
	&hf_bam_reassembled_length,
	&hf_bam_reassembled_data,
	"BAM fragments"};

static const value_string tts_status[] = {
	{0, "Off"}, {1, "Red"}, {2, "Yellow"}, {3, "Info"}, {7, "Not available"}};

BamReassembler bamReassembler;

/* SPN number, header_field_info.id */
std::map<u32, int> hf_spn_id;
std::map<u32 /*TTS number*/, int /*header_field_info.id*/> ttsNumToHinfoId;

static int J1939_addr_to_str(const address* addr, gchar *buf, int buf_len)
{
    const guint8 *addrdata = (const guint8 *)addr->data;

    guint32_to_str_buf(*addrdata, buf, buf_len);
    return (int)strlen(buf);
}

static int J1939_addr_str_len(const address* addr _U_)
{
    return 11; /* Leaves required space (10 bytes) for uint_to_str_back() */
}

static const char* J1939_col_filter_str(const address* addr _U_, gboolean is_src)
{
    if (is_src)
        return "j1939.src_addr";

    return "j1939.dst_addr";
}

static int J1939_addr_len(void)
{
    return 1;
}

void proto_register_j1939(void)
{
	static hf_register_info hf[] = {
        { &hf_j1939_can_id,
            {"CAN Identifier", "j1939.can_id",
            FT_UINT32, BASE_HEX, NULL, CAN_EFF_MASK, NULL, HFILL }
        },
        { &hf_j1939_priority,
            {"Priority", "j1939.priority",
            FT_UINT32, BASE_DEC, NULL, 0x1C000000, NULL, HFILL }
        },
        { &hf_j1939_pgn,
            {"PGN", "j1939.pgn",
            FT_UINT32, BASE_DEC, NULL, 0x3FFFFFF, NULL, HFILL }
        },
        { &hf_j1939_extended_data_page,
            {"Extended Data Page", "j1939.ex_data_page",
            FT_UINT32, BASE_DEC, NULL, 0x02000000, NULL, HFILL }
        },
        { &hf_j1939_data_page,
            {"Data Page", "j1939.data_page",
            FT_UINT32, BASE_DEC, NULL, 0x01000000, NULL, HFILL }
        },
        { &hf_j1939_pdu_format,
            {"PDU Format", "j1939.pdu_format",
            FT_UINT32, BASE_DEC, NULL, 0x00FF0000, NULL, HFILL }
        },
        { &hf_j1939_pdu_specific,
            {"PDU Specific", "j1939.pdu_specific",
            FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL }
        },
        { &hf_j1939_src_addr,
            {"Source Address", "j1939.src_addr",
            FT_UINT32, BASE_DEC, NULL, 0x000000FF, NULL, HFILL }
        },
        { &hf_j1939_dst_addr,
            {"Destination Address", "j1939.dst_addr",
            FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL }
        },
        { &hf_j1939_group_extension,
            {"Group Extension", "j1939.group_extension",
            FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL }
        },
        { &hf_j1939_data,
            {"Data", "j1939.data",
            FT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0, NULL, HFILL }
        },
		{&hf_j1939_frame,
		 {"Frame", "j1939.frame", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
		  HFILL}},
		{&hf_j1939_spn,
		 {"Spn", "j1939.spn", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
		{&hf_j1939_dtc,
		 {"Diagnosis Trouble Code", "j1939.dtc", FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_j1939_oc,
		 {"Ocurrence Count", "j1939.oc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
		  HFILL}},
		{&hf_j1939_fmi,
		 {"Failure Mode Identifier", "j1939.fmi", FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},
		{&hf_j1939_blockId,
		 {"Block ID", "j1939.fms1.blockId", FT_UINT8, BASE_DEC, NULL, 0x0F,
		  NULL, HFILL}},
		{&hf_bam_fragment_overlap,
		 {"Fragment overlap", "bam.fragment.overlap", FT_BOOLEAN, BASE_NONE,
		  NULL, 0x0, "Fragment overlaps with other fragments", HFILL}},

		{&hf_bam_fragment_overlap_conflict,
		 {"Conflicting data in fragment overlap",
		  "bam.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "Overlapping fragments contained conflicting data", HFILL}},

		{&hf_bam_fragment_multiple_tails,
		 {"Multiple tail fragments found", "bam.fragment.multipletails",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "Several tails were found when defragmenting the packet", HFILL}},

		{&hf_bam_fragment_too_long_fragment,
		 {"Fragment too long", "bam.fragment.toolongfragment", FT_BOOLEAN,
		  BASE_NONE, NULL, 0x0, "Fragment contained data past end of packet",
		  HFILL}},

		{&hf_bam_fragment_error,
		 {"Defragmentation error", "bam.fragment.error", FT_FRAMENUM, BASE_NONE,
		  NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL}},

		{&hf_bam_fragment_count,
		 {"Fragment count", "bam.fragment.count", FT_UINT32, BASE_DEC, NULL,
		  0x0, NULL, HFILL}},

		{&hf_bam_fragment,
		 {"BAM Fragment", "bam.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_bam_fragments,
		 {"BAM Fragments", "bam.fragments", FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

		{&hf_bam_reassembled_in,
		 {"Reassembled BAM in frame", "bam.reassembled_in", FT_FRAMENUM,
		  BASE_NONE, NULL, 0x0, "This BAM packet is reassembled in this frame",
		  HFILL}},

		{&hf_bam_reassembled_length,
		 {"Reassembled BAM length", "bam.reassembled.length", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "The total length of the reassembled payload",
		  HFILL}},
		{&hf_bam_reassembled_data,
		 {"Reassembled BAM data", "bam.reassembled.data", FT_BYTES, BASE_NONE,
		  NULL, 0x0, "The reassembled payload", HFILL}},
	};

	static gint *ett[] = {&ett_j1939,		 &ett_j1939_can,
						  &ett_j1939_dtc,	&ett_j1939_message,
						  &ett_bam_fragment, &ett_bam_fragments};

	reassembly_table_register(&bam_reassembly_table,
							  &addresses_reassembly_table_functions);

	proto_j1939 = proto_register_protocol("J1939 Framework",
										  "j1939framework", "j1939framework");

	proto_register_field_array(proto_j1939, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

    j1939_address_type = address_type_dissector_register("AT_J1939", "J1939 Address", J1939_addr_to_str, J1939_addr_str_len, NULL, J1939_col_filter_str, J1939_addr_len, NULL, NULL);
}

static void spn_header_info()
{
	std::unique_ptr<J1939Frame> frame;
	header_field_info* info;
	std::string abbrev;
	std::set<u32> pgns = J1939Factory::getInstance().getAllRegisteredPGNs();

	for(auto pgn = pgns.begin(); pgn != pgns.end(); ++pgn) {
		frame = J1939Factory::getInstance().getJ1939Frame(*pgn);

		if(!frame->isGenericFrame())
			continue;

		GenericFrame *genFrame = static_cast<GenericFrame *>(frame.get());
		std::set<u32> spnNumbers = genFrame->getSPNNumbers();

		for(auto spnNumber = spnNumbers.begin(); spnNumber != spnNumbers.end(); ++spnNumber) {
			const SPN* spn = genFrame->getSPN(*spnNumber);

			info = (header_field_info*)g_malloc0(sizeof(header_field_info));
			info->id = -1;
			info->ref_type = HF_REF_TYPE_NONE;
			info->same_name_prev_id = -1;
			abbrev = std::string("j1939.spn.") + std::to_string(*spnNumber);

			info->name = g_strdup(spn->getName().c_str());
			info->abbrev = g_strdup(abbrev.c_str());

			switch(spn->getType()) {
			case SPN::SPN_STATUS:
				info->type = FT_UINT8;
				info->display = BASE_DEC;
				break;
			case SPN::SPN_NUMERIC:
				info->type = FT_DOUBLE;
				info->display = BASE_NONE;
				break;
			case SPN::SPN_STRING:
				info->type = FT_STRING;
				info->display = BASE_NONE;
				break;
			default:
				break;
			}

			proto_register_fields_section(proto_j1939, info, 1);
			hf_spn_id[*spnNumber] = info->id;
		}
	}
}

void proto_reg_handoff_j1939(void)
{
	j1939_handle = create_dissector_handle(dissect_J1939, proto_j1939);
	dissector_add_for_decode_as("can.subdissector", j1939_handle);

	if (!J1939Factory::getInstance().registerDatabaseFrames(DATABASE_PATH)) {
		cerr << "Database not found in " << DATABASE_PATH << endl;
		return;
	}

	spn_header_info();
}

static unique_ptr<J1939Frame>
j1939_decode(u32 id, const guint8 *content, u32 len)
{
	unique_ptr<J1939Frame> frame;

	try {
		frame = J1939Factory::getInstance().getJ1939Frame(id, content, len);

		if (!frame) {
			u32 pgn = ((id >> J1939_PGN_OFFSET) & J1939_PGN_MASK);
			cerr << "Frame " << id << "(PGN:" << pgn << ")" <<
				" not identified" << endl;
			return nullptr;
		}
	} catch (J1939DecodeException &e) {
		cerr << "Error decoding frame: " << e.getMessage() << endl;
		return nullptr;
	}
	return frame;
}

static void
add_j1939_tree(tvbuff_t *tvb, proto_tree *tree,
		proto_tree **j1939_tree, proto_tree **can_tree, u32 id)
{
	proto_item *ti, *can_id_item;
	uint len = tvb_reported_length(tvb);

	ti = proto_tree_add_item(tree, proto_j1939, tvb, 0, len, ENC_NA);
	*j1939_tree = proto_item_add_subtree(ti, ett_j1939);

	*can_tree = proto_tree_add_subtree_format(*j1939_tree, tvb, 0, 0,
			ett_j1939_can, NULL, "CAN Identifier: 0x%08x", id);

    can_id_item = proto_tree_add_uint(*can_tree, hf_j1939_can_id, tvb, 0, 0, id);
    proto_item_set_generated(can_id_item);
    ti = proto_tree_add_uint(*can_tree, hf_j1939_priority, tvb, 0, 0, id);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(*can_tree, hf_j1939_extended_data_page, tvb, 0, 0, id);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(*can_tree, hf_j1939_data_page, tvb, 0, 0, id);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(*can_tree, hf_j1939_pdu_format, tvb, 0, 0, id);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(*can_tree, hf_j1939_pdu_specific, tvb, 0, 0, id);
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(*can_tree, hf_j1939_src_addr, tvb, 0, 0, id);
    proto_item_set_generated(ti);
}

static void show_addr(tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *can_tree, u32 id)
{
    guint32 pgn;
    guint8 *src_addr, *dest_addr;
	proto_item *ti;

    /* Set source address */
    src_addr = (guint8*)wmem_alloc(pinfo->pool, 1);
    *src_addr = (guint8)(id & 0xFF);
    set_address(&pinfo->src, j1939_address_type, 1, (const void*)src_addr);

    pgn = (id & 0x3FFFF00) >> 8;

    /* If PF < 240, PS is destination address, last byte of PGN is cleared */
    if (((id & 0xFF0000) >> 16) < 240)
    {
        pgn &= 0x3FF00;

        ti = proto_tree_add_uint(can_tree, hf_j1939_dst_addr, tvb, 0, 0, id);
        proto_item_set_generated(ti);
    }
    else
    {
        ti = proto_tree_add_uint(can_tree, hf_j1939_group_extension, tvb, 0, 0, id);
        proto_item_set_generated(ti);
    }

    /* Fill in "destination" address even if its "broadcast" */
    dest_addr = (guint8*)wmem_alloc(pinfo->pool, 1);
    *dest_addr = (guint8)((id & 0xFF00) >> 8);
    set_address(&pinfo->dst, j1939_address_type, 1, (const void*)dest_addr);
}

static void dissect_J1939_framework(tvbuff_t *tvb, packet_info *pinfo, proto_tree **j1939_tree, u32 id)
{
	proto_item *ti;
	proto_tree *frame_tree;
	guint32 data_length = tvb_reported_length(tvb);
	guint8* content = (guint8 *) wmem_alloc(pinfo->pool, data_length);

	tvb_memcpy(tvb, content, 0, data_length);

	unique_ptr<J1939Frame> frame = j1939_decode(id, content, data_length);
	if (frame == nullptr) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown");
		return;
	}

	/* sets up info field */
	const char *frameName = frame->getName().c_str();
	col_add_fstr(pinfo->cinfo, COL_INFO, "PGN: %d", frame->getPGN());
	col_append_fstr(pinfo->cinfo, COL_INFO, " Frame: %s", frameName);

	ti = proto_tree_add_string(*j1939_tree, hf_j1939_frame, tvb, 0, tvb_reported_length(tvb), frameName);
	frame_tree = proto_item_add_subtree(ti, ett_j1939_message);

	if (frame->isGenericFrame()) {
		GenericFrame *f = (GenericFrame *)(frame.get());
		dissect_generic_frame(tvb, frame_tree, ti, f);
	} else {
		;
	}
}

static int dissect_J1939(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_tree *j1939_tree, *can_tree;

    struct can_info can_info;

    DISSECTOR_ASSERT(data);
    can_info = *((struct can_info*)data);

    if ((can_info.id & CAN_ERR_FLAG) ||
        !(can_info.id & CAN_EFF_FLAG))
    {
        /* Error frames and frames with standards ids are not for us */
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "J1939");
    col_clear(pinfo->cinfo, COL_INFO);

	add_j1939_tree(tvb, tree, &j1939_tree, &can_tree, can_info.id);

	show_addr(tvb, pinfo, can_tree, can_info.id);

	dissect_J1939_framework(tvb, pinfo, &j1939_tree, can_info.id);

	return tvb_captured_length(tvb);
}

void dissect_generic_frame(tvbuff_t *tvb, proto_tree *j1939_tree,
						   proto_item *ti, GenericFrame *genFrame)
{
	proto_tree *spn_tree;
	std::set<guint32> spnNumbers = genFrame->getSPNNumbers();

	for (auto iter = spnNumbers.begin(); iter != spnNumbers.end(); ++iter) {
		const SPN *spn = genFrame->getSPN(*iter);

		ti = proto_tree_add_uint(j1939_tree, hf_j1939_spn, tvb,
								 spn->getOffset(), spn->getByteSize(), *iter);
		spn_tree = proto_item_add_subtree(ti, ett_j1939_can);

		switch (spn->getType()) {
		case SPN::SPN_NUMERIC: {
			const SPNNumeric *spnNum = (SPNNumeric *)(spn);

			ti = proto_tree_add_double_format(
					spn_tree, hf_spn_id[*iter], tvb, spn->getOffset(),
					spnNum->getByteSize(), spnNum->getFormattedValue(),
					"%s: %.10g %s", spn->getName().c_str(),
					spnNum->getFormattedValue(), spnNum->getUnits().c_str());
		} break;
		case SPN::SPN_STATUS: {
			const SPNStatus *spnStatus = (SPNStatus *)(spn);

			ti = proto_tree_add_uint_bits_format_value(
					spn_tree, hf_spn_id[*iter], tvb,
					(spn->getOffset() << 3) + 8 - spnStatus->getBitOffset() -
					spnStatus->getBitSize(),
					spnStatus->getBitSize(), spnStatus->getValue(), "%s (%u)",
					spnStatus->getValueDescription(spnStatus->getValue()).c_str(),
					spnStatus->getValue());
		} break;
		case SPN::SPN_STRING: {
			const SPNString *spnStr = (SPNString *)(spn);

			ti = proto_tree_add_item(spn_tree, hf_spn_id[*iter], tvb,
									 spn->getOffset(),
									 spnStr->getValue().size(), ENC_NA);
		} break;
		default:
			break;
		}
	}
}
