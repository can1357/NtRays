#include <hexsuite.hpp>
#include <intel.hpp>

// NT constants.
//
static constexpr size_t index_self_ref = 0x1ED;
static constexpr ea_t make_pte_base( size_t level, size_t max_levels )
{
	ea_t result = ~0ull << ( max_levels * 9 + 12 );
	for ( size_t l = level; l != max_levels; l++ )
		result |= index_self_ref << ( 9 * l + 12 );
	return result;
}
static constexpr ea_t pfn_list_base_va48 = 0xFFFFFA8000000000;
static constexpr ea_t pfn_list_base_la57 = 0xFFFFDE0000000000;

// Optimizes out blocks generated due to inlined scheduler hints, hv enlightenments or instrumentations.
//
hex::insn_optimizer global_optimizer = [ ] ( mblock_t* blk, minsn_t* ins, auto )
{
	// Skip if it isn't a conditional jump.
	//
	if ( !is_mcode_jcond( ins->opcode ) )
		return 0;

	// For each operand and sub-operand:
	//
	int res = ins->for_all_ops( hex::mop_visitor( [ ] ( mop_t* op, const tinfo_t* type, bool is_target )
	{
		const char* force_zero_list[] = {
			"KiIrqlFlags",
			"HvlEnlightenments",
			"PerfGlobalGroupMask",
			"HvlLongSpinCountMask"
		};

		// If referencing any of the globals above at any offset [0-8], assume constant zero.
		//
		for ( int delta = 0; delta <= 8; delta++ )
		{
			auto name = get_name( op->g - delta );
			for ( auto& item : force_zero_list )
			{
				if ( name == item )
				{
					msg( "Ignoring %s\n", item );
					op->make_number( 0, 4 );
					return 1;
				}
			}
		}
		return 0;
	} ) );
	if ( res )
		blk->mark_lists_dirty();
	return res;
};

// Optimizes out blocks generated from PTE writing macro handling shadow ranges.
//
hex::insn_optimizer shadow_pte_update_optimizer = [ ] ( mblock_t* blk, minsn_t* ins, auto )
{
	// Skip if it isn't a conditional jump.
	//
	if ( !is_mcode_jcond( ins->opcode ) )
		return 0;

	// For each operand and sub-operand:
	//
	int res = ins->for_all_ops( hex::mop_visitor( [ ] ( mop_t* op, const tinfo_t* type, bool is_target )
	{
		// If call type:
		//
		if ( op->t == mop_d && op->d->opcode == m_call )
		{
			// If checking shadow PTE, assume 0 return.
			//
			auto callee = get_name( op->d->l.g );
			if ( callee == "MiPteHasShadow" || callee == "MiPteInShadowRange" )
			{
				msg( "Ignoring %s\n", callee.c_str() );
				op->make_number( 0, 4 );
				return 1;
			}
		}
		return 0;
	} ) );

	// If we changed anything, declare lists dirty.
	//
	if ( res )
		blk->mark_lists_dirty();
	return res;
};

// Optimizes out system priority management on IRQL change.
//
hex::block_optimizer scheduler_hint_optimizer = [ ] ( mblock_t* blk )
{
	int changes = 0;
	for( minsn_t* ins : hex::instructions( blk ) )
	{
		// Skip if it does not match scheduler hint:
		//
		if ( ins->opcode != m_call || get_name( ins->l.g ) != "KiRemoveSystemWorkPriorityKick" )
			continue;
		msg( "Ignoring KiRemoveSystemWorkPriorityKick\n" );

		// Clear the call.
		//
		blk->make_nop( ins );
		changes++;

		// Find predecessors.
		//
		for ( mblock_t* pred : hex::predecessors( blk ) )
			for ( minsn_t* ins : hex::instructions( pred ) )
				if ( ins != pred->tail )
					pred->make_nop( ins );
	}
	return changes;
};

// Lifts MOVABS on dynamic relocations to Mm intrinsics.
//
hex::microcode_filter mm_dyn_reloc_lifter = [ ] ( codegen_t& cg )
{
	if ( cg.insn.itype == NN_mov &&
		  cg.insn.ops[ 0 ].type == o_reg &&
		  cg.insn.ops[ 1 ].type == o_imm )
	{
		ea_t imm = cg.insn.ops[ 1 ].value;

		const char* intrinsic_getter = nullptr;
		const char* intrinsic_rtype = nullptr;
		size_t intrinsic_offset = 0;

		// Handle PFN list:
		//
		if ( !intrinsic_getter )
		{
			for ( auto base : { pfn_list_base_va48, pfn_list_base_la57 } )
			{
				if ( base <= imm && imm <= ( base + 48 ) )
				{
					intrinsic_getter = "MmGetPfnDb";
					intrinsic_rtype = "_MMPFN";
					intrinsic_offset = imm - base;
					break;
				}
			}
		}
		// Handle page tables:
		//
		if ( !intrinsic_getter )
		{
			for ( size_t paging_depth : { 4, 5 } )
			{
				constexpr const char* bnames[] = { "MmGetPml5eBase", "MmGetPml4eBase", "MmGetPdpteBase", "MmGetPdeBase", "MmGetPteBase" };
				constexpr const char* lnames[] = { "MmGetPml5eLimit", "MmGetPml4eLimit", "MmGetPdpteLimit", "MmGetPdeLimit", "MmGetPteLimit" };

				for ( size_t level = 0; level != paging_depth; level++ )
				{
					auto pmin = make_pte_base( level, paging_depth );
					auto pmax = pmin + ( ( 1ull << ( 12 + 9 * level ) ) - 1 );

					if ( !level && imm == ( pmin + 0x7F8 ) )
					{
						intrinsic_getter = "MmGetPxeUserLimit";
						intrinsic_offset = 0;
						intrinsic_rtype = "_MMPTE";
						break;
					}
					else if ( !level && imm == ( pmin + ( index_self_ref ) * 8 ) )
					{
						intrinsic_getter = "MmGetPxeSelfRef";
						intrinsic_offset = 0;
						intrinsic_rtype = "_MMPTE";
						break;
					}
					else if ( imm == pmax )
					{
						intrinsic_getter = lnames[ level + ( 5 - paging_depth ) ];
						intrinsic_offset = 0;
						intrinsic_rtype = "_MMPTE";
						break;
					}
					else if ( pmin <= imm && imm <= pmax )
					{
						intrinsic_getter = bnames[ level + ( 5 - paging_depth ) ];
						intrinsic_offset = imm - pmin;
						intrinsic_rtype = "_MMPTE";
						break;
					}
				}
				if ( intrinsic_getter )
					break;
			}
		}

		// If we did find a match:
		//
		if ( intrinsic_getter )
		{
			tinfo_t type = {};
			if ( tinfo_t ttype; ttype.get_named_type( get_idati(), intrinsic_rtype ) )
				type.create_ptr( ttype );
			else
				type = tinfo_t{ BTF_UINT64 };

			qstring types = {};
			type.print( &types );
			msg( "Found relocation: %s %s()\n", types.c_str(), intrinsic_getter );

			auto call_info = hex::call_info( hex::pure_t{}, type );
			auto call = hex::make_call( cg.insn.ea, hex::helper{ intrinsic_getter }, std::move( call_info ) );
			auto adj = hex::make_add( cg.insn.ea, { intrinsic_offset, 8 }, std::move( call ), hex::phys_reg( cg.insn.ops[ 0 ].reg, 8 ) );
			cg.mb->insert_into_block( adj.release(), cg.mb->tail);
			cg.mb->mark_lists_dirty();
			return true;
		}
	}
	return false;
};

// Lifts CPUID.
//
hex::microcode_filter cpuid_lifter = [ ] ( codegen_t& cg )
{
	if ( cg.insn.itype != NN_cpuid )
		return false;

	// Emit the cpuid intrinsic with a "magic" return.
	//
	auto cpuid_ci = hex::call_info(
		tinfo_t{ BT_INT64 },
		hex::call_arg( hex::phys_reg( R_ax, 4 ), tinfo_t{ BT_INT32 }, "leaf" ),
		hex::call_arg( hex::phys_reg( R_cx, 4 ), tinfo_t{ BT_INT32 }, "subleaf" )
	);
	auto cpuid_call = hex::make_call( cg.insn.ea, hex::helper{ "__cpuid" }, std::move( cpuid_ci ) );
	auto cpuid_res = hex::reg( cg.mba->alloc_kreg( 8 ), 8 );
	cg.mb->insert_into_block(
		hex::make_mov( cg.insn.ea, std::move( cpuid_call ), cpuid_res ).release(),
		cg.mb->tail
	);

	// Create movs to each register.
	//
	std::pair<mreg_t, const char*> parts[] = {
		{ reg2mreg( R_ax ), "EAX" },
		{ reg2mreg( R_bx ), "EBX" },
		{ reg2mreg( R_cx ), "ECX" },
		{ reg2mreg( R_dx ), "EDX" }
	};
	for ( auto [reg, extr] : parts )
	{
		auto extract_ci = hex::call_info( 
			hex::pure_t{}, 
			tinfo_t{ BT_INT32 }, 
			hex::call_arg{ cpuid_res, tinfo_t{ BT_INT64 } }
		);
		auto extract_call = hex::make_call( cg.insn.ea, hex::helper( extr ), std::move( extract_ci ) );
		auto mov_ins = hex::make_mov( cg.insn.ea, std::move( extract_call ), hex::reg( reg, 4 ) );
		cg.mb->insert_into_block( mov_ins.release(), cg.mb->tail );
	}
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts XGETBV.
//
hex::microcode_filter xgetbv_lifter = [ ] ( codegen_t& cg )
{
	if ( cg.insn.itype != NN_xgetbv )
		return false;

	// Emit the XGETBV intrinsic.
	//
	auto xgetbv_ci = hex::call_info(
		tinfo_t{ BT_INT64 },
		hex::call_arg( hex::phys_reg( R_cx, 4 ), tinfo_t{ BT_INT32 }, "xcr" )
	);
	auto xgetbv_call = hex::make_call( cg.insn.ea, hex::helper{ "_xgetbv" }, std::move( xgetbv_ci ) );
	auto xgetbv_res = hex::reg( cg.mba->alloc_kreg( 8 ), 8 );
	cg.mb->insert_into_block(
		hex::make_mov( cg.insn.ea, std::move( xgetbv_call ), xgetbv_res ).release(),
		cg.mb->tail
	);

	// Create movs to each register.
	//
	cg.mb->insert_into_block( hex::make_low( cg.insn.ea, xgetbv_res, hex::phys_reg( R_ax, 4 ) ).release(), cg.mb->tail );
	cg.mb->insert_into_block( hex::make_high( cg.insn.ea, xgetbv_res, hex::phys_reg( R_cx, 4 ) ).release(), cg.mb->tail );
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts XSETBV.
//
hex::microcode_filter xsetbv_lifter = [ ] ( codegen_t& cg )
{
	if ( cg.insn.itype != NN_xsetbv )
		return false;

	// Emit the intrinsic.
	//
	auto xsetbv_ci = hex::call_info(
		tinfo_t{ BT_VOID },
		hex::call_arg( hex::phys_reg( R_cx, 4 ), tinfo_t{ BT_INT32 }, "xcr" ),
		hex::call_arg( { hex::phys_reg( R_ax, 4 ), hex::phys_reg( R_dx, 4 ) }, tinfo_t( BT_INT64 ), "value" )
	);
	cg.mb->insert_into_block(
		hex::make_call( cg.insn.ea, hex::helper{ "_xsetbv" }, std::move( xsetbv_ci ) ).release(),
		cg.mb->tail
	);
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts CLAC/STAC.
//
hex::microcode_filter stac_clac_lifter = [ ] ( codegen_t& cg )
{
	// Pick the intrinsic.
	//
	hex::helper helper = {};
	if ( cg.insn.itype == NN_clac )
		helper = { "__clac" };
	else if ( cg.insn.itype == NN_stac )
		helper = { "__stac" };
	if ( !helper.name )
		return false;

	// Emit the intrinsic.
	//
	cg.mb->insert_into_block(
		hex::make_call( cg.insn.ea, helper, hex::call_info( tinfo_t{ BT_VOID } ) ).release(),
		cg.mb->tail
	);
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts RSB flushing on ISRs.
//
constexpr uint8_t rsb_pattern[] = {
	/*
	.text:00000001403A9519 E8 0E 01 00 00                                call    loc_1403A962C
	.text:00000001403A951E
	.text:00000001403A951E                               loc_1403A951E:                          ; CODE XREF: KiPageFault+16B
	.text:00000001403A951E 48 83 C4 08                                   add     rsp, 8
	.text:00000001403A9522 E8 0E 01 00 00                                call    loc_1403A9635
	*/
	0xE8, 0x0E, 0x01, 0x00, 0x00,
	0x48, 0x83, 0xC4, 0x08,
	0xE8, 0x0E, 0x01, 0x00, 0x00
};
constexpr uint8_t rsb_replace_with[] = {
	// 9 byte nop (call + add rsp) | encodes special constant indicating RSB flush.
	0x66, 0x0F, 0x1F, 0x84, 0xDE, 0xAD, 0xC0, 0xFE, 0xFE,
	// original final call as jmp with offset changed
	0xE9, 0x12, 0x01, 0x00, 0x00
};
hex::microcode_filter isr_rsb_flush_lifter = [ ] ( codegen_t& cg )
{
	// Skip if it does not match the RSB replacement.
	//
	if ( cg.insn.itype != NN_nop )
		return false;
	uint8_t buffer[ std::size( rsb_replace_with ) ];
	get_bytes( buffer, std::size( buffer ), cg.insn.ea );
	if ( memcmp( buffer, rsb_replace_with, std::size( rsb_replace_with ) ) )
		return false;

	// Make a dummy call and insert it into the block.
	//
	cg.mb->insert_into_block(
		hex::make_call( cg.insn.ea, hex::helper{ "__flush_rsb" }, hex::call_info( tinfo_t{ BT_VOID } ) ).release(),
		cg.mb->tail
	);;
	cg.mb->mark_lists_dirty();
	return true;
};

// Removes RSB flush gadgets.
//
static void remove_rsb_flush() 
{
	ea_t iterator = inf_get_min_ea();
	while ( true )
	{
		iterator = bin_search2(
			iterator,
			inf_get_max_ea(),
			rsb_pattern,
			nullptr,
			std::size( rsb_pattern ),
			BIN_SEARCH_FORWARD
		);
		if ( iterator == BADADDR )
			break;
		put_bytes( iterator, rsb_replace_with, std::size( rsb_replace_with ) );
		iterator += std::size( rsb_replace_with );
	}
}

// Creates KUSER_SHARED_DATA segments.
//
static void create_kuser_seg() 
{
	constexpr auto km = 0xFFFFF78000000000;
	constexpr auto um = 0x7FFE0000;

	add_segm( 0x1000, km, km + 0x1000, ".kkuser", "DATA" );
	add_segm( 0x1000, um, um + 0x1000, ".ukuser", "CONST" );

	if ( inf_is_kernel_mode() )
		set_name( um, "UKUSER_SHARED_DATA" ), set_name( km, "KUSER_SHARED_DATA" );
	else
		set_name( um, "KUSER_SHARED_DATA" ),  set_name( km, "KKUSER_SHARED_DATA" );

	if ( tinfo_t type{}; type.get_named_type( hex::local_type_lib(), "_KUSER_SHARED_DATA" ) )
	{
		auto tid = import_type( hex::local_type_lib(), -1, "_KUSER_SHARED_DATA" );
		create_struct( km, type.get_size(), tid, true );
		create_struct( um, type.get_size(), tid, true );
	}
}

// List of components.
//
constexpr hex::component* component_list[] = {
	&global_optimizer,            &scheduler_hint_optimizer,
	&shadow_pte_update_optimizer, &mm_dyn_reloc_lifter,
	&isr_rsb_flush_lifter,        &cpuid_lifter,
	&xgetbv_lifter,               &xsetbv_lifter,
	&stac_clac_lifter
};

// Plugin declaration.
//
struct ntrays : plugmod_t
{
	netnode nn = { "$ ntrays", 0, true };
	hex::component_list components{ component_list };

	void set_state( bool s ) 
	{
		if ( s )
			remove_rsb_flush(), create_kuser_seg();
		components.set_state( s );
	}
	ntrays() { set_state( nn.altval( 0 ) == 0 ); }
	~ntrays() { components.uninstall(); }

	bool run( size_t ) override
	{
		constexpr const char* format = R"(
AUTOHIDE NONE
NtRays for Hex-Rays decompiler.
State: %s)";
		int code = ask_buttons( "~E~nable", "~D~isable", "~C~lose", -1, format + 1, nn.altval( 0 ) == 0 ? "Enabled" : "Disabled" );
		if ( code < 0 )
			return true;
		nn.altset( 0, code ? 0 : 1 );
		set_state( code );
		return true;
	}
};
plugin_t PLUGIN = { IDP_INTERFACE_VERSION, PLUGIN_MULTI, hex::init_hexray<ntrays>, nullptr, nullptr, "NtRays", nullptr, "NtRays", nullptr,};