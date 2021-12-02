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


static tinfo_t convert_dtype( uint32_t dtype ) 
{
	switch ( dtype )
	{
		case dt_byte:   return tinfo_t{ BT_INT8 };
		case dt_word:   return tinfo_t{ BT_INT16 };
		case dt_dword:  return tinfo_t{ BT_INT32 };
		case dt_qword:  return tinfo_t{ BT_INT64 };
		case dt_byte16: return tinfo_t{ BT_INT128 };
		case dt_float:  return tinfo_t{ BT_FLOAT };
		case dt_double: return tinfo_t{ BTMT_DOUBLE };
		default:        return tinfo_t{ BT_VOID };
	}
}

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
		std::pair<size_t, const char*> force_zero_list[] = {
			{ 4,    "KiIrqlFlags"          },
			{ 4,    "HvlEnlightenments"    },
			{ 4,    "HvlLongSpinCountMask" },
			{ 0x10, "PerfGlobalGroupMask"  },
		};

		// If referencing any of the globals above at any offset [0-8], assume constant zero.
		//
		for ( int delta = 0; delta <= 0x10; delta++ )
		{
			auto name = get_name( op->g - delta );
			for ( auto& [sz, item] : force_zero_list )
			{
				if ( delta >= sz )
					continue;
				if ( name == item )
				{
					msg( "Ignoring %s\n", item );
					op->make_number( 0, op->size );
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

// Optimizes out blocks generated from PTE reading macro handling shadow ranges.
//
hex::insn_optimizer shadow_pte_read_optimizer = [ ] ( mblock_t* blk, minsn_t* ins, auto )
{
	// Skip if it isn't a conditional jump.
	//
	if ( !is_mcode_jcond( ins->opcode ) )
		return 0;

	// For each operand and sub-operand:
	//
	int res = ins->for_all_ops( hex::mop_visitor( [ ] ( mop_t* op, const tinfo_t* type, bool is_target )
	{
		// If and type:
		//
		if ( op->t == mop_d && op->d->opcode == m_and )
		{
			auto o1 = &op->d->l;
			auto o2 = &op->d->r;
			if ( o1->t == mop_n )
				std::swap( o1, o2 );

			// If Op1 is 0xC00000:
			//
			if ( o2->t == mop_n && o2->nnn->value == 0xC00000 )
			{
				// If Op2 is MiFlags:
				//
				if ( o1->t == mop_v && get_name( o1->g ) == "MiFlags" )
				{
					// Replace with number.
					//
					op->make_number( 0, 4 );
					return 1;
				}
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

// Lifts simple instructions.
//
constexpr std::pair<uint16_t, const char*> simple_instruction_list[] = 
{
	{ NN_clac,         "__clac"          },
	{ NN_stac,         "__stac"          },
	{ NN_swapgs,       "__swapgs"        },
	{ NN_saveprevssp,  "__saveprevssp"   },
	{ NN_setssbsy,     "__setssbsy"      },
	{ NN_endbr64,      "__endbr64"       },
	{ NN_endbr32,      "__endbr32"       },
	{ NN_incsspq,      "__incsspq"       },
	{ NN_incsspd,      "__incsspd"       },
	{ NN_rstorssp,     "__rstorssp"      },
	{ NN_wrssd,        "__wrssd"         },
	{ NN_wrssq,        "__wrssq"         },
	{ NN_wrussd,       "__wrussd"        },
	{ NN_wrussq,       "__wrussq"        },
	{ NN_clrssbsy,     "__clrssbsy"      },
	{ NN_clflushopt,   "_mm_clflushopt"  },
	{ NN_clwb,         "_mm_clwb"        },
	{ NN_vmclear,      "__vmclear"       },
	{ NN_vmlaunch,     "__vmlaunch"      },
	{ NN_vmptrld,      "__vmptrld"       },
	{ NN_vmptrst,      "__vmptrst"       },
	{ NN_vmwrite,      "__vmwrite"       },
	{ NN_vmxoff,       "__vmxoff"        },
	{ NN_vmxon,        "__vmxon"         },
	{ NN_invpcid,      "_invpcid"        },
	{ NN_invlpga,      "_invlpga"        },
	{ NN_xsaves,       "_xsaves"         },
	{ NN_xrstors,      "_xrstors"        },
	{ NN_prefetcht0,   "_mm_prefetcht0"  },
	{ NN_prefetcht1,   "_mm_prefetcht1"  },
	{ NN_prefetcht2,   "_mm_prefetcht2"  },
	{ NN_prefetchnta,  "_mm_prefetchnta" },
	// TODO: vmfunc.
};
hex::microcode_filter simple_instruction_lifter = [ ] ( codegen_t& cg )
{
	// Pick the intrinsic.
	//
	auto it = std::find_if( std::begin( simple_instruction_list ), std::end( simple_instruction_list ), [ & ] ( auto& pair )
	{
		return cg.insn.itype == pair.first;
	} );
	if ( it == std::end( simple_instruction_list ) )
		return false;
	hex::helper helper{ it->second };

	// Create the call information.
	//
	auto ci = hex::call_info( tinfo_t{ BT_VOID } );
	for ( auto& ops : cg.insn.ops )
	{
		if ( ops.type == o_void )
			break;

		if ( ops.type == o_imm )
		{
			tinfo_t t = convert_dtype( ops.dtype );
			if ( t.is_void() ) return false;
			ci->args.push_back( hex::call_arg{ hex::operand{ ops.value, ( int ) t.get_size() }, t } );
		}
		else if ( ops.type == o_reg )
		{
			tinfo_t t = convert_dtype( ops.dtype );
			if ( t.is_void() ) return false;
			ci->args.push_back( hex::call_arg{ hex::phys_reg( ops.reg, t.get_size() ), t } );
		}
		else
		{
			tinfo_t t{};
			t.create_ptr( tinfo_t{ BT_VOID } );
			ci->args.push_back( hex::call_arg{ hex::reg( cg.load_effective_address( &ops - &cg.insn.ops[ 0 ] ), 8 ), t } );
		}
	}

	// Emit the intrinsic.
	//
	cg.mb->insert_into_block(
		hex::make_call( cg.insn.ea, helper, std::move( ci ) ).release(),
		cg.mb->tail
	);
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts RDRAND/RDSEED.
//
hex::microcode_filter rdrand_rdseed_lifter = [ ] ( codegen_t& cg )
{
	// Pick the intrinsic.
	//
	hex::helper helper{};
	if ( cg.insn.itype == NN_rdrand )
		helper = hex::helper{ "__rdrand" };
	else if ( cg.insn.itype == NN_rdseed )
		helper = hex::helper{ "__rdseed" };
	else
		return false;

	// Create the call information.
	//
	tinfo_t t = convert_dtype( cg.insn.ops[ 0 ].dtype );
	if ( t.is_void() ) return false;

	auto ci = hex::call_info( t );
	ci->spoiled.add( mr_cf, 1 );
	auto call = hex::make_call( cg.insn.ea, helper, std::move( ci ) );

	// Emit the mov of the result.
	//
	cg.mb->insert_into_block(
		hex::make_mov( cg.insn.ea, std::move( call ), hex::phys_reg( cg.insn.ops[ 0 ].reg, t.get_size() ) ).release(),
		cg.mb->tail
	);
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts RDSSP.
//
hex::microcode_filter rdssp_lifter = [ ] ( codegen_t& cg )
{
	// Pick the intrinsic.
	//
	hex::helper helper{};
	if ( cg.insn.itype == NN_rdsspd )
		helper = hex::helper{ "__rdsspd" };
	else if ( cg.insn.itype == NN_rdsspq )
		helper = hex::helper{ "__rdsspq" };
	else
		return false;

	// Create the call information.
	//
	tinfo_t t = convert_dtype( cg.insn.ops[ 0 ].dtype );
	if ( t.is_void() ) return false;

	auto ci = hex::call_info( t );
	auto call = hex::make_call( cg.insn.ea, helper, std::move( ci ) );

	// Emit the mov of the result.
	//
	cg.mb->insert_into_block(
		hex::make_mov( cg.insn.ea, std::move( call ), hex::phys_reg( cg.insn.ops[ 0 ].reg, t.get_size() ) ).release(),
		cg.mb->tail
	);
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts VMREAD.
//
hex::microcode_filter vmread_lifter = [ ] ( codegen_t& cg )
{
	if ( cg.insn.itype != NN_vmread )
		return false;
	
	// Figure out the type used.
	//
	tinfo_t src_type = convert_dtype( cg.insn.ops[ 1 ].dtype );
	if ( src_type.is_void() ) return false;

	// Read memory address where relevant.
	//
	bool is_memory = cg.insn.ops[ 0 ].type != o_reg;
	hex::operand mem_addr = {};
	if ( is_memory )
		mem_addr = hex::reg{ cg.load_effective_address( 0 ), 8 };

	// Apply the intrinsic.
	//
	auto ci = hex::call_info(
		hex::pure_t{},
		src_type,
		hex::call_arg( hex::phys_reg( cg.insn.ops[ 1 ].reg, src_type.get_size() ), src_type, "field" )
	);
	auto result = hex::make_call( cg.insn.ea, hex::helper{ "__vmread" }, std::move( ci ) );

	// Move back the result.
	//
	if ( !is_memory )
		cg.mb->insert_into_block( hex::make_mov( cg.insn.ea, std::move( result ), hex::phys_reg( cg.insn.ops[ 0 ].reg, src_type.get_size() ) ).release(), cg.mb->tail );
	else
		cg.mb->insert_into_block( hex::make_stx( cg.insn.ea, std::move( result ), hex::phys_reg( R_ds, 2 ), mem_addr ).release(), cg.mb->tail );
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts RCL/RCR.
//
hex::microcode_filter rcl_rcr_lifter = [ ] ( codegen_t& cg )
{
	if ( cg.insn.itype != NN_rcr && cg.insn.itype != NN_rcl )
		return false;
	bool is_rcr = cg.insn.itype != NN_rcr;
	
	// Figure out the type used.
	//
	tinfo_t src_type = convert_dtype( cg.insn.ops[ 0 ].dtype );
	if ( src_type.is_void() ) return false;

	// Allocate a temporary and mov the input register into it.
	//
	auto tmp = hex::reg( cg.mba->alloc_kreg( src_type.get_size() ), src_type.get_size() );

	bool is_memory = cg.insn.ops[ 0 ].type != o_reg;
	hex::operand mem_addr = {};
	if ( !is_memory )
	{
		cg.mb->insert_into_block( hex::make_mov( cg.insn.ea, hex::phys_reg( cg.insn.ops[ 0 ].reg, src_type.get_size() ), tmp ).release(), cg.mb->tail );
	}
	else
	{
		mem_addr = hex::reg{ cg.load_effective_address( 0 ), 8 };
		cg.mb->insert_into_block( hex::make_ldx( cg.insn.ea, hex::phys_reg( R_ds, 2 ), mem_addr, tmp ).release(), cg.mb->tail );
	}

	// Apply the intrinsic.
	//
	hex::call_arg count{ hex::operand{ 1, 1 }, tinfo_t{ BT_INT8 }, "count" };
	if ( cg.insn.ops[ 1 ].type == o_reg )
		count = { hex::phys_reg( R_cx, 1 ), tinfo_t{ BT_INT8 }, "count" };
	auto ci = hex::call_info(
		hex::pure_t{},
		src_type,
		hex::call_arg( tmp, src_type, "value" ),
		hex::call_arg( hex::reg{ mr_cf, 1 }, tinfo_t{ BT_INT8 }, "carry" ),
		count
	);
	ci->spoiled.add( mr_cf, 1 );
	ci->spoiled.add( mr_of, 1 );
	auto result = hex::make_call( cg.insn.ea, hex::helper{ is_rcr ? "__rcr" : "__rcl" }, std::move( ci ) );

	// Move back the result.
	//
	if ( !is_memory )
		cg.mb->insert_into_block( hex::make_mov( cg.insn.ea, std::move( result ), hex::phys_reg( cg.insn.ops[ 0 ].reg, src_type.get_size() ) ).release(), cg.mb->tail );
	else
		cg.mb->insert_into_block( hex::make_stx( cg.insn.ea, std::move( result ), hex::phys_reg( R_ds, 2 ), mem_addr ).release(), cg.mb->tail );
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts trap-frame setup.
//
hex::microcode_filter trapframe_lifter = [ ] ( codegen_t& cg )
{
	constexpr const char* isr_list[] = {
		"KxIsrLinkage",               "KiCallUserMode",                 "KiApcInterrupt",              "KiHvInterrupt",
		"KiVmbusInterrupt0",          "KiVmbusInterrupt1",              "KiVmbusInterrupt2",           "KiVmbusInterrupt3",
		"KiSwInterrupt",              "KiDpcInterrupt",                 "KiIpiInterrupt",              "KyStartUserThread",
		"KiDivideErrorFault",         "KxDebugTrapOrFault",             "KiNmiInterruptStart",         "KiBreakpointTrap",
		"KiOverflowTrap",             "KiBoundFault",                   "KiInvalidOpcodeFault",        "KiNpxNotAvailableFault",
		"KiDoubleFaultAbort",         "KiNpxSegmentOverrunAbort",       "KiInvalidTssFault",           "KiSegmentNotPresentFault",
		"KiStackFault",               "KiGeneralProtectionFault",       "KiPageFault",                 "KiFloatingErrorFault",
		"KiAlignmentFault",           "KiMcheckAbort",                  "KxMcheckAlternateReturn",     "KiXmmException",
		"KiVirtualizationException",  "KiControlProtectionFault",       "KiRaiseSecurityCheckFailure", "KiRaiseAssertion",
		"KiDebugServiceTrap",         "KiSystemService",                "KiSystemCall32",              "KiServiceInternal",
		"KiSystemCall64",             "KiSystemCall32Shadow",           "KiSystemCall64Shadow",        "HalpBlkDivideErrorFault",
		"HalpBlkDebugExceptionTrap",  "HalpBlkBreakpointTrap",          "HalpBlkOverflowTrap",         "HalpBlkBoundRangeExceededFault",
		"HalpBlkInvalidOpcodeFault",  "HalpBlkDeviceNotAvailableFault", "HalpBlkDoubleFaultAbort",     "HalpBlkCoprocessorSegmentOverrunFault",
		"HalpBlkInvalidTssFault",     "HalpBlkSegmentNotPresentFault",  "HalpBlkStackSegmentFault",    "HalpBlkGeneralProtectionFault",
		"HalpBlkPageFault",           "HalpBlkFloatingPointErrorFault", "HalpBlkAlignmentFault",       "HalpBlkFloatingPointFault",
		"HalpBlkVirtualizationFault", "HalpBlkReservedVector21",        "HalpBlkReservedVector22",     "HalpBlkReservedVector23",
		"HalpBlkReservedVector24",    "HalpBlkReservedVector25",        "HalpBlkReservedVector26",     "HalpBlkReservedVector27",
		"HalpBlkReservedVector28",    "HalpBlkReservedVector29",        "HalpBlkReservedVector30",     "HalpBlkReservedVector31",
		"HalpBlkStubInterrupt",       "HalpBlkSpuriousInterrupt",       "HalpBlkIpiInterrupt",         "HalpBlkLocalErrorInterrupt",
		"HalpBlkMachineCheckAbort",   "HalpBlkNmiInterrupt",            "HalpBlkUnexpectedInterruptCommon"
	};
	
	// Match against LEA RBP, [RSP+0x80].
	//
	uint8_t expected[] = { 0x48 , 0x8D , 0xAC , 0x24 , 0x80 , 0x00 , 0x00, 0x00 };
	uint8_t bytes[ std::size( expected ) ];
	get_bytes( bytes, std::size( expected ), cg.insn.ea );
	if ( memcmp( bytes, expected, std::size( expected ) ) )
		return false;

	// Match the name against an ISR.
	//
	auto name = get_name( cg.mba->entry_ea );
	auto it = std::find_if( std::begin( isr_list ), std::end( isr_list ), [ & ] ( const char* n )
	{
		return name == n;
	} );
	if ( it == std::end( isr_list ) )
		return false;

	// Resolve trapframe type.
	//
	tinfo_t tinfo = {};
	if ( !tinfo.get_named_type( hex::local_type_lib(), "_KTRAP_FRAME" ) )
		return false;

	tinfo_t pinfo = {};
	ptr_type_data_t pi{ tinfo_t(), 0 };
	pi.parent =     tinfo;
	pi.obj_type =   tinfo;
	pi.delta =      0x80;
	pi.taptr_bits = 0x80;
	pinfo.create_ptr( pi );

	msg( "Inserted KeGetTrapFrame.\n" );
	auto tf = hex::make_call( 
		cg.insn.ea, 
		hex::helper{ "KeGetTrapFrame" },
		hex::call_info( hex::pure_t{}, pinfo )
	);
	cg.mb->insert_into_block( hex::make_mov( cg.insn.ea, std::move( tf ), hex::phys_reg( R_bp, 8 ) ).release(), cg.mb->tail );
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts the IRETQ instruction.
//
hex::microcode_filter iretq_lifter = [ ] ( codegen_t& cg )
{
	if ( cg.insn.itype != NN_iretq )
		return false;

	auto load_at = [ & ] ( tinfo_t typ, size_t offset, const char* name )
	{
		auto ltmp = hex::reg{ cg.mba->alloc_kreg( 8 ), 8 };
		auto tmp = hex::reg{ cg.mba->alloc_kreg( typ.get_size() ), ( int ) typ.get_size() };
		cg.mb->insert_into_block( hex::make_add( cg.insn.ea, hex::phys_reg( R_sp, 8 ), hex::operand{ offset, 8 }, ltmp ).release(), cg.mb->tail );
		cg.mb->insert_into_block( hex::make_ldx( cg.insn.ea, hex::phys_reg( R_ss, 2 ), ltmp, tmp ).release(), cg.mb->tail );
		return hex::call_arg( tmp, typ, name );
	};

	tinfo_t vptr{};
	vptr.create_ptr( tinfo_t{ BT_VOID } );
	auto ci = hex::call_info(
		tinfo_t{ BT_VOID },
		load_at( vptr, 0, "ip" ),
		load_at( tinfo_t{ BT_INT16 }, 8, "cs" ),
		load_at( tinfo_t{ BT_INT32 }, 0x10, "flags" ),
		load_at( vptr, 0x18, "sp" ),
		load_at( tinfo_t{ BT_INT16 }, 0x20, "ss" )
	);
	ci->flags |= FCI_NORET;
	cg.mb->insert_into_block( hex::make_call( cg.insn.ea, hex::helper( "__iretq" ), std::move( ci ) ).release(), cg.mb->tail );
	cg.mb->mark_lists_dirty();
	return true;
};

// Lifts the SYSRETQ instruction.
//
hex::microcode_filter sysretq_lifter = [ ] ( codegen_t& cg )
{
	// Sysret with REX.W.
	//
	if ( cg.insn.itype != NN_sysret || get_byte( cg.insn.ea ) != 0x48 )
		return false;

	tinfo_t vptr{};
	vptr.create_ptr( tinfo_t{ BT_VOID } );
	auto ci = hex::call_info(
		tinfo_t{ BT_VOID },
		hex::call_arg( hex::phys_reg( R_cx, 8 ), vptr, "ip" ),
		hex::call_arg( hex::phys_reg( R_r11, 4 ), tinfo_t{ BT_INT32 }, "flags" )
	);
	ci->flags |= FCI_NORET;
	cg.mb->insert_into_block( hex::make_call( cg.insn.ea, hex::helper( "__sysretq" ), std::move( ci ) ).release(), cg.mb->tail );
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

// Type fixing:
//
constexpr std::pair<const char*, const char*> parent_types_list[] = {
	{ "_KTHREAD",  "_ETHREAD"  },
	{ "_KPROCESS", "_EPROCESS" },
};
static std::vector<std::pair<tinfo_t, tinfo_t>> get_parent_type_pairs() 
{
	std::vector<std::pair<tinfo_t, tinfo_t>> list = {};
	for ( auto& [src, dst] : parent_types_list )
	{
		tinfo_t srct, dstt{};
		if ( !srct.get_named_type( hex::local_type_lib(), src ) ||
			  !dstt.get_named_type( hex::local_type_lib(), dst ) )
			continue;
		list.emplace_back( srct, dstt );
	}
	return list;
}
static tinfo_t type_replace_rec( tinfo_t value, const tinfo_t& src, const tinfo_t& dst ) {
	
	if ( value == src )
		return dst;

	if ( value.is_ptr() )
	{
		ptr_type_data_t pi;
		value.get_ptr_details( &pi );
		if ( pi.obj_type == src || pi.parent == src )
		{
			if ( pi.obj_type == src )
				pi.obj_type = dst;
			if ( pi.parent == src )
				pi.parent = dst;

			value.create_ptr( pi );
			return value;
		}
	}
	return value;
}

hex::hexrays_callback type_enforcer = hex::hexrays_callback_for<hxe_maturity>( [ ] ( cfunc_t* cf, ctree_maturity_t mat )
{
	if ( mat == CMAT_ZERO )
	{
		auto replace_list = get_parent_type_pairs();
		if ( replace_list.empty() )
			return 0;
		for ( auto blk : hex::basic_blocks( cf->mba ) )
			for ( auto& lvar : blk->mba->vars )
				for ( auto& [src, dst] : replace_list )
					lvar.set_lvar_type( type_replace_rec( lvar.type(), src, dst) );
	}
	return 0;
} );
static void fix_udts()
{
	// Get the replace list, if there is nothing to do, return.
	//
	auto replace_list = get_parent_type_pairs();
	if ( replace_list.empty() )
		return;

	// For each named type:
	//
	for ( const char* type_name_o : hex::named_types() )
	{
		// Get named type information, if not UDT skip.
		//
		tinfo_t ti{};
		ti.get_named_type( hex::local_type_lib(), type_name_o );
		if ( !ti.is_udt() )
			continue;

		// Save the type name since we'll erase the old one.
		//
		std::string type_name{ type_name_o };

		// Get UDT details.
		//
		udt_type_data_t ui;
		ti.get_udt_details( &ui );

		// For each field:
		//
		size_t replace_count = 0;
		for ( auto& field : ui )
		{
			// Go through the replace list and invoke it on the field type.
			//
			auto orig_type = field.type;
			for ( auto& [s, d] : replace_list )
			{
				// Skip in case it's recursive.
				//
				if ( ti == d )
					continue;
				field.type = type_replace_rec( field.type, s, d );
			}

			// If field type is changed, increment replacement count.
			//
			replace_count += orig_type != field.type;
		}

		// If type remains unchanged continue.
		//
		if ( !replace_count )
			continue;
		msg( "Fixed type '%s'.\n", type_name.c_str() );

		// Replace by-ordinal references to the original structure w named references.
		//
		auto* mtil = ( til_t* ) hex::local_type_lib();
		replace_ordinal_typerefs( mtil, &ti );

		// Set the new type.
		//
		tinfo_t nti{};
		nti.create_udt( ui, ti.is_union() ? BTF_UNION : BTF_STRUCT );
		nti.set_named_type( mtil, type_name.c_str(), NTF_REPLACE );
	}
}

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
	&shadow_pte_update_optimizer, &shadow_pte_read_optimizer, 
	&mm_dyn_reloc_lifter,         &isr_rsb_flush_lifter,        
	&cpuid_lifter,                &xgetbv_lifter,               
	&xsetbv_lifter,               &simple_instruction_lifter,
	&rcl_rcr_lifter,              &trapframe_lifter,
	&iretq_lifter,                &sysretq_lifter,
	&type_enforcer,               &rdrand_rdseed_lifter,
	&rdssp_lifter,                &vmread_lifter
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
			remove_rsb_flush(), create_kuser_seg(), fix_udts();
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