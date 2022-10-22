`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: Technische Universität München (TUM) / Fraunhofer Institute for Applied and Integrated Security (AISEC)
// Engineer: Tobias Stelzer (tobias.stelzer@aisec.fraunhofer.de , tobias.stelzer@tum.de)
// 
// Create Date: 06/21/2022 08:20:57 AM
// Design Name: PQ_ALU
// Module Name: otbn_pq_pkg
// Project Name: 2022-MA-PQ-ALU-OpenTitan
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////



package otbn_pq_pkg;
    import otbn_pkg::*;
    // Global Constants ==============================================================================
    
    // Data path width for PQ instructions, in bits.
    parameter int PQLEN = 32;
    
    // Number of 32-bit words per WLEN
    parameter int BaseWordsPerPQLEN = 8*PQLEN / 32;
    
    //
    parameter int LOG_R = 32;
    
    // "Extended" PQLEN: the size of the datapath with added integrity bits
    parameter int ExtPQLEN = PQLEN * 39 / 32;



  typedef enum logic {
    InsnSubsetBasePq = 1'b0,  // Base (RV32/Narrow) Instruction Subset
    InsnSubsetPq = 1'b1     // PQ (BN/Wide) Instruction Subset
  } insn_subset_pq_e;


  typedef struct packed {
    insn_subset_pq_e    subset;
    logic               br_insn;
    logic   [3:0]       br_nof_bits;
    
    logic               sl_j2;
    logic               sl_m;
    logic               inc_j;
    logic               inc_idx;
    logic               set_idx;
    
    logic               ispr_rd_insn;
    logic               ispr_wr_insn;
    logic               ispr_rs_insn;

    logic               ictrlspr_rd_insn;
    logic               ictrlspr_wr_insn;
    logic               ictrlspr_rs_insn;
    
    logic               update_omega;
    logic               update_psi;
    logic               set_twiddle_as_psi;
    logic               update_twiddle;
    logic               invert_twiddle;
    logic               omega_idx_inc;
    logic               psi_idx_inc;
  } insn_dec_shared_pq_t;


  // Regfile write data selection
  typedef enum logic [1:0] {
    RfWdSelExPq,
    RfWdSelExInPlacePq,
    RfWdSelIsprPq,
    RfWdSelIsprPqCtrl
  } rf_wd_pq_sel_e;


    // TODO: Can we simplify decoding logic in pq_alu?
    // {sel_gs_subtractor, sel_ct_mux0,el_ct_mux1, sel_twiddle, sel_forward_rd, sel_forward_rs0, sel_forward_rs1, sel_rd }
    typedef enum logic [7:0] {
        AluOpPqAdd          = 8'h42,
        AluOpPqSub          = 8'h27,
        AluOpPqMul          = 8'h01,
        AluOpPqMulAdd       = 8'h48,
        AluOpPqButterflyCT  = 8'h74,
        AluOpPqButterflyGS  = 8'hD2
    } alu_op_pq_e;
  
  
    typedef struct packed {
        alu_op_pq_e             op;
        logic   [WLEN-1:0]      operand_a;
        logic   [WLEN-1:0]      operand_b;
        logic   [PQLEN-1:0]     operand_c;  
        logic   [PQLEN-1:0]     prime;
        logic   [LOG_R-1:0]     prime_dash;
        logic   [PQLEN-1:0]     twiddle;
        logic   [2:0]           operand_a_w_sel;
        logic   [2:0]           operand_b_w_sel; 
        logic   [2:0]           d_w_sel;
    } alu_pq_operation_t;


    typedef enum logic {
        BitrevOpPq          = 1'b0,
        BitrevOpPqShift     = 1'b1
    } bitrev_op_pq_e;

    typedef struct packed {
        bitrev_op_pq_e          op;
        logic   [PQLEN-1:0]     operand_a;
        logic   [PQLEN-1:0]     nof_bits;    
    } bitrev_pq_operation_t;
    

  parameter int NPqspr = 8;
  parameter int PqsprNumWidth = $clog2(NPqspr);
  typedef enum logic [PqsprNumWidth-1:0] {
    PqsrPrime       = 'd0,
    PqsrPrimeDash   = 'd1,
    PqsrTwiddle     = 'd2,
    PqsrOmega       = 'd3,
    PqsrPsi         = 'd4,
    PqsrOmegaIdx    = 'd5,
    PqsrPsiIdx      = 'd6,
    PqsrConst       = 'd7
  } pqspr_e;


  parameter int PqctrlsprNumWidth = 12;
  typedef enum logic [PqctrlsprNumWidth-1:0] {
    PqctrlsrM           = 'h001,
    PqctrlsrJ2          = 'h002,
    PqctrlsrJ           = 'h003,
    PqctrlsrIdx0        = 'h004,
    PqctrlsrIdx1        = 'h005,
    PqctrlsrMode        = 'h006,
    PqctrlsrPrime       = 'h010,
    PqctrlsrPrimeDash   = 'h020,
    PqctrlsrTwiddle     = 'h030,
    PqctrlsrOmega0      = 'h040,
    PqctrlsrOmega1      = 'h041,
    PqctrlsrOmega2      = 'h042,
    PqctrlsrOmega3      = 'h043,
    PqctrlsrOmega4      = 'h044,
    PqctrlsrOmega5      = 'h045,
    PqctrlsrOmega6      = 'h046,
    PqctrlsrOmega7      = 'h047,
    PqctrlsrPsi0        = 'h050,
    PqctrlsrPsi1        = 'h051,
    PqctrlsrPsi2        = 'h052,
    PqctrlsrPsi3        = 'h053,
    PqctrlsrPsi4        = 'h054,
    PqctrlsrPsi5        = 'h055,
    PqctrlsrPsi6        = 'h056,
    PqctrlsrPsi7        = 'h057,
    PqctrlsrOmegaIdx    = 'h060,
    PqctrlsrPsiIdx     	= 'h070,
    PqctrlsrConst       = 'h080
  } pqctrlspr_e;
  
  // Internal Post-Quantum Special Purpose Registers (IPQSPRs)
  // CSRs and PQSRs might have some overlap in the future into what they map into. IPQSPRs are the actual registers in the
  // design which CSRs and PQSRs are mapped on to.
  // TODO: Adapt CSRs
  parameter int Nipqspr = 13;
  parameter int IpqsprNumWidth = $clog2(Nipqspr);
  typedef enum logic [IpqsprNumWidth-1:0] {
    IsprPrime       = 'd0,
    IsprPrimeDash   = 'd1,
    IsprTwiddle     = 'd2,
    IsprOmega       = 'd3,
    IsprPsi         = 'd4,
    IsprOmegaIdx    = 'd5,
    IsprPsiIdx      = 'd6,
    IsprConst       = 'd7,
    IsprM           = 'd8,
    IsprJ2          = 'd9,
    IsprJ           = 'd10,
    IsprIdx0        = 'd11,
    IsprIdx1        = 'd12,
    IsprMode        = 'd13
  } ipqspr_e;



  typedef struct packed {
    logic [WdrAw-1:0]        d;           // Destination register
    logic [WdrAw-1:0]        a;           // First source register
    logic [WdrAw-1:0]        b;           // Second source register
    
    logic [PqsprNumWidth-1:0]        pqsr_addr;   // PQSR Address
    logic [PqctrlsprNumWidth-1:0]        pqctrlsr_addr;   // PQSR Address
    alu_op_pq_e              alu_op;
    op_b_sel_e               alu_op_b_sel;

    logic [2:0]              pq_op_a_w_sel;
    logic [2:0]              pq_op_b_w_sel;
    logic [2:0]              pq_d_w_sel;
    
    logic [7:0]              pq_wr_w_sel_a;
    logic [7:0]              pq_wr_w_sel_b;
    logic [7:0]              pq_wr_w_sel_d;
    
    logic                    pq_in_place;
    logic                    operands_indirect;
    logic                    use_const;
     
    logic                    rf_we;
    rf_wd_pq_sel_e           rf_wdata_sel;
    
    logic                    rf_ren_a;
    logic                    rf_ren_b;

    logic                    sel_insn;
  } insn_dec_pq_t;

endpackage
