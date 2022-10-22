`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: Technische Universität München (TUM) / Fraunhofer Institute for Applied and Integrated Security (AISEC)
// Engineer: Tobias Stelzer (tobias.stelzer@aisec.fraunhofer.de , tobias.stelzer@tum.de)
// 
// Create Date: 05/06/2022 09:56:19 AM
// Design Name: PQ_ALU 
// Module Name: twiddle_update
// Project Name: 2022-MA-PQ-ALU-OpenTitan
// Target Devices: 
// Tool Versions: 
// Description: 
//  Implementation of twiddle update unit (all values should be in Montgomery domain)
//      twiddle = (twiddle * omega) % q for Iterative NTT
//      twiddle = psi                   for Iterative NTT/INTT
//      psi = omega                     for Iterative INTT
//      omega = (omega * omega) % q     for Iterative INTT
//      twiddle = q - twiddle % q       for Basecase Multiplications
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module twiddle_update
    import otbn_pq_pkg::*;
(   
    input   logic                       clk_i,
    input   logic                       rst_ni,
    
    input   logic                       update_omega_i,
    input   logic                       update_psi_i,
    input   logic                       set_twiddle_as_psi_i,
    input   logic                       update_twiddle_i,
    input   logic                       invert_twiddle_i,
    input   logic                       omega_idx_inc_i,
    input   logic                       psi_idx_inc_i,
    
    output  logic   [PQLEN-1:0]         twiddle_o,
    output  logic   [PQLEN-1:0]         psi_o,
    output  logic   [PQLEN-1:0]         omega_o,
    
    output  logic   [PQLEN-1:0]         prime_o,
    output  logic   [PQLEN-1:0]         prime_dash_o,    
    
    output  logic   [PQLEN-1:0]         const_o,
    
    input  ipqspr_e                         ispr_addr_i,
    input  logic [31:0]                     ispr_base_wdata_i,
    input  logic [BaseWordsPerPQLEN-1:0]    ispr_base_wr_en_i,
    input  logic [8*PQLEN-1:0]              ispr_pq_wdata_i,
    input  logic                            ispr_pq_wr_en_i,
    input  logic                            ispr_init_i,
    output logic [8*PQLEN-1:0]              ispr_rdata_o
);

    logic   [PQLEN-1:0]    twiddle_mul;
    
    logic   [PQLEN-1:0]    omega_mul;
    
    logic   [PQLEN-1:0]    twiddle_inv;
    
    logic [PQLEN-1:0]               prime_q;
    logic [PQLEN-1:0]               prime_d;
    logic                           prime_wr_en;
    
    logic [PQLEN-1:0]               prime_dash_q;
    logic [PQLEN-1:0]               prime_dash_d;
    logic                           prime_dash_wr_en;
    
    logic [PQLEN-1:0]               twiddle_q;
    logic [PQLEN-1:0]               twiddle_d;
    logic                           twiddle_wr_en;
    
    logic [8*PQLEN-1:0]             omega_q;
    logic [8*PQLEN-1:0]             omega_d;
    logic [BaseWordsPerPQLEN-1:0]   omega_wr_en;
    
    logic [8*PQLEN-1:0]             psi_q;
    logic [8*PQLEN-1:0]             psi_d;
    logic [BaseWordsPerPQLEN-1:0]   psi_wr_en;
    
    logic [2:0]                     psi_idx_q;
    logic [2:0]                     psi_idx_d;
    logic [2:0]                     psi_idx_inc;
    logic                           psi_idx_wr_en;
    logic [7:0]                     psi_onehot;
    
    logic [2:0]                     omega_idx_q;
    logic [2:0]                     omega_idx_d;
    logic [2:0]                     omega_idx_inc;
    logic                           omega_idx_wr_en;
    logic [7:0]                     omega_onehot;
    
    logic [PQLEN-1:0]               const_q;
    logic [PQLEN-1:0]               const_d;
    logic                           const_wr_en;
    
    
    logic [PQLEN-1:0]               psi;
    logic [PQLEN-1:0]               omega;
    
    always_comb begin
        omega = '0;
        psi = '0;
        omega_onehot = 8'b00000000;
        psi_onehot = 8'b00000000;
    
        unique case (psi_idx_q)
          3'd0: begin
                    psi = psi_q[PQLEN*0+:PQLEN];
                end
          3'd1: begin
                    psi = psi_q[PQLEN*1+:PQLEN];
                end
          3'd2: begin 
                    psi = psi_q[PQLEN*2+:PQLEN];
                end
          3'd3: begin 
                    psi = psi_q[PQLEN*3+:PQLEN];
                end
          3'd4: begin 
                    psi = psi_q[PQLEN*4+:PQLEN];
                end
          3'd5: begin 
                    psi = psi_q[PQLEN*5+:PQLEN];
                end
          3'd6: begin 
                    psi = psi_q[PQLEN*6+:PQLEN]; 
                end 
          3'd7: begin 
                    psi = psi_q[PQLEN*7+:PQLEN];    
        
                end
          default: psi = '0;
        endcase
        
        unique case (omega_idx_q)
          3'd0: begin
                    omega = omega_q[PQLEN*0+:PQLEN];
                end
          3'd1: begin
                    omega = omega_q[PQLEN*1+:PQLEN];
                end
          3'd2: begin 
                    omega = omega_q[PQLEN*2+:PQLEN];
                end
          3'd3: begin 
                    omega = omega_q[PQLEN*3+:PQLEN];
                end
          3'd4: begin 
                    omega = omega_q[PQLEN*4+:PQLEN];
                end
          3'd5: begin 
                    omega = omega_q[PQLEN*5+:PQLEN];
                end
          3'd6: begin 
                    omega = omega_q[PQLEN*6+:PQLEN]; 
                end 
          3'd7: begin 
                    omega = omega_q[PQLEN*7+:PQLEN];    
        
                end
          default: omega = '0;
        endcase
        
        unique case (psi_idx_q)
            3'd0: psi_onehot = 8'b00000001;
            3'd1: psi_onehot = 8'b00000010;
            3'd2: psi_onehot = 8'b00000100;
            3'd3: psi_onehot = 8'b00001000;
            3'd4: psi_onehot = 8'b00010000;
            3'd5: psi_onehot = 8'b00100000;
            3'd6: psi_onehot = 8'b01000000;
            3'd7: psi_onehot = 8'b10000000;
            default: psi_onehot = 8'b00000000;
        endcase
        
        unique case (omega_idx_q)
            3'd0: omega_onehot = 8'b00000001;
            3'd1: omega_onehot = 8'b00000010;
            3'd2: omega_onehot = 8'b00000100;
            3'd3: omega_onehot = 8'b00001000;
            3'd4: omega_onehot = 8'b00010000;
            3'd5: omega_onehot = 8'b00100000;
            3'd6: omega_onehot = 8'b01000000;
            3'd7: omega_onehot = 8'b10000000;
            default: omega_onehot = 8'b00000000;
        endcase    
    end
    multiplier #(.DATA_WIDTH(PQLEN), .LOG_R(LOG_R)) U_UPDATE_TWIDDLE(
        .op0_i(twiddle_q),
        .op1_i(omega),
        .q_i(prime_q),
        .q_dash_i(prime_dash_q),
        .res_o(twiddle_mul)  
    ); 
    
    multiplier #(.DATA_WIDTH(PQLEN), .LOG_R(LOG_R)) U_UPDATE_OMEGA(
        .op0_i(omega),
        .op1_i(omega),
        .q_i(prime_q),
        .q_dash_i(prime_dash_q),
        .res_o(omega_mul)  
    );   
     
    assign twiddle_inv = prime_q - twiddle_q;


    // Prime Register
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            prime_q <= '0;
        end else if (prime_wr_en) begin
            prime_q <= prime_d;
        end
    end

    always_comb begin
    prime_d= ispr_pq_wdata_i[0+:PQLEN];

    unique case (1'b1)
        ispr_init_i:               prime_d = '0;
        ispr_base_wr_en_i[0]:      prime_d = ispr_base_wdata_i[0+:PQLEN];
    default: ;
        endcase
    end
    
    //TODO Enable ASSERTs
    //`ASSERT(ModWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[i_word]}))
    assign prime_wr_en = ispr_init_i |
    ((ispr_addr_i == IsprPrime) & (ispr_base_wr_en_i[0] | ispr_pq_wr_en_i));



    // Prime Dash Register
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            prime_dash_q <= '0;
        end else if (prime_dash_wr_en) begin
            prime_dash_q <= prime_dash_d;
        end
    end

    always_comb begin
    prime_dash_d = ispr_pq_wdata_i[0+:PQLEN];

    unique case (1'b1)
        ispr_init_i:                prime_dash_d = '0;
        ispr_base_wr_en_i[0]:       prime_dash_d = ispr_base_wdata_i[0+:PQLEN];
    default: ;
        endcase
    end
    
    //TODO Enable ASSERTs
    //`ASSERT(ModWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[i_word]}))

    assign prime_dash_wr_en = ispr_init_i |
    ((ispr_addr_i == IsprPrimeDash) & (ispr_base_wr_en_i[0] | ispr_pq_wr_en_i));


    // Twiddle Register
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            twiddle_q <= '0;
        end else if (twiddle_wr_en) begin
            twiddle_q <= twiddle_d;
        end
    end

    always_comb begin
    twiddle_d = ispr_pq_wdata_i[0+:PQLEN];

    unique case (1'b1)
        ispr_init_i:                twiddle_d = '0;
        ispr_base_wr_en_i[0]:       twiddle_d = ispr_base_wdata_i[0+:PQLEN];
        update_twiddle_i:           twiddle_d = twiddle_mul;
        invert_twiddle_i:           twiddle_d = twiddle_inv;
        set_twiddle_as_psi_i:       twiddle_d = psi;
    default: ;
        endcase
    end
    
    //TODO Enable ASSERTs
    //`ASSERT(ModWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[i_word]}))

    assign twiddle_wr_en = ispr_init_i |
    update_twiddle_i | invert_twiddle_i | set_twiddle_as_psi_i |
    ((ispr_addr_i == IsprTwiddle) & (ispr_base_wr_en_i[0] | ispr_pq_wr_en_i));


    // Omega Register
    for (genvar i_word = 0; i_word < BaseWordsPerPQLEN; i_word++) begin : g_omega_words
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) begin
                omega_q[i_word*32+:32] <= '0;
            end else if (omega_wr_en[i_word]) begin
                omega_q[i_word*32+:32] <= omega_d[i_word*32+:32];
            end
        end
    
        always_comb begin
            omega_d[i_word*32+:32] = ispr_pq_wdata_i[i_word*32+:32];
        
            unique case (1'b1)
                ispr_init_i:                omega_d[i_word*32+:32] = '0;
                ispr_base_wr_en_i[i_word]:  omega_d[i_word*32+:32] = ispr_base_wdata_i;
                update_omega_i:             omega_d[i_word*32+:32] = omega_mul;
            default: ;
            endcase
        end
    
    //TODO Enable ASSERTs
    //`ASSERT(ModWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[i_word]}))

        assign omega_wr_en[i_word] = ispr_init_i |
        (omega_onehot[i_word] & update_omega_i) | 
        ((ispr_addr_i == IsprOmega) & (ispr_base_wr_en_i[i_word] | ispr_pq_wr_en_i));
    end


    // Psi Register
    for (genvar i_word = 0; i_word < BaseWordsPerPQLEN; i_word++) begin : g_psi_words
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) begin
                psi_q[i_word*32+:32] <= '0;
            end else if (psi_wr_en[i_word]) begin
                psi_q[i_word*32+:32] <= psi_d[i_word*32+:32];
            end
        end
    
        always_comb begin
            psi_d[i_word*32+:32] = ispr_pq_wdata_i[i_word*32+:32];
        
            unique case (1'b1)
                ispr_init_i:                psi_d[i_word*32+:32] = '0;
                ispr_base_wr_en_i[i_word]:  psi_d[i_word*32+:32] = ispr_base_wdata_i;
                update_psi_i:               psi_d[i_word*32+:32] = omega;
            default: ;
            endcase
        end
        
        //TODO Enable ASSERTs
        //`ASSERT(ModWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[i_word]}))
    
        assign psi_wr_en[i_word] = ispr_init_i |
        (psi_onehot[i_word] & update_psi_i) | 
        ((ispr_addr_i == IsprPsi) & (ispr_base_wr_en_i[i_word] | ispr_pq_wr_en_i));
    end

    // Omega Idx Register
    assign omega_idx_inc = omega_idx_q + 1;
    
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            omega_idx_q <= '0;
        end else if (omega_idx_wr_en) begin
            omega_idx_q <= omega_idx_d;
        end
    end
    
    always_comb begin
        omega_idx_d= ispr_pq_wdata_i[0+:3];
        
        unique case (1'b1)
            ispr_init_i:               omega_idx_d = '0;
            ispr_base_wr_en_i[0]:      omega_idx_d = ispr_base_wdata_i[0+:3];
            omega_idx_inc_i:           omega_idx_d = omega_idx_inc;
        default: ;
        endcase
    end
    
    //TODO Enable ASSERTs
    //`ASSERT(ModWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[i_word]}))
    
    assign omega_idx_wr_en = ispr_init_i |
    omega_idx_inc_i | 
    ((ispr_addr_i == IsprOmegaIdx) & (ispr_base_wr_en_i[0] | ispr_pq_wr_en_i));
    
    
    // Psi Idx Register
    assign psi_idx_inc = psi_idx_q + 1;
    
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            psi_idx_q <= '0;
        end else if (psi_idx_wr_en) begin
            psi_idx_q <= psi_idx_d;
        end
    end
    
    always_comb begin
        psi_idx_d= ispr_pq_wdata_i[0+:3];
        
        unique case (1'b1)
            ispr_init_i:               psi_idx_d = '0;
            ispr_base_wr_en_i[0]:      psi_idx_d = ispr_base_wdata_i[0+:3];
            psi_idx_inc_i:             psi_idx_d = psi_idx_inc;
        default: ;
        endcase
    end
    
    //TODO Enable ASSERTs
    //`ASSERT(ModWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[i_word]}))
    
    assign psi_idx_wr_en = ispr_init_i |
    psi_idx_inc_i | 
    ((ispr_addr_i == IsprPsiIdx) & (ispr_base_wr_en_i[0] | ispr_pq_wr_en_i));


    // Const Register
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            const_q <= '0;
        end else if (const_wr_en) begin
            const_q <= const_d;
        end
    end

    always_comb begin
        const_d= ispr_pq_wdata_i[0+:PQLEN];
    
        unique case (1'b1)
            ispr_init_i:               const_d = '0;
            ispr_base_wr_en_i[0]:      const_d = ispr_base_wdata_i[0+:PQLEN];
        default: ;
        endcase
    end
    
    //TODO Enable ASSERTs
    //`ASSERT(ModWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[i_word]}))

    assign const_wr_en = ispr_init_i |
    ((ispr_addr_i == IsprConst) & (ispr_base_wr_en_i[0] | ispr_pq_wr_en_i));


    
    assign psi_o = psi;
    
    assign twiddle_o = twiddle_q;
    
    assign omega_o = omega;
    
    assign prime_o = prime_q;
    
    assign prime_dash_o = prime_dash_q;
    
    assign const_o = const_q;
    
    always_comb begin
        ispr_rdata_o = prime_q;
        
        unique case (ispr_addr_i)
            IsprPrime:        ispr_rdata_o = prime_q;
            IsprPrimeDash:    ispr_rdata_o = prime_dash_q;
            IsprTwiddle:      ispr_rdata_o = twiddle_q;
            IsprOmega:        ispr_rdata_o = omega_q;
            IsprPsi:          ispr_rdata_o = psi_q;
            IsprOmegaIdx:     ispr_rdata_o = omega_idx_q;
            IsprPsiIdx:       ispr_rdata_o = psi_idx_q;
            IsprConst:        ispr_rdata_o = const_q;
            default: ;
        endcase
    end


endmodule: twiddle_update
