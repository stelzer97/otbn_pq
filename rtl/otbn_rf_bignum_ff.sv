// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

/**
 * ExtWLEN (312b) Wide Register File (WDRs)
 *
 * ExtWLEN allows bits to provide integrity checking to WLEN words on a 32-bit granule. Integrity
 * generation/checking implemented in wrapping otbn_rf_bignum module
 *
 * Features:
 * - 2 read ports
 * - 1 write port
 * - Half (WLEN) word write enables
 */
module otbn_rf_bignum_ff
  import otbn_pkg::*;
(
  input  logic             clk_i,
  input  logic             rst_ni,

  input  logic [WdrAw-1:0]   wr_addr_a_i,
  input  logic [7:0]         wr_en_a_i,
  input  logic [ExtWLEN-1:0] wr_data_a_i,

  input  logic [WdrAw-1:0]   wr_addr_b_i,
  input  logic [7:0]         wr_en_b_i,
  input  logic [ExtWLEN-1:0] wr_data_b_i,

  input  logic [WdrAw-1:0]   rd_addr_a_i,
  output logic [ExtWLEN-1:0] rd_data_a_o,

  input  logic [WdrAw-1:0]   rd_addr_b_i,
  output logic [ExtWLEN-1:0] rd_data_b_o
);
  logic [ExtWLEN-1:0] rf [NWdr];
  logic [7:0]         we_onehot_a [NWdr];
  logic [7:0]         we_onehot_b [NWdr];

  for (genvar i = 0; i < NWdr; i++) begin : g_rf
    assign we_onehot_a[i] = wr_en_a_i & {8{wr_addr_a_i == i}};
    assign we_onehot_b[i] = wr_en_b_i & {8{wr_addr_b_i == i}};
    //ToDo
    // Split registers into halves for clear seperation for the enable terms
    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        rf[i][0+:ExtWLEN/8] <= '0;
      end else if (we_onehot_a[i][0]) begin
        rf[i][0+:ExtWLEN/8] <= wr_data_a_i[0+:ExtWLEN/8];
      end else if (we_onehot_b[i][0]) begin
        rf[i][0+:ExtWLEN/8] <= wr_data_b_i[0+:ExtWLEN/8];
      end
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        rf[i][ExtWLEN/8+:ExtWLEN/8] <= '0;
      end else if (we_onehot_a[i][1]) begin
        rf[i][ExtWLEN/8+:ExtWLEN/8] <= wr_data_a_i[ExtWLEN/8+:ExtWLEN/8];
      end else if (we_onehot_b[i][1]) begin
        rf[i][ExtWLEN/8+:ExtWLEN/8] <= wr_data_b_i[ExtWLEN/8+:ExtWLEN/8];
      end
    end
    
    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        rf[i][ExtWLEN/8*2+:ExtWLEN/8] <= '0;
      end else if (we_onehot_a[i][2]) begin
        rf[i][ExtWLEN/8*2+:ExtWLEN/8] <= wr_data_a_i[ExtWLEN/8*2+:ExtWLEN/8];
      end else if (we_onehot_b[i][2]) begin
        rf[i][ExtWLEN/8*2+:ExtWLEN/8] <= wr_data_b_i[ExtWLEN/8*2+:ExtWLEN/8];
      end
    end    

    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        rf[i][ExtWLEN/8*3+:ExtWLEN/8] <= '0;
      end else if (we_onehot_a[i][3]) begin
        rf[i][ExtWLEN/8*3+:ExtWLEN/8] <= wr_data_a_i[ExtWLEN/8*3+:ExtWLEN/8];
      end else if (we_onehot_b[i][3]) begin
        rf[i][ExtWLEN/8*3+:ExtWLEN/8] <= wr_data_b_i[ExtWLEN/8*3+:ExtWLEN/8];
      end
    end 

    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        rf[i][ExtWLEN/8*4+:ExtWLEN/8] <= '0;
      end else if (we_onehot_a[i][4]) begin
        rf[i][ExtWLEN/8*4+:ExtWLEN/8] <= wr_data_a_i[ExtWLEN/8*4+:ExtWLEN/8];
      end else if (we_onehot_b[i][4]) begin
        rf[i][ExtWLEN/8*4+:ExtWLEN/8] <= wr_data_b_i[ExtWLEN/8*4+:ExtWLEN/8];
      end
    end 

    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        rf[i][ExtWLEN/8*5+:ExtWLEN/8] <= '0;
      end else if (we_onehot_a[i][5]) begin
        rf[i][ExtWLEN/8*5+:ExtWLEN/8] <= wr_data_a_i[ExtWLEN/8*5+:ExtWLEN/8];
      end else if (we_onehot_b[i][5]) begin
        rf[i][ExtWLEN/8*5+:ExtWLEN/8] <= wr_data_b_i[ExtWLEN/8*5+:ExtWLEN/8];
      end
    end 

    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        rf[i][ExtWLEN/8*6+:ExtWLEN/8] <= '0;
      end else if (we_onehot_a[i][6]) begin
        rf[i][ExtWLEN/8*6+:ExtWLEN/8] <= wr_data_a_i[ExtWLEN/8*6+:ExtWLEN/8];
      end else if (we_onehot_b[i][6]) begin
        rf[i][ExtWLEN/8*6+:ExtWLEN/8] <= wr_data_b_i[ExtWLEN/8*6+:ExtWLEN/8];
      end
    end 
    
    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        rf[i][ExtWLEN/8*7+:ExtWLEN/8] <= '0;
      end else if (we_onehot_a[i][7]) begin
        rf[i][ExtWLEN/8*7+:ExtWLEN/8] <= wr_data_a_i[ExtWLEN/8*7+:ExtWLEN/8];
      end else if (we_onehot_b[i][7]) begin
        rf[i][ExtWLEN/8*7+:ExtWLEN/8] <= wr_data_b_i[ExtWLEN/8*7+:ExtWLEN/8];
      end
    end 
    
  end

  assign rd_data_a_o = rf[rd_addr_a_i];
  assign rd_data_b_o = rf[rd_addr_b_i];
endmodule
