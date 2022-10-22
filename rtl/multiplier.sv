`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: Technische Universität München (TUM) / Fraunhofer Institute for Applied and Integrated Security (AISEC)
// Engineer: Tobias Stelzer (tobias.stelzer@aisec.fraunhofer.de , tobias.stelzer@tum.de)
// 
// Create Date: 04/23/2022 11:10:35 AM
// Design Name: PQ_ALU 
// Module Name: multiplier
// Project Name: 2022-MA-PQ-ALU-OpenTitan
// Target Devices: 
// Tool Versions: 
// Description: 
//  Implementation of modular multiplication in Montgomery Domain
//  (a * b) R^(-1) mod q
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module multiplier
#(
    parameter DATA_WIDTH = 32,
    parameter LOG_R = 32
)
(
    input   logic   [DATA_WIDTH-1:0]    op0_i,
    input   logic   [DATA_WIDTH-1:0]    op1_i,
    input   logic   [DATA_WIDTH-1:0]    q_i,
    input   logic   [LOG_R-1:0]         q_dash_i,
    output  logic   [DATA_WIDTH-1:0]    res_o   
);

logic   [2*DATA_WIDTH-1:0]          p;
logic   [2*LOG_R-1:0]               m;
logic   [2*DATA_WIDTH+LOG_R:0]      s;
logic   [DATA_WIDTH-1:0]            t;

always_comb
begin
    p = op0_i * op1_i;
    m = p[LOG_R-1:0] * q_dash_i;
    s = p + (m[LOG_R-1:0] * q_i);
    t = s[LOG_R+DATA_WIDTH-1:LOG_R];
    if (q_i <= t) begin
        t = t-q_i;
    end
end

assign res_o = t;

endmodule: multiplier
