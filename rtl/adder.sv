`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: Technische Universität München (TUM) / Fraunhofer Institute for Applied and Integrated Security (AISEC)
// Engineer: Tobias Stelzer (tobias.stelzer@aisec.fraunhofer.de , tobias.stelzer@tum.de)
// 
// Create Date: 04/20/2022 03:32:55 PM
// Design Name: PQ_ALU
// Module Name: adder
// Project Name: 2022-MA-PQ-ALU-OpenTitan
// Target Devices: 
// Tool Versions: 
// Description: 
//  Implementation of (a + b) mod q
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module adder
#(
    parameter DATA_WIDTH = 32
)
(
    input   logic   [DATA_WIDTH-1:0]    op0_i,
    input   logic   [DATA_WIDTH-1:0]    op1_i,
    input   logic   [DATA_WIDTH-1:0]    q_i,
    output  logic   [DATA_WIDTH-1:0]    res_o
);

    logic   [DATA_WIDTH-1:0]    add;
    logic   [DATA_WIDTH-1:0]    sub;

always_comb
begin    
    add = op0_i + op1_i;
    sub = add - q_i;
    res_o = (add < q_i) ? add : sub;
end

endmodule: adder
