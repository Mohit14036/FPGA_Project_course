`timescale 1ns/1ps

module tb_blowfish_fixed;

    reg clk;
    reg rst_n;
    reg start_encrypt;
    reg [63:0] pt_in;
    reg [63:0] key_in;
    wire [63:0] ct_out;
    wire done_encrypt;

    // DUT instance (ONLY encryption, NO key expansion)
    blowfish DUT (
        .clk(clk),
        .rst_n(rst_n),
        .start_encrypt(start_encrypt),
        .pt_in(pt_in),
        .ct_out(ct_out),
        .done_encrypt(done_encrypt),
        .key_in(key_in)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;   // 100 MHz clock (10 ns period)
    end

    initial begin
        // Initial values
        rst_n = 0;
        start_encrypt = 0;
        pt_in = 64'h0123456789ABCDEF;   // test vector
                key_in = 64'hAABB09182736CCDD;

        // Release reset
        #20 rst_n = 1;

        // Give time
        #20;

        // Start encryption pulse
        start_encrypt = 1;

        // Wait for encryption to finish
        wait(done_encrypt);

        // Display result
        $display("-----------------------------------------------------");
        $display(" FIXED BLOWFISH ENCRYPTION TEST");
        $display(" PLAINTEXT   = %016h", pt_in);
        $display(" CIPHERTEXT  = %016h", ct_out);
        $display("-----------------------------------------------------");

        #20;
        $finish;
    end

endmodule
