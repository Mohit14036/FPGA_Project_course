`timescale 1ns / 1ps

module uart_top 
#(
    parameter DBITS   = 8,
              SB_TICK = 16,
              BR_LIMIT = 651,
              BR_BITS  = 10,
              FIFO_EXP = 5
)
(
    input  clk_100MHz,
    input  reset,

    input  read_uart,      // BUTTON 1 → pop + XOR
    input  write_uart,     // BUTTON 2 → send via TX
    input write_data,
    input  rx,
    output tx,
    output reg key,
    output reg out,
    output rx_full,
    output rx_empty,
    output [7:0] read_data
);

    // UART signals
    wire tick;
    wire rx_done_tick;
    wire tx_done_tick;
    wire tx_empty;

    wire [7:0] rx_data_raw;
    wire [7:0] tx_fifo_out;

    //----------------------------------------------
    // Baud generator
    //----------------------------------------------
    baud_rate_generator #(.M(BR_LIMIT), .N(BR_BITS)) baud_gen (
        .clk_100MHz(clk_100MHz),
        .reset(reset),
        .tick(tick)
    );

    //----------------------------------------------
    // UART Receiver
    //----------------------------------------------
    uart_receiver #(.DBITS(DBITS), .SB_TICK(SB_TICK)) RX (
        .clk_100MHz(clk_100MHz),
        .reset(reset),
        .rx(rx),
        .sample_tick(tick),
        .data_ready(rx_done_tick),
        .data_out(rx_data_raw)
    );

    //----------------------------------------------
    // UART Transmitter
    //----------------------------------------------
    uart_transmitter #(.DBITS(DBITS), .SB_TICK(SB_TICK)) TX (
        .clk_100MHz(clk_100MHz),
        .reset(reset),
        .tx_start(~tx_empty),
        .sample_tick(tick),
        .data_in(tx_fifo_out),
        .tx_done(tx_done_tick),
        .tx(tx)
    );

    //----------------------------------------------
    // RX FIFO
    //----------------------------------------------
    reg pop_rx_fifo;

    fifo #(.DATA_SIZE(8), .ADDR_SPACE_EXP(FIFO_EXP)) FIFO_RX (
        .clk(clk_100MHz),
        .reset(reset),
        .write_to_fifo(rx_done_tick),
        .read_from_fifo(pop_rx_fifo),
        .write_data_in(rx_data_raw),
        .read_data_out(read_data),
        .empty(rx_empty),
        .full(rx_full)
    );

    //----------------------------------------------
    // TX FIFO
    //----------------------------------------------
    reg push_tx_fifo;
    reg [7:0] processed_data;     // STORED RESULT

    fifo #(.DATA_SIZE(8), .ADDR_SPACE_EXP(FIFO_EXP)) FIFO_TX (
        .clk(clk_100MHz),
        .reset(reset),
        .write_to_fifo(push_tx_fifo),
        .read_from_fifo(tx_done_tick),
        .write_data_in(processed_data),
        .read_data_out(tx_fifo_out),
        .empty(tx_empty),
        .full()
    );

   // ============================================================
// NEW MAIN LOGIC: single button read_uart loads both KEY then PT
// ============================================================

reg [63:0] key_buf;
reg [63:0] pt_buf;
reg [63:0] ct_buf;

reg [3:0] byte_cnt;     // counts 0..7
reg       loading_key;  // 1 → currently collecting key
reg       loading_pt;   // 1 → collecting plaintext

// Blowfish interface signals
reg        bf_start_encrypt;
wire       bf_done_encrypt;
wire [63:0] bf_ct_out;

// instantiate your blowfish module
bfp BF(
    .clk(clk_100MHz),
    .rst_n(~reset),
    .key_in(key_buf),
    .start_encrypt(bf_start_encrypt),
    .pt_in(pt_buf),
    .ct_out(bf_ct_out),
    .done_encrypt(bf_done_encrypt)
);

reg [3:0] nibble_in;
reg [3:0] nibble_out;
reg [3:0] nib_idx; 
always @(*) begin
    if (read_data >= "0" && read_data <= "9")
        nibble_in = read_data - 8'h30;       // '0'=0 ... '9'=9
    else if (read_data >= "A" && read_data <= "F")
        nibble_in = read_data - 8'h37;       // 'A'=10 ... 'F'=15
    else if (read_data >= "a" && read_data <= "f")
        nibble_in = read_data - 8'h57;       // 'a'=10 ... 'f'=15
    else
        nibble_in = 4'h0;
end


always @(posedge clk_100MHz or posedge reset) begin
    if (reset) begin
        pop_rx_fifo    <= 0;
        push_tx_fifo   <= 0;
        processed_data <= 0;

        key_buf        <= 0;
        pt_buf         <= 0;
        ct_buf         <= 0;

        byte_cnt       <= 0;
        loading_key    <= 1;   // FIRST read is always KEY
        loading_pt     <= 0;
        nibble_out<=4'b0;
        bf_start_encrypt <= 0;
        key<=1'b0;
        out<=1'b0;

    end else begin
        pop_rx_fifo    <= 0;
        push_tx_fifo   <= 0;
       

        // --------------------------
        // STEP 1: LOAD KEY (first 8 bytes)
        // --------------------------
        if (read_uart && !rx_empty && loading_key) begin
            pop_rx_fifo <= 1;
            key_buf <= {key_buf[59:0], nibble_in};
            byte_cnt <= byte_cnt + 1;

            if (byte_cnt == 4'd15) begin
                loading_key <= 0;
                loading_pt  <= 1;
                byte_cnt    <= 0;
                key<=1'b1; // kick key expansion
            end
        end

       

        if (read_uart && !rx_empty && loading_pt) begin
            pop_rx_fifo <= 1;
            pt_buf <= {pt_buf[59:0], nibble_in};
            byte_cnt <= byte_cnt + 1;

            if (byte_cnt == 4'd15) begin
                loading_pt <= 0;
                byte_cnt   <= 0;
                bf_start_encrypt <= 1; // kick encryption
            end
        end

        // --------------------------
        // STEP 4: GET CIPHERTEXT
        // --------------------------
        if (bf_done_encrypt) begin
            ct_buf <= bf_ct_out;
            bf_start_encrypt<=1'b0;
            out<=1'b1;
        end

        // --------------------------
        // STEP 5: SEND CIPHERTEXT (8 bytes) using write_uart
        // --------------------------
          // 0..15

       // STEP 5: SEND CIPHERTEXT NIBBLE BY NIBBLE
if (write_uart && out) begin
    // extract nibble based on nib_idx
    nibble_out <= ct_buf[63 - nib_idx*4 -: 4];

    // convert to ASCII
    if (nibble_out <= 9)
        processed_data = nibble_out + 8'h30;
    else
        processed_data = nibble_out + 8'h37;

    push_tx_fifo <= 1;

    // move to next nibble
    if (nib_idx == 4'd15) begin
        nib_idx <= 0;
        out <= 0; // finished sending whole ciphertext
    end else begin
        nib_idx <= nib_idx + 1;
    end
end

    end
end


endmodule
