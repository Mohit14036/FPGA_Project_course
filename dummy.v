`timescale 1ns / 1ps

module uart_top 
#(
    parameter DBITS   = 8,      // number of data bits in a word
              SB_TICK = 16,     // number of stop bit / oversampling ticks
              BR_LIMIT = 651,   // baud rate generator counter limit
              BR_BITS  = 10,    // number of baud rate generator counter bits
              FIFO_EXP = 5      // exponent for number of FIFO addresses (2^5 = 32)
)
(
    input  clk_100MHz,          // FPGA clock
    input  reset,               // reset

    input  read_uart,           // button
    input  write_uart,          // button
    input  rx,                  // serial data in
    input  [DBITS-1:0] write_data, // data to Tx FIFO

    output rx_full,             // Rx FIFO full
    output rx_empty,            // Rx FIFO empty
    output tx,                  // serial data out
    output [DBITS-1:0] read_data // data from Rx FIFO
);

    // ----------------------------------------------------
    // Connection Signals
    // ----------------------------------------------------
    wire tick;
    wire rx_done_tick;
    wire tx_done_tick;
    wire tx_empty;
    wire tx_fifo_not_empty;
    wire [DBITS-1:0] tx_fifo_out;
    wire [DBITS-1:0] rx_data_out;

    // ----------------------------------------------------
    // Baud Rate Generator
    // ----------------------------------------------------
    baud_rate_generator 
    #(
        .M(BR_LIMIT),
        .N(BR_BITS)
    )
    BAUD_RATE_GEN 
    (
        .clk_100MHz(clk_100MHz),
        .reset(reset),
        .tick(tick)
    );

    // ----------------------------------------------------
    // UART Receiver
    // ----------------------------------------------------
    uart_receiver 
    #(
        .DBITS(DBITS),
        .SB_TICK(SB_TICK)
    )
    UART_RX_UNIT 
    (
        .clk_100MHz(clk_100MHz),
        .reset(reset),
        .rx(rx),
        .sample_tick(tick),
        .data_ready(rx_done_tick),
        .data_out(rx_data_out)
    );

    // ----------------------------------------------------
    // UART Transmitter
    // ----------------------------------------------------
    uart_transmitter 
    #(
        .DBITS(DBITS),
        .SB_TICK(SB_TICK)
    )
    UART_TX_UNIT 
    (
        .clk_100MHz(clk_100MHz),
        .reset(reset),
        .tx_start(tx_fifo_not_empty),
        .sample_tick(tick),
        .data_in(tx_fifo_out),
        .tx_done(tx_done_tick),
        .tx(tx)
    );

    // ----------------------------------------------------
    // RX FIFO
    // ----------------------------------------------------
    fifo 
    #(
        .DATA_SIZE(DBITS),
        .ADDR_SPACE_EXP(FIFO_EXP)
    )
    FIFO_RX_UNIT
    (
        .clk(clk_100MHz),
        .reset(reset),
        .write_to_fifo(rx_done_tick),
        .read_from_fifo(read_uart),
        .write_data_in(rx_data_out),
        .read_data_out(read_data),
        .empty(rx_empty),
        .full(rx_full)
    );

    // ----------------------------------------------------
    // TX FIFO
    // ----------------------------------------------------
    fifo
    #(
        .DATA_SIZE(DBITS),
        .ADDR_SPACE_EXP(FIFO_EXP)
    )
    FIFO_TX_UNIT
    (
        .clk(clk_100MHz),
        .reset(reset),
        .write_to_fifo(write_uart),
        .read_from_fifo(tx_done_tick),
        .write_data_in(write_data),
        .read_data_out(tx_fifo_out),
        .empty(tx_empty),
        .full()           // intentionally unused
    );

    // ----------------------------------------------------
    // Signal Logic
    // ----------------------------------------------------
    assign tx_fifo_not_empty = ~tx_empty;

endmodule
