`timescale 1ns/1ps

module dummybf2 (
    input        clk,
    input        rst_n,
    input        start_expand,
    input [63:0] key_in,        // ---- FIXED 64-bit KEY ----
    input        start_encrypt,
    input [63:0] pt_in,
    output reg [63:0] ct_out,
    output reg   done_expand,
    output reg   done_encrypt
);
    
    integer i, idx;
    
    reg [31:0] P [0:17];
    reg [31:0] P1 [0:17];
    
    
    initial begin
        P[0]  = 32'h243F6A88; P[1]  = 32'h85A308D3; P[2]  = 32'h13198A2E; P[3]  = 32'h03707344;
        P[4]  = 32'hA4093822; P[5]  = 32'h299F31D0; P[6]  = 32'h082EFA98; P[7]  = 32'hEC4E6C89;
        P[8]  = 32'h452821E6; P[9]  = 32'h38D01377; P[10] = 32'hBE5466CF; P[11] = 32'h34E90C6C;
        P[12] = 32'hC0AC29B7; P[13] = 32'hC97C50DD; P[14] = 32'h3F84D5B5; P[15] = 32'hB5470917;
        P[16] = 32'h9216D5D9; P[17] = 32'h8979FB1B;
    end



      initial begin
        P1[0]  = 32'h243F6A88; P1[1]  = 32'h85A308D3; P1[2]  = 32'h13198A2E; P1[3]  = 32'h03707344;
        P1[4]  = 32'hA4093822; P1[5]  = 32'h299F31D0; P1[6]  = 32'h082EFA98; P1[7]  = 32'hEC4E6C89;
        P1[8]  = 32'h452821E6; P1[9]  = 32'h38D01377; P1[10] = 32'hBE5466CF; P1[11] = 32'h34E90C6C;
        P1[12] = 32'hC0AC29B7; P1[13] = 32'hC97C50DD; P1[14] = 32'h3F84D5B5; P1[15] = 32'hB5470917;
        P1[16] = 32'h9216D5D9; P1[17] = 32'h8979FB1B;
    end

    // -------------------------------------------------------------
    // S-boxes (1024 entries)
    // -------------------------------------------------------------
    reg [31:0] S_all [0:1023];
    reg [31:0] S0 [0:255];
    reg [31:0] S1 [0:255];
    reg [31:0] S2 [0:255];
    reg [31:0] S3 [0:255];
    
    
    
    // ---------------- S0 ----------------
initial begin
    S0[0] = 32'hD1310BA6;
    S0[1] = 32'h98DFB5AC;
    S0[2] = 32'h2FFD72DB;
    S0[3] = 32'hD01ADFB7;
    S0[4] = 32'hB8E1AFED;
    S0[5] = 32'h6A267E96;
    S0[6] = 32'hBA7C9045;
    S0[7] = 32'hF12C7F99;
    S0[8] = 32'h24A19947;
    S0[9] = 32'hB3916CF7;
    S0[10] = 32'h0801F2E2;
    S0[11] = 32'h858EFC16;
    S0[12] = 32'h636920D8;
    S0[13] = 32'h71574E69;
    S0[14] = 32'hA458FEA3;
    S0[15] = 32'hF4933D7E;
    S0[16] = 32'h0D95748F;
    S0[17] = 32'h728EB658;
    S0[18] = 32'h718BCD58;
    S0[19] = 32'h82154AEE;
    S0[20] = 32'h7B54A41D;
    S0[21] = 32'hC25A59B5;
    S0[22] = 32'h9C30D539;
    S0[23] = 32'h2AF26013;
    S0[24] = 32'hC5D1B023;
    S0[25] = 32'h286085F0;
    S0[26] = 32'hCA417918;
    S0[27] = 32'hB8DB38EF;
    S0[28] = 32'h8E79DCB0;
    S0[29] = 32'h603A180E;
    S0[30] = 32'h6C9E0E8B;
    S0[31] = 32'hB01E8A3E;
    S0[32] = 32'hD71577C1;
    S0[33] = 32'hBD314B27;
    S0[34] = 32'h78AF2FDA;
    S0[35] = 32'h55605C60;
    S0[36] = 32'hE65525F3;
    S0[37] = 32'hAA55AB94;
    S0[38] = 32'h57489862;
    S0[39] = 32'h63E81440;
    S0[40] = 32'h55CA396A;
    S0[41] = 32'h2AAB10B6;
    S0[42] = 32'hB4CC5C34;
    S0[43] = 32'h1141E8CE;
    S0[44] = 32'hA15486AF;
    S0[45] = 32'h7C72E993;
    S0[46] = 32'hB3EE1411;
    S0[47] = 32'h636FBC2A;
    S0[48] = 32'h2BA9C55D;
    S0[49] = 32'h741831F6;
    S0[50] = 32'hCE5C3E16;
    S0[51] = 32'h9B87931E;
    S0[52] = 32'hAFD6BA33;
    S0[53] = 32'h6C24CF5C;
    S0[54] = 32'h7A325381;
    S0[55] = 32'h28958677;
    S0[56] = 32'h3B8F4898;
    S0[57] = 32'h6B4BB9AF;
    S0[58] = 32'hC4BFE81B;
    S0[59] = 32'h66282193;
    S0[60] = 32'h61D809CC;
    S0[61] = 32'hFB21A991;
    S0[62] = 32'h487CAC60;
    S0[63] = 32'h5DEC8032;
    S0[64] = 32'hEF845D5D;
    S0[65] = 32'hE98575B1;
    S0[66] = 32'hDC262302;
    S0[67] = 32'hEB651B88;
    S0[68] = 32'h23893E81;
    S0[69] = 32'hD396ACC5;
    S0[70] = 32'h0F6D6FF3;
    S0[71] = 32'h83F44239;
    S0[72] = 32'h2E0B4482;
    S0[73] = 32'hA4842004;
    S0[74] = 32'h69C8F04A;
    S0[75] = 32'h9E1F9B5E;
    S0[76] = 32'h21C66842;
    S0[77] = 32'hF6E96C9A;
    S0[78] = 32'h670C9C61;
    S0[79] = 32'hABD388F0;
    S0[80] = 32'h6A51A0D2;
    S0[81] = 32'hD8542F68;
    S0[82] = 32'h960FA728;
    S0[83] = 32'hAB5133A3;
    S0[84] = 32'h6EEF0B6C;
    S0[85] = 32'h137A3BE4;
    S0[86] = 32'hBA3BF050;
    S0[87] = 32'h7EFB2A98;
    S0[88] = 32'hA1F1651D;
    S0[89] = 32'h39AF0176;
    S0[90] = 32'h66CA593E;
    S0[91] = 32'h82430E88;
    S0[92] = 32'h8CEE8619;
    S0[93] = 32'h456F9FB4;
    S0[94] = 32'h7D84A5C3;
    S0[95] = 32'h3B8B5EBE;
    S0[96] = 32'hE06F75D8;
    S0[97] = 32'h85C12073;
    S0[98] = 32'h401A449F;
    S0[99] = 32'h56C16AA6;
    S0[100] = 32'h4ED3AA62;
    S0[101] = 32'h363F7706;
    S0[102] = 32'h1BFEDF72;
    S0[103] = 32'h429B023D;
    S0[104] = 32'h37D0D724;
    S0[105] = 32'hD00A1248;
    S0[106] = 32'hDB0FEAD3;
    S0[107] = 32'h49F1C09B;
    S0[108] = 32'h075372C9;
    S0[109] = 32'h80991B7B;
    S0[110] = 32'h25D479D8;
    S0[111] = 32'hF6E8DEF7;
    S0[112] = 32'hE3FE501A;
    S0[113] = 32'hB6794C3B;
    S0[114] = 32'h976CE0BD;
    S0[115] = 32'h04C006BA;
    S0[116] = 32'hC1A94FB6;
    S0[117] = 32'h409F60C4;
    S0[118] = 32'h5E5C9EC2;
    S0[119] = 32'h196A2463;
    S0[120] = 32'h68FB6FAF;
    S0[121] = 32'h3E6C53B5;
    S0[122] = 32'h1339B2EB;
    S0[123] = 32'h3B52EC6F;
    S0[124] = 32'h6DFC511F;
    S0[125] = 32'h9B30952C;
    S0[126] = 32'hCC814544;
    S0[127] = 32'hAF5EBD09;
    S0[128] = 32'hBEE3D004;
    S0[129] = 32'hDE334AFD;
    S0[130] = 32'h660F2807;
    S0[131] = 32'h192E4BB3;
    S0[132] = 32'hC0CBA857;
    S0[133] = 32'h45C8740F;
    S0[134] = 32'hD20B5F39;
    S0[135] = 32'hB9D3FBDB;
    S0[136] = 32'h5579C0BD;
    S0[137] = 32'h1A60320A;
    S0[138] = 32'hD6A100C6;
    S0[139] = 32'h402C7279;
    S0[140] = 32'h679F25FE;
    S0[141] = 32'hFB1FA3CC;
    S0[142] = 32'h8EA5E9F8;
    S0[143] = 32'hDB3222F8;
    S0[144] = 32'h3C7516DF;
    S0[145] = 32'hFD616B15;
    S0[146] = 32'h2F501EC8;
    S0[147] = 32'hAD0552AB;
    S0[148] = 32'h323DB5FA;
    S0[149] = 32'hFD238760;
    S0[150] = 32'h53317B48;
    S0[151] = 32'h3E00DF82;
    S0[152] = 32'h9E5C57BB;
    S0[153] = 32'hCA6F8CA0;
    S0[154] = 32'h1A87562E;
    S0[155] = 32'hDF1769DB;
    S0[156] = 32'hD542A8F6;
    S0[157] = 32'h287EFFC3;
    S0[158] = 32'hAC6732C6;
    S0[159] = 32'h8C4F5573;
    S0[160] = 32'h695B27B0;
    S0[161] = 32'hBBCA58C8;
    S0[162] = 32'hE1FFA35D;
    S0[163] = 32'hB8F011A0;
    S0[164] = 32'h10FA3D98;
    S0[165] = 32'hFD2183B8;
    S0[166] = 32'h4AFCB56C;
    S0[167] = 32'h2DD1D35B;
    S0[168] = 32'h9A53E479;
    S0[169] = 32'hB6F84565;
    S0[170] = 32'hD28E49BC;
    S0[171] = 32'h4BFB9790;
    S0[172] = 32'hE1DDF2DA;
    S0[173] = 32'hA4CB7E33;
    S0[174] = 32'h62FB1341;
    S0[175] = 32'hCEE4C6E8;
    S0[176] = 32'hEF20CADA;
    S0[177] = 32'h36774C01;
    S0[178] = 32'hD07E9EFE;
    S0[179] = 32'h2BF11FB4;
    S0[180] = 32'h95DBDA4D;
    S0[181] = 32'hAE909198;
    S0[182] = 32'hEAAD8E71;
    S0[183] = 32'h6B93D5A0;
    S0[184] = 32'hD08ED1D0;
    S0[185] = 32'hAFC725E0;
    S0[186] = 32'h8E3C5B2F;
    S0[187] = 32'h8E7594B7;
    S0[188] = 32'h8FF6E2FB;
    S0[189] = 32'hF2122B64;
    S0[190] = 32'h8888B812;
    S0[191] = 32'h900DF01C;
    S0[192] = 32'h4FAD5EA0;
    S0[193] = 32'h688FC31C;
    S0[194] = 32'hD1CFF191;
    S0[195] = 32'hB3A8C1AD;
    S0[196] = 32'h2F2F2218;
    S0[197] = 32'hBE0E1777;
    S0[198] = 32'hEA752DFE;
    S0[199] = 32'h8B021FA1;
    S0[200] = 32'hE5A0CC0F;
    S0[201] = 32'hB56F74E8;
    S0[202] = 32'h18ACF3D6;
    S0[203] = 32'hCE89E299;
    S0[204] = 32'hB4A84FE0;
    S0[205] = 32'hFD13E0B7;
    S0[206] = 32'h7CC43B81;
    S0[207] = 32'hD2ADA8D9;
    S0[208] = 32'h165FA266;
    S0[209] = 32'h80957705;
    S0[210] = 32'h93CC7314;
    S0[211] = 32'h211A1477;
    S0[212] = 32'hE6AD2065;
    S0[213] = 32'h77B5FA86;
    S0[214] = 32'hC75442F5;
    S0[215] = 32'hFB9D35CF;
    S0[216] = 32'hEBCDAF0C;
    S0[217] = 32'h7B3E89A0;
    S0[218] = 32'hD6411BD3;
    S0[219] = 32'hAE1E7E49;
    S0[220] = 32'h00250E2D;
    S0[221] = 32'h2071B35E;
    S0[222] = 32'h226800BB;
    S0[223] = 32'h57B8E0AF;
    S0[224] = 32'h2464369B;
    S0[225] = 32'hF009B91E;
    S0[226] = 32'h5563911D;
    S0[227] = 32'h59DFA6AA;
    S0[228] = 32'h78C14389;
    S0[229] = 32'hD95A537F;
    S0[230] = 32'h207D5BA2;
    S0[231] = 32'h02E5B9C5;
    S0[232] = 32'h83260376;
    S0[233] = 32'h6295CFA9;
    S0[234] = 32'h11C81968;
    S0[235] = 32'h4E734A41;
    S0[236] = 32'hB3472DCA;
    S0[237] = 32'h7B14A94A;
    S0[238] = 32'h1B510052;
    S0[239] = 32'h9A532915;
    S0[240] = 32'hD60F573F;
    S0[241] = 32'hBC9BC6E4;
    S0[242] = 32'h2B60A476;
    S0[243] = 32'h81E67400;
    S0[244] = 32'h08BA6FB5;
    S0[245] = 32'h571BE91F;
    S0[246] = 32'hF296EC6B;
    S0[247] = 32'h2A0DD915;
    S0[248] = 32'hB6636521;
    S0[249] = 32'hE7B9F9B6;
    S0[250] = 32'hFF34052E;
    S0[251] = 32'hC5855664;
    S0[252] = 32'h53B02D5D;
    S0[253] = 32'hA99F8FA1;
    S0[254] = 32'h08BA4799;
    S0[255] = 32'h6E85076A;
end

    
    
    
// ---------------- S1 ----------------
initial begin
    S1[0] = 32'h4B7A70E9;
    S1[1] = 32'hB5B32944;
    S1[2] = 32'hDB75092E;
    S1[3] = 32'hC4192623;
    S1[4] = 32'hAD6EA6B0;
    S1[5] = 32'h49A7DF7D;
    S1[6] = 32'h9CEE60B8;
    S1[7] = 32'h8FEDB266;
    S1[8] = 32'hECAA8C71;
    S1[9] = 32'h699A17FF;
    S1[10] = 32'h5664526C;
    S1[11] = 32'hC2B19EE1;
    S1[12] = 32'h193602A5;
    S1[13] = 32'h75094C29;
    S1[14] = 32'hA0591340;
    S1[15] = 32'hE4183A3E;
    S1[16] = 32'h3F54989A;
    S1[17] = 32'h5B429D65;
    S1[18] = 32'h6B8FE4D6;
    S1[19] = 32'h99F73FD6;
    S1[20] = 32'hA1D29C07;
    S1[21] = 32'hEFE830F5;
    S1[22] = 32'h4D2D38E6;
    S1[23] = 32'hF0255DC1;
    S1[24] = 32'h4CDD2086;
    S1[25] = 32'h8470EB26;
    S1[26] = 32'h6382E9C6;
    S1[27] = 32'h021ECC5E;
    S1[28] = 32'h09686B3F;
    S1[29] = 32'h3EBAEFC9;
    S1[30] = 32'h3C971814;
    S1[31] = 32'h6B6A70A1;
    S1[32] = 32'h687F3584;
    S1[33] = 32'h52A0E286;
    S1[34] = 32'hB79C5305;
    S1[35] = 32'hAA500737;
    S1[36] = 32'h3E07841C;
    S1[37] = 32'h7FDEAE5C;
    S1[38] = 32'h8E7D44EC;
    S1[39] = 32'h5716F2B8;
    S1[40] = 32'hB03ADA37;
    S1[41] = 32'hF0500C0D;
    S1[42] = 32'hF01C1F04;
    S1[43] = 32'h0200B3FF;
    S1[44] = 32'hAE0CF51A;
    S1[45] = 32'h3CB574B2;
    S1[46] = 32'h25837A58;
    S1[47] = 32'hDC0921BD;
    S1[48] = 32'hD19113F9;
    S1[49] = 32'h7CA92FF6;
    S1[50] = 32'h94324773;
    S1[51] = 32'h22F54701;
    S1[52] = 32'h3AE5E581;
    S1[53] = 32'h37C2DADC;
    S1[54] = 32'hC8B57634;
    S1[55] = 32'h9AF3DDA7;
    S1[56] = 32'hA9446146;
    S1[57] = 32'h0FD0030E;
    S1[58] = 32'hECC8C73E;
    S1[59] = 32'hA4751E41;
    S1[60] = 32'hE238CD99;
    S1[61] = 32'h3BEA0E2F;
    S1[62] = 32'h3280BBA1;
    S1[63] = 32'h183EB331;
    S1[64] = 32'h4E548B38;
    S1[65] = 32'h4F6DB908;
    S1[66] = 32'h6F420D03;
    S1[67] = 32'hF60A04BF;
    S1[68] = 32'h2CB81290;
    S1[69] = 32'h24977C79;
    S1[70] = 32'h5679B072;
    S1[71] = 32'hBCAF89AF;
    S1[72] = 32'hDE9A771F;
    S1[73] = 32'hD9930810;
    S1[74] = 32'hB38BAE12;
    S1[75] = 32'hDCCF3F2E;
    S1[76] = 32'h5512721F;
    S1[77] = 32'h2E6B7124;
    S1[78] = 32'h501ADDE6;
    S1[79] = 32'h9F84CD87;
    S1[80] = 32'h7A584718;
    S1[81] = 32'h7408DA17;
    S1[82] = 32'hBC9F9ABC;
    S1[83] = 32'hE94B7D8C;
    S1[84] = 32'hEC7AEC3A;
    S1[85] = 32'hDB851DFA;
    S1[86] = 32'h63094366;
    S1[87] = 32'hC464C3D2;
    S1[88] = 32'hEF1C1847;
    S1[89] = 32'h3215D908;
    S1[90] = 32'hDD433B37;
    S1[91] = 32'h24C2BA16;
    S1[92] = 32'h12A14D43;
    S1[93] = 32'h2A65C451;
    S1[94] = 32'h50940002;
    S1[95] = 32'h133AE4DD;
    S1[96] = 32'h71DFF89E;
    S1[97] = 32'h10314E55;
    S1[98] = 32'h81AC77D6;
    S1[99] = 32'h5F11199B;
    S1[100] = 32'h043556F1;
    S1[101] = 32'hD7A3C76B;
    S1[102] = 32'h3C11183B;
    S1[103] = 32'h5924A509;
    S1[104] = 32'hF28FE6ED;
    S1[105] = 32'h97F1FBFA;
    S1[106] = 32'h9EBABF2C;
    S1[107] = 32'h1E153C6E;
    S1[108] = 32'h86E34570;
    S1[109] = 32'hEAE96FB1;
    S1[110] = 32'h860E5E0A;
    S1[111] = 32'h5A3E2AB3;
    S1[112] = 32'h771FE71C;
    S1[113] = 32'h4E3D06FA;
    S1[114] = 32'h2965DCB9;
    S1[115] = 32'h99E71D0F;
    S1[116] = 32'h803E89D6;
    S1[117] = 32'h5266C825;
    S1[118] = 32'h2E4CC978;
    S1[119] = 32'h9C10B36A;
    S1[120] = 32'hC6150EBA;
    S1[121] = 32'h94E2EA78;
    S1[122] = 32'hA5FC3C53;
    S1[123] = 32'h1E0A2DF4;
    S1[124] = 32'hF2F74EA7;
    S1[125] = 32'h361D2B3D;
    S1[126] = 32'h1939260F;
    S1[127] = 32'h19C27960;
    S1[128] = 32'h5223A708;
    S1[129] = 32'hF71312B6;
    S1[130] = 32'hEBADFE6E;
    S1[131] = 32'hEAC31F66;
    S1[132] = 32'hE3BC4595;
    S1[133] = 32'hA67BC883;
    S1[134] = 32'hB17F37D1;
    S1[135] = 32'h018CFF28;
    S1[136] = 32'hC332DDEF;
    S1[137] = 32'hBE6C5AA5;
    S1[138] = 32'h65582185;
    S1[139] = 32'h68AB9802;
    S1[140] = 32'hEECEA50F;
    S1[141] = 32'hDB2F953B;
    S1[142] = 32'h2AEF7DAD;
    S1[143] = 32'h5B6E2F84;
    S1[144] = 32'h1521B628;
    S1[145] = 32'h29076170;
    S1[146] = 32'hECDD4775;
    S1[147] = 32'h619F1510;
    S1[148] = 32'h13CCA830;
    S1[149] = 32'hEB61BD96;
    S1[150] = 32'h0334FE1E;
    S1[151] = 32'hAA0363CF;
    S1[152] = 32'hB5735C90;
    S1[153] = 32'h4C70A239;
    S1[154] = 32'hD59E9E0B;
    S1[155] = 32'hCBAADE14;
    S1[156] = 32'hEECC86BC;
    S1[157] = 32'h60622CA7;
    S1[158] = 32'h9CAB5CAB;
    S1[159] = 32'hB2F3846E;
    S1[160] = 32'h648B1EAF;
    S1[161] = 32'h19BDF0CA;
    S1[162] = 32'hA02369B9;
    S1[163] = 32'h655ABB50;
    S1[164] = 32'h40685A32;
    S1[165] = 32'h3C2AB4B3;
    S1[166] = 32'h319EE9D5;
    S1[167] = 32'hC021B8F7;
    S1[168] = 32'h9B540B19;
    S1[169] = 32'h875FA099;
    S1[170] = 32'h95F7997E;
    S1[171] = 32'h623D7DA8;
    S1[172] = 32'hF837889A;
    S1[173] = 32'h97E32D77;
    S1[174] = 32'h11ED935F;
    S1[175] = 32'h16681281;
    S1[176] = 32'h0E358829;
    S1[177] = 32'hC7E61FD6;
    S1[178] = 32'h96DEDFA1;
    S1[179] = 32'h7858BA99;
    S1[180] = 32'h57F584A5;
    S1[181] = 32'h1B227263;
    S1[182] = 32'h9B83C3FF;
    S1[183] = 32'h1AC24696;
    S1[184] = 32'hCDB30AEB;
    S1[185] = 32'h532E3054;
    S1[186] = 32'h8FD948E4;
    S1[187] = 32'h6DBC3128;
    S1[188] = 32'h58EBF2EF;
    S1[189] = 32'h34C6FFEA;
    S1[190] = 32'hFE28ED61;
    S1[191] = 32'hEE7C3C73;
    S1[192] = 32'h5D4A14D9;
    S1[193] = 32'hE864B7E3;
    S1[194] = 32'h42105D14;
    S1[195] = 32'h203E13E0;
    S1[196] = 32'h45EEE2B6;
    S1[197] = 32'hA3AAABEA;
    S1[198] = 32'hDB6C4F15;
    S1[199] = 32'hFACB4FD0;
    S1[200] = 32'hC742F442;
    S1[201] = 32'hEF6ABBB5;
    S1[202] = 32'h654F3B1D;
    S1[203] = 32'h41CD2105;
    S1[204] = 32'hD81E799E;
    S1[205] = 32'h86854DC7;
    S1[206] = 32'hE44B476A;
    S1[207] = 32'h3D816250;
    S1[208] = 32'hCF62A1F2;
    S1[209] = 32'h5B8D2646;
    S1[210] = 32'hFC8883A0;
    S1[211] = 32'hC1C7B6A3;
    S1[212] = 32'h7F1524C3;
    S1[213] = 32'h69CB7492;
    S1[214] = 32'h47848A0B;
    S1[215] = 32'h5692B285;
    S1[216] = 32'h095BBF00;
    S1[217] = 32'hAD19489D;
    S1[218] = 32'h1462B174;
    S1[219] = 32'h23820E00;
    S1[220] = 32'h58428D2A;
    S1[221] = 32'h0C55F5EA;
    S1[222] = 32'h1DADF43E;
    S1[223] = 32'h233F7061;
    S1[224] = 32'h3372F092;
    S1[225] = 32'h8D937E41;
    S1[226] = 32'hD65FECF1;
    S1[227] = 32'h6C223BDB;
    S1[228] = 32'h7CDE3759;
    S1[229] = 32'hCBEE7460;
    S1[230] = 32'h4085F2A7;
    S1[231] = 32'hCE77326E;
    S1[232] = 32'hA6078084;
    S1[233] = 32'h19F8509E;
    S1[234] = 32'hE8EFD855;
    S1[235] = 32'h61D99735;
    S1[236] = 32'hA969A7AA;
    S1[237] = 32'hC50C06C2;
    S1[238] = 32'h5A04ABFC;
    S1[239] = 32'h800BCADC;
    S1[240] = 32'h9E447A2E;
    S1[241] = 32'hC3453484;
    S1[242] = 32'hFDD56705;
    S1[243] = 32'h0E1E9EC9;
    S1[244] = 32'hDB73DBD3;
    S1[245] = 32'h105588CD;
    S1[246] = 32'h675FDA79;
    S1[247] = 32'hE3674340;
    S1[248] = 32'hC5C43465;
    S1[249] = 32'h713E38D8;
    S1[250] = 32'h3D28F89E;
    S1[251] = 32'hF16DFF20;
    S1[252] = 32'h153E21E7;
    S1[253] = 32'h8FB03D4A;
    S1[254] = 32'hE6E39F2B;
    S1[255] = 32'hDB83ADF7;
end




// ---------------- S2 ----------------
initial begin
    S2[0] = 32'hE93D5A68;
    S2[1] = 32'h948140F7;
    S2[2] = 32'hF64C261C;
    S2[3] = 32'h94692934;
    S2[4] = 32'h411520F7;
    S2[5] = 32'h7602D4F7;
    S2[6] = 32'hBCF46B2E;
    S2[7] = 32'hD4A20068;
    S2[8] = 32'hD4082471;
    S2[9] = 32'h3320F46A;
    S2[10] = 32'h43B7D4B7;
    S2[11] = 32'h500061AF;
    S2[12] = 32'h1E39F62E;
    S2[13] = 32'h97244546;
    S2[14] = 32'h14214F74;
    S2[15] = 32'hBF8B8840;
    S2[16] = 32'h4D95FC1D;
    S2[17] = 32'h96B591AF;
    S2[18] = 32'h70F4DDD3;
    S2[19] = 32'h66A02F45;
    S2[20] = 32'hBFBC09EC;
    S2[21] = 32'h03BD9785;
    S2[22] = 32'h7FAC6DD0;
    S2[23] = 32'h31CB8504;
    S2[24] = 32'h96EB27B3;
    S2[25] = 32'h55FD3941;
    S2[26] = 32'hDA2547E6;
    S2[27] = 32'hABCA0A9A;
    S2[28] = 32'h28507825;
    S2[29] = 32'h530429F4;
    S2[30] = 32'h0A2C86DA;
    S2[31] = 32'hE9B66DFB;
    S2[32] = 32'h68DC1462;
    S2[33] = 32'hD7486900;
    S2[34] = 32'h680EC0A4;
    S2[35] = 32'h27A18DEE;
    S2[36] = 32'h4F3FFEA2;
    S2[37] = 32'hE887AD8C;
    S2[38] = 32'hB58CE006;
    S2[39] = 32'h7AF4D6B6;
    S2[40] = 32'hAACE1E7C;
    S2[41] = 32'hD3375FEC;
    S2[42] = 32'hCE78A399;
    S2[43] = 32'h406B2A42;
    S2[44] = 32'h20FE9E35;
    S2[45] = 32'hD9F385B9;
    S2[46] = 32'hEE39D7AB;
    S2[47] = 32'h3B124E8B;
    S2[48] = 32'h1DC9FAF7;
    S2[49] = 32'h4B6D1856;
    S2[50] = 32'h26A36631;
    S2[51] = 32'hEAE397B2;
    S2[52] = 32'h3A6EFA74;
    S2[53] = 32'hDD5B4332;
    S2[54] = 32'h6841E7F7;
    S2[55] = 32'hCA7820FB;
    S2[56] = 32'hFB0AF54E;
    S2[57] = 32'hD8FEB397;
    S2[58] = 32'h454056AC;
    S2[59] = 32'hBA489527;
    S2[60] = 32'h55533A3A;
    S2[61] = 32'h20838D87;
    S2[62] = 32'hFE6BA9B7;
    S2[63] = 32'hD096954B;
    S2[64] = 32'h55A867BC;
    S2[65] = 32'hA1159A58;
    S2[66] = 32'hCCA92963;
    S2[67] = 32'h99E1DB33;
    S2[68] = 32'hA62A4A56;
    S2[69] = 32'h3F3125F9;
    S2[70] = 32'h5EF47E1C;
    S2[71] = 32'h9029317C;
    S2[72] = 32'hFDF8E802;
    S2[73] = 32'h04272F70;
    S2[74] = 32'h80BB155C;
    S2[75] = 32'h05282CE3;
    S2[76] = 32'h95C11548;
    S2[77] = 32'hE4C66D22;
    S2[78] = 32'h48C1133F;
    S2[79] = 32'hC70F86DC;
    S2[80] = 32'h07F9C9EE;
    S2[81] = 32'h41041F0F;
    S2[82] = 32'h404779A4;
    S2[83] = 32'h5D886E17;
    S2[84] = 32'h325F51EB;
    S2[85] = 32'hD59BC0D1;
    S2[86] = 32'hF2BCC18F;
    S2[87] = 32'h41113564;
    S2[88] = 32'h257B7834;
    S2[89] = 32'h602A9C60;
    S2[90] = 32'hDFF8E8A3;
    S2[91] = 32'h1F636C1B;
    S2[92] = 32'h0E12B4C2;
    S2[93] = 32'h02E1329E;
    S2[94] = 32'hAF664FD1;
    S2[95] = 32'hCAD18115;
    S2[96] = 32'h6B2395E0;
    S2[97] = 32'h333E92E1;
    S2[98] = 32'h3B240B62;
    S2[99] = 32'hEEBEB922;
    S2[100] = 32'h85B2A20E;
    S2[101] = 32'hE6BA0D99;
    S2[102] = 32'hDE720C8C;
    S2[103] = 32'h2DA2F728;
    S2[104] = 32'hD0127845;
    S2[105] = 32'h95B794FD;
    S2[106] = 32'h647D0862;
    S2[107] = 32'hE7CCF5F0;
    S2[108] = 32'h5449A36F;
    S2[109] = 32'h877D48FA;
    S2[110] = 32'hC39DFD27;
    S2[111] = 32'hF33E8D1E;
    S2[112] = 32'h0A476341;
    S2[113] = 32'h992EFF74;
    S2[114] = 32'h3A6F6EAB;
    S2[115] = 32'hF4F8FD37;
    S2[116] = 32'hA812DC60;
    S2[117] = 32'hA1EBDDF8;
    S2[118] = 32'h991BE14C;
    S2[119] = 32'hDB6E6B0D;
    S2[120] = 32'hC67B5510;
    S2[121] = 32'h6D672C37;
    S2[122] = 32'h2765D43B;
    S2[123] = 32'hDCD0E804;
    S2[124] = 32'hF1290DC7;
    S2[125] = 32'hCC00FFA3;
    S2[126] = 32'hB5390F92;
    S2[127] = 32'h690FED0B;
    S2[128] = 32'h667B9FFB;
    S2[129] = 32'hCEDB7D9C;
    S2[130] = 32'hA091CF0B;
    S2[131] = 32'hD9155EA3;
    S2[132] = 32'hBB132F88;
    S2[133] = 32'h515BAD24;
    S2[134] = 32'h7B9479BF;
    S2[135] = 32'h763BD6EB;
    S2[136] = 32'h37392EB3;
    S2[137] = 32'hCC115979;
    S2[138] = 32'h8026E297;
    S2[139] = 32'hF42E312D;
    S2[140] = 32'h6842ADA7;
    S2[141] = 32'hC66A2B3B;
    S2[142] = 32'h12754CCC;
    S2[143] = 32'h782EF11C;
    S2[144] = 32'h6A124237;
    S2[145] = 32'hB79251E7;
    S2[146] = 32'h06A1BBE6;
    S2[147] = 32'h4BFB6350;
    S2[148] = 32'h1A6B1018;
    S2[149] = 32'h11CAEDFA;
    S2[150] = 32'h3D25BDD8;
    S2[151] = 32'hE2E1C3C9;
    S2[152] = 32'h44421659;
    S2[153] = 32'h0A121386;
    S2[154] = 32'hD90CEC6E;
    S2[155] = 32'hD5ABEA2A;
    S2[156] = 32'h64AF674E;
    S2[157] = 32'hDA86A85F;
    S2[158] = 32'hBEBFE988;
    S2[159] = 32'h64E4C3FE;
    S2[160] = 32'h9DBC8057;
    S2[161] = 32'hF0F7C086;
    S2[162] = 32'h60787BF8;
    S2[163] = 32'h6003604D;
    S2[164] = 32'hD1FD8346;
    S2[165] = 32'hF6381FB0;
    S2[166] = 32'h7745AE04;
    S2[167] = 32'hD736FCCC;
    S2[168] = 32'h83426B33;
    S2[169] = 32'hF01EAB71;
    S2[170] = 32'hB0804187;
    S2[171] = 32'h3C005E5F;
    S2[172] = 32'h77A057BE;
    S2[173] = 32'hBDE8AE24;
    S2[174] = 32'h55464299;
    S2[175] = 32'hBF582E61;
    S2[176] = 32'h4E58F48F;
    S2[177] = 32'hF2DDFDA2;
    S2[178] = 32'hF474EF38;
    S2[179] = 32'h8789BDC2;
    S2[180] = 32'h5366F9C3;
    S2[181] = 32'hC8B38E74;
    S2[182] = 32'hB475F255;
    S2[183] = 32'h46FCD9B9;
    S2[184] = 32'h7AEB2661;
    S2[185] = 32'h8B1DDF84;
    S2[186] = 32'h846A0E79;
    S2[187] = 32'h915F95E2;
    S2[188] = 32'h466E598E;
    S2[189] = 32'h20B45770;
    S2[190] = 32'h8CD55591;
    S2[191] = 32'hC902DE4C;
    S2[192] = 32'hB90BACE1;
    S2[193] = 32'hBB8205D0;
    S2[194] = 32'h11A86248;
    S2[195] = 32'h7574A99E;
    S2[196] = 32'hB77F19B6;
    S2[197] = 32'hE0A9DC09;
    S2[198] = 32'h662D09A1;
    S2[199] = 32'hC4324633;
    S2[200] = 32'hE85A1F02;
    S2[201] = 32'h09F0BE8C;
    S2[202] = 32'h4A99A025;
    S2[203] = 32'h1D6EFE10;
    S2[204] = 32'h1AB93D1D;
    S2[205] = 32'h0BA5A4DF;
    S2[206] = 32'hA186F20F;
    S2[207] = 32'h2868F169;
    S2[208] = 32'hDCB7DA83;
    S2[209] = 32'h573906FE;
    S2[210] = 32'hA1E2CE9B;
    S2[211] = 32'h4FCD7F52;
    S2[212] = 32'h50115E01;
    S2[213] = 32'hA70683FA;
    S2[214] = 32'hA002B5C4;
    S2[215] = 32'h0DE6D027;
    S2[216] = 32'h9AF88C27;
    S2[217] = 32'h773F8641;
    S2[218] = 32'hC3604C06;
    S2[219] = 32'h61A806B5;
    S2[220] = 32'hF0177A28;
    S2[221] = 32'hC0F586E0;
    S2[222] = 32'h006058AA;
    S2[223] = 32'h30DC7D62;
    S2[224] = 32'h11E69ED7;
    S2[225] = 32'h2338EA63;
    S2[226] = 32'h53C2DD94;
    S2[227] = 32'hC2C21634;
    S2[228] = 32'hBBCBEE56;
    S2[229] = 32'h90BCB6DE;
    S2[230] = 32'hEBFC7DA1;
    S2[231] = 32'hCE591D76;
    S2[232] = 32'h6F05E409;
    S2[233] = 32'h4B7C0188;
    S2[234] = 32'h39720A3D;
    S2[235] = 32'h7C927C24;
    S2[236] = 32'h86E3725F;
    S2[237] = 32'h724D9DB9;
    S2[238] = 32'h1AC15BB4;
    S2[239] = 32'hD39EB8FC;
    S2[240] = 32'hED545578;
    S2[241] = 32'h08FCA5B5;
    S2[242] = 32'hD83D7CD3;
    S2[243] = 32'h4DAD0FC4;
    S2[244] = 32'h1E50EF5E;
    S2[245] = 32'hB161E6F8;
    S2[246] = 32'hA28514D9;
    S2[247] = 32'h6C51133C;
    S2[248] = 32'h6FD5C7E7;
    S2[249] = 32'h56E14EC4;
    S2[250] = 32'h362ABFCE;
    S2[251] = 32'hDDC6C837;
    S2[252] = 32'hD79A3234;
    S2[253] = 32'h92638212;
    S2[254] = 32'h670EFA8E;
    S2[255] = 32'h406000E0;
end


// ---------------- S3 ----------------
initial begin
    S3[0] = 32'h3A39CE37;
    S3[1] = 32'hD3FAF5CF;
    S3[2] = 32'hABC27737;
    S3[3] = 32'h5AC52D1B;
    S3[4] = 32'h5CB0679E;
    S3[5] = 32'h4FA33742;
    S3[6] = 32'hD3822740;
    S3[7] = 32'h99BC9BBE;
    S3[8] = 32'hD5118E9D;
    S3[9] = 32'hBF0F7315;
    S3[10] = 32'hD62D1C7E;
    S3[11] = 32'hC700C47B;
    S3[12] = 32'hB78C1B6B;
    S3[13] = 32'h21A19045;
    S3[14] = 32'hB26EB1BE;
    S3[15] = 32'h6A366EB4;
    S3[16] = 32'h5748AB2F;
    S3[17] = 32'hBC946E79;
    S3[18] = 32'hC6A376D2;
    S3[19] = 32'h6549C2C8;
    S3[20] = 32'h530FF8EE;
    S3[21] = 32'h468DDE7D;
    S3[22] = 32'hD5730A1D;
    S3[23] = 32'h4CD04DC6;
    S3[24] = 32'h2939BBDB;
    S3[25] = 32'hA9BA4650;
    S3[26] = 32'hAC9526E8;
    S3[27] = 32'hBE5EE304;
    S3[28] = 32'hA1FAD5F0;
    S3[29] = 32'h6A2D519A;
    S3[30] = 32'h63EF8CE2;
    S3[31] = 32'h9A86EE22;
    S3[32] = 32'hC089C2B8;
    S3[33] = 32'h43242EF6;
    S3[34] = 32'hA51E03AA;
    S3[35] = 32'h9CF2D0A4;
    S3[36] = 32'h83C061BA;
    S3[37] = 32'h9BE96A4D;
    S3[38] = 32'h8FE51550;
    S3[39] = 32'hBA645BD6;
    S3[40] = 32'h2826A2F9;
    S3[41] = 32'hA73A3AE1;
    S3[42] = 32'h4BA99586;
    S3[43] = 32'hEF5562E9;
    S3[44] = 32'hC72FEFD3;
    S3[45] = 32'hF752F7DA;
    S3[46] = 32'h3F046F69;
    S3[47] = 32'h77FA0A59;
    S3[48] = 32'h80E4A915;
    S3[49] = 32'h87B08601;
    S3[50] = 32'h9B09E6AD;
    S3[51] = 32'h3B3EE593;
    S3[52] = 32'hE990FD5A;
    S3[53] = 32'h9E34D797;
    S3[54] = 32'h2CF0B7D9;
    S3[55] = 32'h022B8B51;
    S3[56] = 32'h96D5AC3A;
    S3[57] = 32'h017DA67D;
    S3[58] = 32'hD1CF3ED6;
    S3[59] = 32'h7C7D2D28;
    S3[60] = 32'h1F9F25CF;
    S3[61] = 32'hADF2B89B;
    S3[62] = 32'h5AD6B472;
    S3[63] = 32'h5A88F54C;
    S3[64] = 32'hE029AC71;
    S3[65] = 32'hE019A5E6;
    S3[66] = 32'h47B0ACFD;
    S3[67] = 32'hED93FA9B;
    S3[68] = 32'hE8D3C48D;
    S3[69] = 32'h283B57CC;
    S3[70] = 32'hF8D56629;
    S3[71] = 32'h79132E28;
    S3[72] = 32'h785F0191;
    S3[73] = 32'hED756055;
    S3[74] = 32'hF7960E44;
    S3[75] = 32'hE3D35E8C;
    S3[76] = 32'h15056DD4;
    S3[77] = 32'h88F46DBA;
    S3[78] = 32'h03A16125;
    S3[79] = 32'h0564F0BD;
    S3[80] = 32'hC3EB9E15;
    S3[81] = 32'h3C9057A2;
    S3[82] = 32'h97271AEC;
    S3[83] = 32'hA93A072A;
    S3[84] = 32'h1B3F6D9B;
    S3[85] = 32'h1E6321F5;
    S3[86] = 32'hF59C66FB;
    S3[87] = 32'h26DCF319;
    S3[88] = 32'h7533D928;
    S3[89] = 32'hB155FDF5;
    S3[90] = 32'h03563482;
    S3[91] = 32'h8ABA3CBB;
    S3[92] = 32'h28517711;
    S3[93] = 32'hC20AD9F8;
    S3[94] = 32'hABCC5167;
    S3[95] = 32'hCCAD925F;
    S3[96] = 32'h4DE81751;
    S3[97] = 32'h3830DC8E;
    S3[98] = 32'h379D5862;
    S3[99] = 32'h9320F991;
    S3[100] = 32'hEA7A90C2;
    S3[101] = 32'hFB3E7BCE;
    S3[102] = 32'h5121CE64;
    S3[103] = 32'h774FBE32;
    S3[104] = 32'hA8B6E37E;
    S3[105] = 32'hC3293D46;
    S3[106] = 32'h48DE5369;
    S3[107] = 32'h6413E680;
    S3[108] = 32'hA2AE0810;
    S3[109] = 32'hDD6DB224;
    S3[110] = 32'h69852DFD;
    S3[111] = 32'h09072166;
    S3[112] = 32'hB39A460A;
    S3[113] = 32'h6445C0DD;
    S3[114] = 32'h586CDECF;
    S3[115] = 32'h1C20C8AE;
    S3[116] = 32'h5BBEF7DD;
    S3[117] = 32'h1B588D40;
    S3[118] = 32'hCCD2017F;
    S3[119] = 32'h6BB4E3BB;
    S3[120] = 32'hDDA26A7E;
    S3[121] = 32'h3A59FF45;
    S3[122] = 32'h3E350A44;
    S3[123] = 32'hBCB4CDD5;
    S3[124] = 32'h72Eacea8;
    S3[125] = 32'hFA6484BB;
    S3[126] = 32'h8D6612AE;
    S3[127] = 32'hBF3C6F47;
    S3[128] = 32'hD29BE463;
    S3[129] = 32'h542F5D9E;
    S3[130] = 32'hAEC2771B;
    S3[131] = 32'hF64E6370;
    S3[132] = 32'h740E0D8D;
    S3[133] = 32'hE75B1357;
    S3[134] = 32'hF8721671;
    S3[135] = 32'hAF537D5D;
    S3[136] = 32'h4040CB08;
    S3[137] = 32'h4EB4E2CC;
    S3[138] = 32'h34D2466A;
    S3[139] = 32'h0115AF84;
    S3[140] = 32'hE1B00428;
    S3[141] = 32'h95983A1D;
    S3[142] = 32'h06B89FB4;
    S3[143] = 32'hCE6EA048;
    S3[144] = 32'h6F3F3B82;
    S3[145] = 32'h3520AB82;
    S3[146] = 32'h011A1D4B;
    S3[147] = 32'h277227F8;
    S3[148] = 32'h611560B1;
    S3[149] = 32'hE7933FDC;
    S3[150] = 32'hBB3A792B;
    S3[151] = 32'h344525BD;
    S3[152] = 32'hA08839E1;
    S3[153] = 32'h51CE794B;
    S3[154] = 32'h2F32C9B7;
    S3[155] = 32'hA01FBAC9;
    S3[156] = 32'hE01CC87E;
    S3[157] = 32'hBCC7D1F6;
    S3[158] = 32'hCF0111C3;
    S3[159] = 32'hA1E8AAC7;
    S3[160] = 32'h1A908749;
    S3[161] = 32'hD44FBD9A;
    S3[162] = 32'hD0DADECB;
    S3[163] = 32'hD50ADA38;
    S3[164] = 32'h0339C32A;
    S3[165] = 32'hC6913667;
    S3[166] = 32'h8DF9317C;
    S3[167] = 32'hE0B12B4F;
    S3[168] = 32'hF79E59B7;
    S3[169] = 32'h43F5BB3A;
    S3[170] = 32'hF2D519FF;
    S3[171] = 32'h27D9459C;
    S3[172] = 32'hBF97222C;
    S3[173] = 32'h15E6FC2A;
    S3[174] = 32'h0F91FC71;
    S3[175] = 32'h9B941525;
    S3[176] = 32'hFAE59361;
    S3[177] = 32'hCEB69CEB;
    S3[178] = 32'hC2A86459;
    S3[179] = 32'h12BAA8D1;
    S3[180] = 32'hB6C1075E;
    S3[181] = 32'hE3056A0C;
    S3[182] = 32'h10D25065;
    S3[183] = 32'hCB03A442;
    S3[184] = 32'hE0EC6E0E;
    S3[185] = 32'h1698DB3B;
    S3[186] = 32'h4C98A0BE;
    S3[187] = 32'h3278E964;
    S3[188] = 32'h9F1F9532;
    S3[189] = 32'hE0D392DF;
    S3[190] = 32'hD3A0342B;
    S3[191] = 32'h8971F21E;
    S3[192] = 32'h1B0A7441;
    S3[193] = 32'h4BA3348C;
    S3[194] = 32'hC5BE7120;
    S3[195] = 32'hC37632D8;
    S3[196] = 32'hDF359F8D;
    S3[197] = 32'h9B992F2E;
    S3[198] = 32'hE60B6F47;
    S3[199] = 32'h0FE3F11D;
    S3[200] = 32'hE54CDA54;
    S3[201] = 32'h1EDAD891;
    S3[202] = 32'hCE6279CF;
    S3[203] = 32'hCD3E7E6F;
    S3[204] = 32'h1618B166;
    S3[205] = 32'hFD2C1D05;
    S3[206] = 32'h848FD2C5;
    S3[207] = 32'hF6FB2299;
    S3[208] = 32'hF523F357;
    S3[209] = 32'hA6327623;
    S3[210] = 32'h93A83531;
    S3[211] = 32'h56CCCD02;
    S3[212] = 32'hACF08162;
    S3[213] = 32'h5A75EBB5;
    S3[214] = 32'h6E163697;
    S3[215] = 32'h88D273CC;
    S3[216] = 32'hDE966292;
    S3[217] = 32'h81B949D0;
    S3[218] = 32'h4C50901B;
    S3[219] = 32'h71C65614;
    S3[220] = 32'hE6C6C7BD;
    S3[221] = 32'h327A140A;
    S3[222] = 32'h45E1D006;
    S3[223] = 32'hC3F27B9A;
    S3[224] = 32'hC9AA53FD;
    S3[225] = 32'h62A80F00;
    S3[226] = 32'hBB25BFE2;
    S3[227] = 32'h35BDD2F6;
    S3[228] = 32'h71126905;
    S3[229] = 32'hB2040222;
    S3[230] = 32'hB6CBCF7C;
    S3[231] = 32'hCD769C2B;
    S3[232] = 32'h53113EC0;
    S3[233] = 32'h1640E3D3;
    S3[234] = 32'h38ABBD60;
    S3[235] = 32'h2547ADF0;
    S3[236] = 32'hBA38209C;
    S3[237] = 32'hF746CE76;
    S3[238] = 32'h77AFA1C5;
    S3[239] = 32'h20756060;
    S3[240] = 32'h85CBFE4E;
    S3[241] = 32'h8AE88DD8;
    S3[242] = 32'h7AAAF9B0;
    S3[243] = 32'h4CF9AA7E;
    S3[244] = 32'h1948C25C;
    S3[245] = 32'h02FB8A8C;
    S3[246] = 32'h01C36AE4;
    S3[247] = 32'hD6EBE1F9;
    S3[248] = 32'h90D4F869;
    S3[249] = 32'hA65CDEA0;
    S3[250] = 32'h3F09252D;
    S3[251] = 32'hC208E69F;
    S3[252] = 32'hB74E6132;
    S3[253] = 32'hCE77E25B;
    S3[254] = 32'h578FDFE3;
    S3[255] = 32'h3AC372E6;
end


  
   
    function [31:0] F_func;
        input [31:0] x;
        reg [7:0] a,b,c,d;
        reg [31:0] y;
    begin
        a = x[31:24];
        b = x[23:16];
        c = x[15:8];
        d = x[7:0];
        y = S0[a] + S1[b];
        y = y ^ S2[c];
        y = y + S3[d];
        F_func = y;
    end
    endfunction
   // ============================================================
    // =====================  ENCRYPTION ENGINE  ===================
    // ============================================================
    // The engine is driven by arb_enc_start / arb_enc_L / arb_enc_R only.
    reg        enc_busy;
    reg [4:0]  enc_round;
    reg [31:0] enc_L_reg, enc_R_reg;
    reg        enc_done_flag;
    reg [31:0] enc_L_done, enc_R_done;
    reg [31:0] Ltmp, Rtmp;

    // Flag selects whether to use P1 (during initial expansion) or P (final)
    reg use_P1;

    // Arbiter-driven signals (single owner of engine inputs)
    reg        arb_enc_start;
    reg [31:0] arb_enc_L;
    reg [31:0] arb_enc_R;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            enc_busy      <= 0;
            enc_round     <= 0;
            enc_done_flag <= 0;
            enc_L_done    <= 0;
            enc_R_done    <= 0;
            Ltmp <= 0;
            Rtmp <= 0;
            use_P1 <= 0;
        end
        else begin
            enc_done_flag <= 0;

            // =============== START encryption ================
            if (arb_enc_start && !enc_busy) begin
                enc_busy  <= 1;
                enc_round <= 0;
                enc_L_reg <= arb_enc_L;
                enc_R_reg <= arb_enc_R;
            end

            // =============== RUN 16 ROUNDS ===================
            else if (enc_busy) begin
                if (enc_round < 16) begin
                    // choose round key from P1 or P depending on use_P1
                    if (use_P1)
                        Ltmp = enc_L_reg ^ P1[enc_round];
                    else
                        Ltmp = enc_L_reg ^ P[enc_round];

                    Rtmp = enc_R_reg ^ F_func(Ltmp);

                    enc_L_reg <= Rtmp;
                    enc_R_reg <= Ltmp;
                    enc_round <= enc_round + 1;
                end
                else begin
                    // final swap back and XOR with P[16], P[17] (or P1 if use_P1)
                    if (use_P1) begin
                        enc_R_done <= (Rtmp ^ P1[16]);
                        enc_L_done <= (Ltmp ^ P1[17]);
                    end else begin
                        enc_R_done <= (Rtmp ^ P[16]);
                        enc_L_done <= (Ltmp ^ P[17]);
                    end

                    enc_busy      <= 0;
                    enc_done_flag <= 1;
                    enc_round     <= enc_round + 1;
                end
            end
        end
    end

    // ============================================================
    // ========================  FSM #1  ===========================
    // =============== XOR all P[i] with 64-bit key ================
    // Writes P1[] only
    // ============================================================
    reg [2:0] pstate;
    reg [4:0] p_index;
    reg       p_xor_done;

    localparam PX_IDLE  = 0,
               PX_RUN   = 1,
               PX_DONE  = 2;

    reg [31:0] keyW0, keyW1;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pstate     <= PX_IDLE;
            p_index    <= 0;
            p_xor_done <= 0;
            keyW0      <= 0;
            keyW1      <= 0;
        end
        else begin
            p_xor_done <= 0;

            case (pstate)

            PX_IDLE: begin
                if (start_expand) begin
                    keyW0    <= key_in[63:32];
                    keyW1    <= key_in[31:0];
                    p_index  <= 0;
                    pstate   <= PX_RUN;
                end
            end

            PX_RUN: begin
                if (p_index < 18) begin
                    if (p_index[0] == 1'b0)
                        P1[p_index] <= P[p_index] ^ keyW0; // write to P1
                    else
                        P1[p_index] <= P[p_index] ^ keyW1; // write to P1
                        use_P1<=1'b1;
                    p_index <= p_index + 1;
                end
                else begin
                    pstate <= PX_DONE;
                end
            end

            PX_DONE: begin
                p_xor_done <= 1;   // signals FSM2 to start
                pstate <= PX_IDLE;
            end

            endcase
        end
    end

    // ============================================================
    // ========================  FSM #2  ===========================
    // ===   Replace P[i],P[i+1] using bf_encrypt, 18 entries    ===
    // ===   FSM2 is the only writer to P[] (final P-array)     ===
    // ============================================================
    reg [2:0] p2_state;
    reg [4:0] p2_idx;
    reg       p2_done;

    localparam P2_IDLE  = 0,
               P2_START = 1,
               P2_WAIT  = 2,
               P2_WRITE1 = 3,
               P2_WRITE2 = 4,
               P2_DONE  = 5;

    reg [31:0] KL_p2, KR_p2;
    reg        enc_req_p2;    // request to arbiter to start encryption for P2

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            p2_state <= P2_IDLE;
            p2_idx   <= 0;
            KL_p2    <= 0;
            KR_p2    <= 0;
            p2_done  <= 0;
            enc_req_p2 <= 0;
        end
        else begin
            // defaults
            p2_done <= 0;
            enc_req_p2 <= 0;

            case (p2_state)

            // ----------- Wait for XOR-P to finish --------------
            P2_IDLE: begin
                if (p_xor_done) begin
                    // start expansion phase using P1 as round keys (use_P1 = 1)
                    KL_p2   <= 32'h00000000;
                    KR_p2   <= 32'h00000000;
                    p2_idx  <= 0;
                    p2_state <= P2_START;
                end
            end

            // ---- Start encryption of (KL_p2, KR_p2) ----
            P2_START: begin
                // request encryption via per-FSM request signal
                enc_req_p2 <= 1;
                // deliver inputs to arbiter in separate signals below (enc_req_p2_L/R)
                p2_state  <= P2_WAIT;
            end

            // ---- Wait for encryption to complete ----
            P2_WAIT: begin
                if (enc_done_flag) begin
                    p2_state <= P2_WRITE1;
                end
            end

            // ---- Write back into P-array (first of pair) ----
            P2_WRITE1: begin
                // write P[p2_idx] <= enc_L_done
                P[p2_idx] <= enc_L_done;

                p2_state <= P2_WRITE2;
            end

            // ---- Write back into P-array (second of pair) ----
            P2_WRITE2: begin
                // write P[p2_idx+1] <= enc_R_done
                P[p2_idx + 1] <= enc_R_done;

                // chain result forward
                KL_p2 <= enc_L_done;
                KR_p2 <= enc_R_done;

                if (p2_idx + 2 >= 18)
                    p2_state <= P2_DONE;
                else begin
                    p2_idx  <= p2_idx + 2;
                    p2_state <= P2_START;
                end
            end

            // ---- finished all 18 entries ----
            P2_DONE: begin
                p2_done  <= 1;
                use_P1   <= 0;    // after P expansion, use final P[]
                p2_state <= P2_IDLE;
            end

            endcase
        end
    end

    // ============================================================
    // ========================  FSM #3  ===========================
    // ======== Expand all 4 S-boxes using bf_encrypt =============
    // ============================================================
    reg [2:0] s3_state;
    reg [1:0] s_box_sel;
    reg [8:0] s_idx;
    reg       s3_done;

    localparam S3_IDLE  = 0,
               S3_START = 1,
               S3_WAIT  = 2,
               S3_WRITE = 3,
               S3_NEXT  = 4,
               S3_DONE  = 5;

    reg [31:0] KL_s3, KR_s3;
    reg        enc_req_s3;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            s3_state  <= S3_IDLE;
            s_box_sel <= 0;
            s_idx     <= 0;
            s3_done   <= 0;
            KL_s3     <= 0;
            KR_s3     <= 0;
            enc_req_s3 <= 0;
        end
        else begin
            s3_done <= 0;
            enc_req_s3 <= 0;

            case (s3_state)

            // ---------------- Wait for P-expansion done ---------------
            S3_IDLE: begin
                if (p2_done) begin
                    s_box_sel <= 0;
                    s_idx     <= 0;
                    KL_s3     <= KL_p2;   // continue chain
                    KR_s3     <= KR_p2;
                    s3_state  <= S3_START;
                end
            end

            // ----------- Start encryption ------------
            S3_START: begin
                enc_req_s3 <= 1;      // request encryption via arbiter
                s3_state  <= S3_WAIT;
            end

            // ----------- Wait ------------------------
            S3_WAIT: begin
                if (enc_done_flag)
                    s3_state <= S3_WRITE;
            end

            // ----------- Write into S-boxes ----------
            S3_WRITE: begin
                case (s_box_sel)
                    0: begin S0[s_idx] <= enc_L_done; S0[s_idx+1] <= enc_R_done; end
                    1: begin S1[s_idx] <= enc_L_done; S1[s_idx+1] <= enc_R_done; end
                    2: begin S2[s_idx] <= enc_L_done; S2[s_idx+1] <= enc_R_done; end
                    3: begin S3[s_idx] <= enc_L_done; S3[s_idx+1] <= enc_R_done; end
                endcase

                // update chain
                KL_s3 <= enc_L_done;
                KR_s3 <= enc_R_done;

                s3_state <= S3_NEXT;
            end

            // ----------- Move to next entries --------
            S3_NEXT: begin
                if (s_idx == 254) begin
                    if (s_box_sel == 3)
                        s3_state <= S3_DONE;
                    else begin
                        s_box_sel <= s_box_sel + 1;
                        s_idx <= 0;
                        s3_state <= S3_START;
                    end
                end
                else begin
                    s_idx <= s_idx + 2;
                    s3_state <= S3_START;
                end
            end

            // ------------- Finished all S-boxes -----------
            S3_DONE: begin
                s3_done     <= 1;
                done_expand <= 1;
                s3_state    <= S3_IDLE;
            end

            endcase
        end
    end

    // ============================================================
    // ============== Simple Arbiter for the Encryption ===========
    // FSMs set enc_req_p2 / enc_req_s3 / enc_req_final and put
    // their inputs in enc_req_*_L/R signals. Arbiter accepts one
    // request at a time and drives arb_enc_start/L/R for the engine.
    // ============================================================
    reg enc_req_p2_L_valid, enc_req_s3_L_valid, enc_req_final_valid;
    reg [31:0] enc_req_p2_L, enc_req_p2_R;
    reg [31:0] enc_req_s3_L, enc_req_s3_R;
    reg [31:0] enc_req_final_L, enc_req_final_R;

    // These are written by the FSMs (single-writer each), so safe:
    // - p2 uses enc_req_p2_* (we will set them when requesting)
    // - s3 uses enc_req_s3_*
    // - final encryption uses enc_req_final_*
    // FSMs will set their valid flag for one cycle when they request.

    // We'll update these valid/data flags inside the existing FSMs
    // by setting the *_valid signals; below arbiter picks them up.

    // Arbiter state
    reg arb_busy;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            arb_enc_start <= 0;
            arb_enc_L     <= 0;
            arb_enc_R     <= 0;

            enc_req_p2_L_valid <= 0;
            enc_req_s3_L_valid <= 0;
            enc_req_final_valid <= 0;
            enc_req_p2_L <= 0;
            enc_req_p2_R <= 0;
            enc_req_s3_L <= 0;
            enc_req_s3_R <= 0;
            enc_req_final_L <= 0;
            enc_req_final_R <= 0;

            arb_busy <= 0;
        end else begin
            // default: don't start
            arb_enc_start <= 0;

            // latch any requests that were set by FSMs this cycle
            // (Note: FSMs should set enc_req_*_L_valid for 1 cycle with their data)
            if (enc_req_p2) begin
                enc_req_p2_L_valid <= 1;
                enc_req_p2_L <= KL_p2;
                enc_req_p2_R <= KR_p2;
            end else if (enc_req_s3) begin
                enc_req_s3_L_valid <= 1;
                enc_req_s3_L <= KL_s3;
                enc_req_s3_R <= KR_s3;
            end else if (enc_req_final) begin
                enc_req_final_valid <= 1;
                enc_req_final_L <= pt_in[63:32];
                enc_req_final_R <= pt_in[31:0];
            end

            // If engine not busy and we have a pending request, service in priority:
            // priority: P2 -> S3 -> final encryption
            if (!enc_busy) begin
                if (enc_req_p2_L_valid) begin
                    arb_enc_L <= enc_req_p2_L;
                    arb_enc_R <= enc_req_p2_R;
                    arb_enc_start <= 1;
                    enc_req_p2_L_valid <= 0;
                end else if (enc_req_s3_L_valid) begin
                    arb_enc_L <= enc_req_s3_L;
                    arb_enc_R <= enc_req_s3_R;
                    arb_enc_start <= 1;
                    enc_req_s3_L_valid <= 0;
                end else if (enc_req_final_valid) begin
                    arb_enc_L <= enc_req_final_L;
                    arb_enc_R <= enc_req_final_R;
                    arb_enc_start <= 1;
                    enc_req_final_valid <= 0;
                end
            end
        end
    end

    // NOTE: we chose to implement the request-latching by having
    // the FSMs assert enc_req_p2 / enc_req_s3 / enc_req_final for one cycle.
    // We declared those signals below and they are driven only inside their FSMs.

    // Declare the per-FSM request signals (driven only inside that FSM)
    reg enc_req_p2;
    reg enc_req_s3;
    reg enc_req_final;

    // We must ensure FSMs assert enc_req_* for one cycle when they want service.
    // We already used enc_req_p2 and enc_req_s3 inside FSMs earlier - make sure
    // they are set to 1 for one cycle at the request point.
    // For final encryption we'll assert enc_req_final in FSM#4.

    // ============================================================
    // ========================  FSM #4  ===========================
    // =============  Final Encryption (Blowfish)  =================
    // ============================================================
    reg [2:0] e_state;

    localparam E_IDLE  = 3'd0,
               E_LOAD  = 3'd1,
               E_WAIT  = 3'd2,
               E_OUT   = 3'd3;

    // e_start_flag removed; use enc_req_final to request arbiter

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            e_state      <= E_IDLE;
            done_encrypt <= 0;
            ct_out       <= 64'h0;
            enc_req_final <= 0;
        end
        else begin
            done_encrypt <= 0;
            enc_req_final <= 0;

            case (e_state)

            // Wait until S-box expansion is finished (s3_done == 1)
            // Then wait for user to give start_encrypt
            E_IDLE: begin
                if (done_expand && start_encrypt) begin
                    e_state <= E_LOAD;
                end
            end

            // Load input block into encryption engine by requesting arbiter
            E_LOAD: begin
                enc_req_final <= 1;   // request one-cycle
                e_state  <= E_WAIT;
            end

            // Wait for encryption engine (16 rounds + final P's)
            E_WAIT: begin
                if (enc_done_flag)
                    e_state <= E_OUT;
            end

            // Output full ciphertext
            E_OUT: begin
                ct_out       <= {enc_L_done, enc_R_done};
                done_encrypt <= 1;
            end

            endcase
        end
    end

    // ------------- Ensure FSMs drive their enc_req_* signals only where appropriate -------------
    // We must set enc_req_p2 and enc_req_s3 inside FSM2 and FSM3 respectively.
    // We'll modify FSM2 and FSM3 earlier to assert enc_req_p2/enc_req_s3 for 1 cycle.
    // (We used enc_req_p2 / enc_req_s3 local regs in those FSMs.)

    // -------------------------------------------------------------------------
    // Small adjustments: convert enc_req_p2/enc_req_s3 usage in previous FSMs
    // to assert one-cycle requests. We already used enc_req_p2/enc_req_s3 in the FSMs.
    // -------------------------------------------------------------------------

    // Note: done_expand and done_encrypt are set in S3_DONE and E_OUT respectively.


    
    
    
    
//    // -------------------------------------------------------------
//    // Normal Blowfish encryption after expansion
//    // -------------------------------------------------------------
//    reg encrypt_phase;

//    always @(posedge clk or negedge rst_n) begin
//        if (!rst_n) begin
//            done_encrypt <= 0;
//        end else begin
//            done_encrypt <= 0;

//            if (start_encrypt && !enc_busy) begin
//                enc_L <= pt_in[63:32];
//                enc_R <= pt_in[31:0];
//                enc_start <= 1;
//                encrypt_phase <= 1;
//            end else if (encrypt_phase && enc_done_flag) begin
//                ct_out <= {enc_L_done, enc_R_done};
//                done_encrypt <= 1;
//                encrypt_phase <= 0;
//            end
//        end
//    end

endmodule
