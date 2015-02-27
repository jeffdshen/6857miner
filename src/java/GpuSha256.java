/*
 * Copyright 2015 Ronald W Hoffman.
 * Copyright 2015 Jeffrey D Shen.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.amd.aparapi.Kernel;

/**
* SHA-256 hash algorithm for Monetary System currencies - modified for 6.857 Problem Set 2.
*
* GpuSha256 uses the Aparapi package to calculate hashes using the graphics card
* GPU.  The Aparapi and OpenCL runtime libraries must be available in either the
* system path or the Java library path.  This GPU version of HashSha256 is optimized
* for the GPU and does not support generalized hashing.
*
* Aparapi builds an OpenCL kernel from the Java bytecodes when the Kernel.execute()
* method is invoked.  The compiled program is saved for subsequent executions by
* the same kernel.
*
* Aparapi supports a subset of Java functions:
*   o Only primitive data types and single-dimension arrays are supported.
*   o Objects cannot be created by the kernel program.  This means that kernel
*     code cannot use the 'new' operation.
*   o Java exceptions, enhanced 'for' statements and 'break' statements are not supported.
*   o Variable assignment during expression evaluation is not supported.
*   o Primitive data types defined within a function must be assigned a value at the time of definition.
*   o Only data belonging to the enclosing Java class can be copied to/from GPU memory.
*   o Primitives and objects can be read from kernel code but only objects can be
*     written by kernel code.
*   o Aparapi normally defines kernel groups based on the capabilities of the graphics card.
*     The Range object can be used to define an explicit grouping.
*   o Untagged data is shared by all instances of the kernel.
*   o Constant data is not fetched upon completion of kernel execution.  Constant data is
*     indicated by prefixing the data definition with @Constant.
*   o Local data is shared by all instances in the same kernel group.  Local data is indicated
*     by prefixing the data definition with @Local
*   o Private data is not shared and each kernel instance has its own copy of the data.  Private
*     data is indicated by prefixing the data definition with @PrivateMemorySpace(nnn) where 'nnn'
*     is the array dimension.  Private data cannot be passed as a function parameter since it is
*     in a separate address space and this information is not passed on the function call.
*/
public class GpuSha256 extends Kernel {

    /** SHA-256 constants */
    private final int[] k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    /** Input data */
    private final byte[] input = new byte[64];

    /** Hash target */
    public final byte[] target = new byte[32];

    private final long start;
    private final long mod;
    private final int length;
    public final boolean[] solved = new boolean[1];
    public final long[] nonce = new long[1];

    /**
     * Create the GPU hash function
     *
     */
    public GpuSha256(byte[] block, long start, long mod, int length) {
        this.start = start;
        this.mod = mod;
        this.length = length;
        setInput(block);
    }

//    public GpuSha256() {
//
//    }

    /**
     * Set the input data and the hash target
     *
     * The input data is in the following format:
     *     Bytes 0-7:   Initial nonce (modified for each kernel instance)
     *     Bytes 8-15:  Currency identifier
     *     Bytes 16-23: Currency units
     *     Bytes 24-31: Minting counter
     *     Bytes 32-39: Account identifier
     *
     * The hash target and hash digest are treated as unsigned 32-byte numbers in little-endian format.
     * The digest must be less than the target in order to be a solution.
     *
     * @param       inputBytes      Bytes to be hashed (40 bytes)
     */
    public void setInput(byte[] inputBytes) {
//        if (inputBytes.length != 46)
//            throw new IllegalArgumentException("Input data length must be 40 bytes");
        //
        // Copy the input data
        //


        // CUSTOM : assumes content = 2 bytes, and thus we have 46 total bytes
        System.arraycopy(inputBytes, 0, input, 0, 46);
        //
        // Pad the buffer
        //
        // SHA-256 processes data in 64-byte blocks where the data bit count
        // is stored in the last 8 bytes in big-endian format.  The first pad
        // byte is 0x80 and the remaining pad bytes are 0x00.  Since we have
        // 46 bytes of data, the data bit count is 368 (0x170).
        //
        input[46] = (byte)0x80;
        input[62] = (byte)0x01;
        input[63] = (byte)0x70;

        // clear targetBytes
        for (int i = 0; i < 32; i++) {
            target[i] = 0;
        }

    }

    /**
     * Compute the hash
     */
    public boolean hash(long nonce, int difficulty) {
        //
        // Initialization
        //
        int A = 0x6a09e667;
        int B = 0xbb67ae85;
        int C = 0x3c6ef372;
        int D = 0xa54ff53a;
        int E = 0x510e527f;
        int F = 0x9b05688c;
        int G = 0x1f83d9ab;
        int H = 0x5be0cd19;
        int T, T2;
        int w16;

        long value = nonce;
        byte nonce7 = (byte) (value & 0xffL);
        value >>= 8;
        byte nonce6 = (byte) (value & 0xffL);
        value >>= 8;
        byte nonce5 = (byte) (value & 0xffL);
        value >>= 8;
        byte nonce4 = (byte) (value & 0xffL);
        value >>= 8;
        byte nonce3 = (byte) (value & 0xffL);
        value >>= 8;
        byte nonce2 = (byte) (value & 0xffL);
        value >>= 8;
        byte nonce1 = (byte) (value & 0xffL);
        value >>= 8;
        byte nonce0 = (byte) (value & 0xffL);
        // Transform the data
        //
        // We will modify the nonce (first 8 bytes of the input data) for each execution instance
        //

        byte[] input = this.input;
        int[] k = this.k;

        // unroll: r = 0
        w16 = (input[0] << 24 | (input[1] & 0xFF) << 16 |
            (input[2] & 0xFF) << 8 | (input[3] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[0] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w0 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 1
        w16 = (input[4] << 24 | (input[5] & 0xFF) << 16 |
            (input[6] & 0xFF) << 8 | (input[7] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[1] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w1 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 2
        w16 = (input[8] << 24 | (input[9] & 0xFF) << 16 |
            (input[10] & 0xFF) << 8 | (input[11] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[2] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w2 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 3
        w16 = (input[12] << 24 | (input[13] & 0xFF) << 16 |
            (input[14] & 0xFF) << 8 | (input[15] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[3] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w3 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 4
        w16 = (input[16] << 24 | (input[17] & 0xFF) << 16 |
            (input[18] & 0xFF) << 8 | (input[19] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[4] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w4 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 5
        w16 = (input[20] << 24 | (input[21] & 0xFF) << 16 |
            (input[22] & 0xFF) << 8 | (input[23] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[5] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w5 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 6
        w16 = (input[24] << 24 | (input[25] & 0xFF) << 16 |
            (input[26] & 0xFF) << 8 | (input[27] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[6] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w6 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 7
        w16 = (input[28] << 24 | (input[29] & 0xFF) << 16 |
            (input[30] & 0xFF) << 8 | (input[31] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[7] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w7 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 8
        // CUSTOM : nonce at bytes 34, 35 (34 / 4 = 8)
        w16 = (input[32] << 24 | (input[33] & 0xFF) << 16 |
            (nonce0 & 0xFF) << 8 | (nonce1 & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[8] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w8 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 9
        // CUSTOM : nonce at byte 36, 37, 38, 39 (36 / 4 = 9)
        w16 = (nonce2 << 24 | (nonce3 & 0xFF) << 16 |
            (nonce4 & 0xFF) << 8 | (nonce5 & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[9] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w9 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 10
        w16 = (nonce6 << 24 | (nonce7 & 0xFF) << 16 |
            (input[42] & 0xFF) << 8 | (input[43] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[10] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w10 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 11
        w16 = (input[44] << 24 | (input[45] & 0xFF) << 16 |
            (input[46] & 0xFF) << 8 | (input[47] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[11] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w11 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 12
        w16 = (input[48] << 24 | (input[49] & 0xFF) << 16 |
            (input[50] & 0xFF) << 8 | (input[51] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[12] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w12 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 13
        w16 = (input[52] << 24 | (input[53] & 0xFF) << 16 |
            (input[54] & 0xFF) << 8 | (input[55] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[13] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w13 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 14
        w16 = (input[56] << 24 | (input[57] & 0xFF) << 16 |
            (input[58] & 0xFF) << 8 | (input[59] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[14] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w14 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        // unroll: r = 15
        w16 = (input[60] << 24 | (input[61] & 0xFF) << 16 |
            (input[62] & 0xFF) << 8 | (input[63] & 0xFF));
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[15] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        int w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[16] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[17] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[18] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[19] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[20] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[21] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[22] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[23] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[24] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[25] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[26] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[27] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[28] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[29] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[30] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[31] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[32] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[33] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[34] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[35] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[36] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[37] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[38] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[39] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[40] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[41] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[42] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[43] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[44] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[45] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[46] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[47] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[48] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[49] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[50] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[51] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[52] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[53] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[54] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[55] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8; w8 = w9;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[56] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7; w7 = w8;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[57] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6; w6 = w7;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[58] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5; w5 = w6;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w13 = w14; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[59] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4; w4 = w5;
        w9 = w10; w10 = w11; w11 = w12; w12 = w13; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[60] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3; w3 = w4;
        w9 = w10; w10 = w11; w11 = w12; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[61] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        w0 = w1; w1 = w2; w2 = w3;
        w9 = w10; w10 = w11; w14 = w15; w15 = w16;
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w14;
        T2 = w1;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w9 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w0);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[62] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        T =  w15;
        T2 = w2;
        w16 = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10)) + w10 +
            (((T2 >>> 7) | (T2 << 25)) ^ ((T2 >>> 18) | (T2 << 14)) ^ (T2 >>> 3)) + w1);
        T = (H + (((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7))) +
            ((E & F) ^ (~E & G)) + k[63] + w16);
        T2 = ((((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10))) +
            ((A & B) ^ (A & C) ^ (B & C)));
        H = G; G = F; F = E;
        E = D + T;
        D = C; C = B; B = A;
        A = T + T2;

        //
        // Finish the digest
        //
        int h0 = A + 0x6a09e667;
        int h1 = B + 0xbb67ae85;
        int h2 = C + 0x3c6ef372;
        int h3 = D + 0xa54ff53a;
        int h4 = E + 0x510e527f;
        int h5 = F + 0x9b05688c;
        int h6 = G + 0x1f83d9ab;
        int h7 = H + 0x5be0cd19;

        int cur = 0;
        if (difficulty >= 32) {
            if (h0 != 0) {
                return false;
            }

            if (difficulty >= 64) {
                if (h1 != 0) {
                    return false;
                }

                if (difficulty >= 96) {
                    if (h2 != 0) {
                        return false;
                    }
                    // should never reach...
                    cur = h3;
                } else {
                    cur = h2;
                }
            } else {
                cur = h1;
            }
        } else {
            cur = h0;
        }

        difficulty %= 32;
        if (difficulty > 0 && (cur >> (32 - difficulty)) != 0) {
            return false;
        }

        // if made it here, then the check worked

        target[0] = (byte) (h0 >> 24);
        target[1] = (byte) (h0 >> 16);
        target[2] = (byte) (h0 >> 8);
        target[3] = (byte) (h0);

        target[4] = (byte) (h1 >> 24);
        target[5] = (byte) (h1 >> 16);
        target[6] = (byte) (h1 >> 8);
        target[7] = (byte) (h1);

        target[8] = (byte) (h2 >> 24);
        target[9] = (byte) (h2 >> 16);
        target[10] = (byte) (h2 >> 8);
        target[11] = (byte) (h2);

        target[12] = (byte) (h3 >> 24);
        target[13] = (byte) (h3 >> 16);
        target[14] = (byte) (h3 >> 8);
        target[15] = (byte) (h3);

        target[16] = (byte) (h4 >> 24);
        target[17] = (byte) (h4 >> 16);
        target[18] = (byte) (h4 >> 8);
        target[19] = (byte) (h4);

        target[20] = (byte) (h5 >> 24);
        target[21] = (byte) (h5 >> 16);
        target[22] = (byte) (h5 >> 8);
        target[23] = (byte) (h5);

        target[24] = (byte) (h6 >> 24);
        target[25] = (byte) (h6 >> 16);
        target[26] = (byte) (h6 >> 8);
        target[27] = (byte) (h6);

        target[28] = (byte) (h7 >> 24);
        target[29] = (byte) (h7 >> 16);
        target[30] = (byte) (h7 >> 8);
        target[31] = (byte) (h7);

        solved[0] =  true;
        this.nonce[0] = nonce;
        return true;
    }

    @Override
    public void run() {
        int id = getGlobalId();
        int difficulty = length / 100 + 24;
        long end = id + start + mod * 1_000_000;

        for (long i = start + id; i < end; i+= mod) {
            if (hash(i, difficulty)) {
                return;
            }
        }
    }
}