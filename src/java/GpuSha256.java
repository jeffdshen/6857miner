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
//    public final long[] count = new long[8192];

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
        int w17;

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

        int r;
        for (r = 16; r < 64; r += 16) {
            w0 += (((w14 >>> 17) | (w14 << (15))) ^ ((w14 >>> 19)
                | (w14 << (13))) ^ (w14 >>> 10)) + w9
                + (((w1 >>> 7) | (w1 << (25)))
                ^ ((w1 >>> 18) | (w1 << (14)))
                ^ (w1 >>> 3));
            T = H + (((E >>> 6) | (E << (26))) ^ ((E >>> 11)
                | (E << (21))) ^ ((E >>> 25)
                | (E << (7)))) + (((F ^ G) & E) ^ G)
                + k[r + 0x0] + w0;
            T2 = (((A >>> 2) | (A << (30))) ^ ((A >>> 13)
                | (A << (19))) ^ ((A >>> 22)
                | (A << (10))))
                + ((B & C) | ((B | C) & A));
            D += T;
            H = T + T2;
            w1 += (((w15 >>> 17) | (w15 << (15))) ^ ((w15 >>> 19)
                | (w15 << (13))) ^ (w15 >>> 10)) + w10
                + (((w2 >>> 7) | (w2 << (25)))
                ^ ((w2 >>> 18) | (w2 << (14)))
                ^ (w2 >>> 3));
            T = G + (((D >>> 6) | (D << (26))) ^ ((D >>> 11)
                | (D << (21))) ^ ((D >>> 25)
                | (D << (7)))) + (((E ^ F) & D) ^ F)
                + k[r + 0x1] + w1;
            T2 = (((H >>> 2) | (H << (30))) ^ ((H >>> 13)
                | (H << (19))) ^ ((H >>> 22)
                | (H << (10))))
                + ((A & B) | ((A | B) & H));
            C += T;
            G = T + T2;
            w2 += (((w0 >>> 17) | (w0 << (15))) ^ ((w0 >>> 19)
                | (w0 << (13))) ^ (w0 >>> 10)) + w11
                + (((w3 >>> 7) | (w3 << (25)))
                ^ ((w3 >>> 18) | (w3 << (14)))
                ^ (w3 >>> 3));
            T = F + (((C >>> 6) | (C << (26))) ^ ((C >>> 11)
                | (C << (21))) ^ ((C >>> 25)
                | (C << (7)))) + (((D ^ E) & C) ^ E)
                + k[r + 0x2] + w2;
            T2 = (((G >>> 2) | (G << (30))) ^ ((G >>> 13)
                | (G << (19))) ^ ((G >>> 22)
                | (G << (10))))
                + ((H & A) | ((H | A) & G));
            B += T;
            F = T + T2;
            w3 += (((w1 >>> 17) | (w1 << (15))) ^ ((w1 >>> 19)
                | (w1 << (13))) ^ (w1 >>> 10)) + w12
                + (((w4 >>> 7) | (w4 << (25)))
                ^ ((w4 >>> 18) | (w4 << (14)))
                ^ (w4 >>> 3));
            T = E + (((B >>> 6) | (B << (26))) ^ ((B >>> 11)
                | (B << (21))) ^ ((B >>> 25)
                | (B << (7)))) + (((C ^ D) & B) ^ D)
                + k[r + 0x3] + w3;
            T2 = (((F >>> 2) | (F << (30))) ^ ((F >>> 13)
                | (F << (19))) ^ ((F >>> 22)
                | (F << (10))))
                + ((G & H) | ((G | H) & F));
            A += T;
            E = T + T2;
            w4 += (((w2 >>> 17) | (w2 << (15))) ^ ((w2 >>> 19)
                | (w2 << (13))) ^ (w2 >>> 10)) + w13
                + (((w5 >>> 7) | (w5 << (25)))
                ^ ((w5 >>> 18) | (w5 << (14)))
                ^ (w5 >>> 3));
            T = D + (((A >>> 6) | (A << (26))) ^ ((A >>> 11)
                | (A << (21))) ^ ((A >>> 25)
                | (A << (7)))) + (((B ^ C) & A) ^ C)
                + k[r + 0x4] + w4;
            T2 = (((E >>> 2) | (E << (30))) ^ ((E >>> 13)
                | (E << (19))) ^ ((E >>> 22)
                | (E << (10))))
                + ((F & G) | ((F | G) & E));
            H += T;
            D = T + T2;
            w5 += (((w3 >>> 17) | (w3 << (15))) ^ ((w3 >>> 19)
                | (w3 << (13))) ^ (w3 >>> 10)) + w14
                + (((w6 >>> 7) | (w6 << (25)))
                ^ ((w6 >>> 18) | (w6 << (14)))
                ^ (w6 >>> 3));
            T = C + (((H >>> 6) | (H << (26))) ^ ((H >>> 11)
                | (H << (21))) ^ ((H >>> 25)
                | (H << (7)))) + (((A ^ B) & H) ^ B)
                + k[r + 0x5] + w5;
            T2 = (((D >>> 2) | (D << (30))) ^ ((D >>> 13)
                | (D << (19))) ^ ((D >>> 22)
                | (D << (10))))
                + ((E & F) | ((E | F) & D));
            G += T;
            C = T + T2;
            w6 += (((w4 >>> 17) | (w4 << (15))) ^ ((w4 >>> 19)
                | (w4 << (13))) ^ (w4 >>> 10)) + w15
                + (((w7 >>> 7) | (w7 << (25)))
                ^ ((w7 >>> 18) | (w7 << (14)))
                ^ (w7 >>> 3));
            T = B + (((G >>> 6) | (G << (26))) ^ ((G >>> 11)
                | (G << (21))) ^ ((G >>> 25)
                | (G << (7)))) + (((H ^ A) & G) ^ A)
                + k[r + 0x6] + w6;
            T2 = (((C >>> 2) | (C << (30))) ^ ((C >>> 13)
                | (C << (19))) ^ ((C >>> 22)
                | (C << (10))))
                + ((D & E) | ((D | E) & C));
            F += T;
            B = T + T2;
            w7 += (((w5 >>> 17) | (w5 << (15))) ^ ((w5 >>> 19)
                | (w5 << (13))) ^ (w5 >>> 10)) + w0
                + (((w8 >>> 7) | (w8 << (25)))
                ^ ((w8 >>> 18) | (w8 << (14)))
                ^ (w8 >>> 3));
            T = A + (((F >>> 6) | (F << (26))) ^ ((F >>> 11)
                | (F << (21))) ^ ((F >>> 25)
                | (F << (7)))) + (((G ^ H) & F) ^ H)
                + k[r + 0x7] + w7;
            T2 = (((B >>> 2) | (B << (30))) ^ ((B >>> 13)
                | (B << (19))) ^ ((B >>> 22)
                | (B << (10))))
                + ((C & D) | ((C | D) & B));
            E += T;
            A = T + T2;
            w8 += (((w6 >>> 17) | (w6 << (15))) ^ ((w6 >>> 19)
                | (w6 << (13))) ^ (w6 >>> 10)) + w1
                + (((w9 >>> 7) | (w9 << (25)))
                ^ ((w9 >>> 18) | (w9 << (14)))
                ^ (w9 >>> 3));
            T = H + (((E >>> 6) | (E << (26))) ^ ((E >>> 11)
                | (E << (21))) ^ ((E >>> 25)
                | (E << (7)))) + (((F ^ G) & E) ^ G)
                + k[r + 0x8] + w8;
            T2 = (((A >>> 2) | (A << (30))) ^ ((A >>> 13)
                | (A << (19))) ^ ((A >>> 22)
                | (A << (10))))
                + ((B & C) | ((B | C) & A));
            D += T;
            H = T + T2;
            w9 += (((w7 >>> 17) | (w7 << (15))) ^ ((w7 >>> 19)
                | (w7 << (13))) ^ (w7 >>> 10)) + w2
                + (((w10 >>> 7) | (w10 << (25)))
                ^ ((w10 >>> 18) | (w10 << (14)))
                ^ (w10 >>> 3));
            T = G + (((D >>> 6) | (D << (26))) ^ ((D >>> 11)
                | (D << (21))) ^ ((D >>> 25)
                | (D << (7)))) + (((E ^ F) & D) ^ F)
                + k[r + 0x9] + w9;
            T2 = (((H >>> 2) | (H << (30))) ^ ((H >>> 13)
                | (H << (19))) ^ ((H >>> 22)
                | (H << (10))))
                + ((A & B) | ((A | B) & H));
            C += T;
            G = T + T2;
            w10 += (((w8 >>> 17) | (w8 << (15))) ^ ((w8 >>> 19)
                | (w8 << (13))) ^ (w8 >>> 10)) + w3
                + (((w11 >>> 7) | (w11 << (25)))
                ^ ((w11 >>> 18) | (w11 << (14)))
                ^ (w11 >>> 3));
            T = F + (((C >>> 6) | (C << (26))) ^ ((C >>> 11)
                | (C << (21))) ^ ((C >>> 25)
                | (C << (7)))) + (((D ^ E) & C) ^ E)
                + k[r + 0xA] + w10;
            T2 = (((G >>> 2) | (G << (30))) ^ ((G >>> 13)
                | (G << (19))) ^ ((G >>> 22)
                | (G << (10))))
                + ((H & A) | ((H | A) & G));
            B += T;
            F = T + T2;
            w11 += (((w9 >>> 17) | (w9 << (15))) ^ ((w9 >>> 19)
                | (w9 << (13))) ^ (w9 >>> 10)) + w4
                + (((w12 >>> 7) | (w12 << (25)))
                ^ ((w12 >>> 18) | (w12 << (14)))
                ^ (w12 >>> 3));
            T = E + (((B >>> 6) | (B << (26))) ^ ((B >>> 11)
                | (B << (21))) ^ ((B >>> 25)
                | (B << (7)))) + (((C ^ D) & B) ^ D)
                + k[r + 0xB] + w11;
            T2 = (((F >>> 2) | (F << (30))) ^ ((F >>> 13)
                | (F << (19))) ^ ((F >>> 22)
                | (F << (10))))
                + ((G & H) | ((G | H) & F));
            A += T;
            E = T + T2;
            w12 += (((w10 >>> 17) | (w10 << (15))) ^ ((w10 >>> 19)
                | (w10 << (13))) ^ (w10 >>> 10)) + w5
                + (((w13 >>> 7) | (w13 << (25)))
                ^ ((w13 >>> 18) | (w13 << (14)))
                ^ (w13 >>> 3));
            T = D + (((A >>> 6) | (A << (26))) ^ ((A >>> 11)
                | (A << (21))) ^ ((A >>> 25)
                | (A << (7)))) + (((B ^ C) & A) ^ C)
                + k[r + 0xC] + w12;
            T2 = (((E >>> 2) | (E << (30))) ^ ((E >>> 13)
                | (E << (19))) ^ ((E >>> 22)
                | (E << (10))))
                + ((F & G) | ((F | G) & E));
            H += T;
            D = T + T2;
            w13 += (((w11 >>> 17) | (w11 << (15))) ^ ((w11 >>> 19)
                | (w11 << (13))) ^ (w11 >>> 10)) + w6
                + (((w14 >>> 7) | (w14 << (25)))
                ^ ((w14 >>> 18) | (w14 << (14)))
                ^ (w14 >>> 3));
            T = C + (((H >>> 6) | (H << (26))) ^ ((H >>> 11)
                | (H << (21))) ^ ((H >>> 25)
                | (H << (7)))) + (((A ^ B) & H) ^ B)
                + k[r + 0xD] + w13;
            T2 = (((D >>> 2) | (D << (30))) ^ ((D >>> 13)
                | (D << (19))) ^ ((D >>> 22)
                | (D << (10))))
                + ((E & F) | ((E | F) & D));
            G += T;
            C = T + T2;
            w14 += (((w12 >>> 17) | (w12 << (15))) ^ ((w12 >>> 19)
                | (w12 << (13))) ^ (w12 >>> 10)) + w7
                + (((w15 >>> 7) | (w15 << (25)))
                ^ ((w15 >>> 18) | (w15 << (14)))
                ^ (w15 >>> 3));
            T = B + (((G >>> 6) | (G << (26))) ^ ((G >>> 11)
                | (G << (21))) ^ ((G >>> 25)
                | (G << (7)))) + (((H ^ A) & G) ^ A)
                + k[r + 0xE] + w14;
            T2 = (((C >>> 2) | (C << (30))) ^ ((C >>> 13)
                | (C << (19))) ^ ((C >>> 22)
                | (C << (10))))
                + ((D & E) | ((D | E) & C));
            F += T;
            B = T + T2;
            w15 += (((w13 >>> 17) | (w13 << (15))) ^ ((w13 >>> 19)
                | (w13 << (13))) ^ (w13 >>> 10)) + w8
                + (((w0 >>> 7) | (w0 << (25)))
                ^ ((w0 >>> 18) | (w0 << (14)))
                ^ (w0 >>> 3));
            T = A + (((F >>> 6) | (F << (26))) ^ ((F >>> 11)
                | (F << (21))) ^ ((F >>> 25)
                | (F << (7)))) + (((G ^ H) & F) ^ H)
                + k[r + 0xF] + w15;
            T2 = (((B >>> 2) | (B << (30))) ^ ((B >>> 13)
                | (B << (19))) ^ ((B >>> 22)
                | (B << (10))))
                + ((C & D) | ((C | D) & B));
            E += T;
            A = T + T2;
        }

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
        long end = id + start + mod * 100_000;

        for (long i = start + id; i < end; i+= mod) {
//            count[id]++;
            if (hash(i, difficulty)) {
                return;
            }
        }
    }
}