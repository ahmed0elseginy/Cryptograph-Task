package com.ac.service;

// Done
public class SHA1Service {

    public String hash(String text) {
        byte[] message = text.getBytes();
        int[] h = {
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0
        };

        int messageLength = message.length;
        int numBlocks = ((messageLength + 8) >>> 6) + 1;
        int totalLength = numBlocks * 64;
        byte[] padded = new byte[totalLength];

        System.arraycopy(message, 0, padded, 0, messageLength);
        padded[messageLength] = (byte) 0x80;

        long messageLengthBits = (long) messageLength * 8;
        for (int i = 0; i < 8; i++) {
            padded[totalLength - 1 - i] = (byte) (messageLengthBits >>> (8 * i));
        }

        int[] w = new int[80];
        for (int block = 0; block < numBlocks; block++) {
            int index = block * 64;

            for (int i = 0; i < 16; i++) {
                w[i] = ((padded[index + 4 * i] & 0xFF) << 24) |
                        ((padded[index + 4 * i + 1] & 0xFF) << 16) |
                        ((padded[index + 4 * i + 2] & 0xFF) << 8) |
                        (padded[index + 4 * i + 3] & 0xFF);
            }

            for (int i = 16; i < 80; i++) {
                w[i] = Integer.rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }

            int a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

            for (int i = 0; i < 80; i++) {
                int f, k;
                if (i < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                int temp = Integer.rotateLeft(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = Integer.rotateLeft(b, 30);
                b = a;
                a = temp;
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
        }

        return toHexString(h);
    }

    public boolean verify(String text, String expectedHash) {
        return hash(text).equals(expectedHash);
    }

    private String toHexString(int[] hashParts) {
        StringBuilder hex = new StringBuilder();
        for (int part : hashParts) {
            String segment = Integer.toHexString(part);
            while (segment.length() < 8) {
                segment = "0" + segment;
            }
            hex.append(segment);
        }
        return hex.toString();
    }
}
