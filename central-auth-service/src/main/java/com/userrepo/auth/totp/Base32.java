package com.userrepo.auth.totp;

/**
 * RFC 4648 Base32 codec (A-Z2-7), uppercase, no padding, as expected by
 * Microsoft Authenticator / Google Authenticator for TOTP secrets. Decode is
 * case-insensitive and tolerates whitespace.
 */
public final class Base32 {

    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int[] DECODE_TABLE = new int[128];

    static {
        for (int i = 0; i < DECODE_TABLE.length; i++) {
            DECODE_TABLE[i] = -1;
        }
        for (int i = 0; i < ALPHABET.length; i++) {
            DECODE_TABLE[ALPHABET[i]] = i;
            DECODE_TABLE[Character.toLowerCase(ALPHABET[i])] = i;
        }
    }

    private Base32() {
    }

    public static String encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder out = new StringBuilder(((data.length * 8 + 4) / 5));
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            int v = b & 0xFF;
            buffer = (buffer << 8) | v;
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                out.append(ALPHABET[index]);
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            out.append(ALPHABET[index]);
        }
        return out.toString();
    }

    public static byte[] decode(String s) {
        if (s == null || s.isEmpty()) {
            return new byte[0];
        }
        // Strip whitespace/padding.
        String clean = s.replace(" ", "").replace("\t", "").replace("=", "").toUpperCase();
        int outLen = clean.length() * 5 / 8;
        byte[] out = new byte[outLen];
        int buffer = 0;
        int bitsLeft = 0;
        int idx = 0;
        for (int i = 0; i < clean.length(); i++) {
            char c = clean.charAt(i);
            int v = (c < 128) ? DECODE_TABLE[c] : -1;
            if (v < 0) {
                throw new IllegalArgumentException("Invalid Base32 character: " + c);
            }
            buffer = (buffer << 5) | v;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out[idx++] = (byte) ((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out;
    }
}
