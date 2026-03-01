package net.dev4any1.simcrypt;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

/**
 * Core symmetric encryption contract.
 *
 * <p>Use {@link EncryptionService} as the implementation:
 * <pre>{@code
 * Encryptor sc = new EncryptionService(myBase64MasterKey);
 *
 * String token = sc.seal("secret");   // random strong cipher, self-contained token
 * String plain = sc.open(token);
 * }</pre>
 */
public interface Encryptor {

    /** Encrypts {@code plainText} with the given cipher. IV is prepended to the returned Base64 blob. */
    String encrypt(String plainText, CryptoKey key) throws Exception;

    /** Decrypts a Base64 blob produced by {@link #encrypt}. */
    String decrypt(String encryptedText, CryptoKey key) throws Exception;

    /**
     * Seals plaintext with a random strong cipher.
     * The returned token is self-contained — no external key tracking needed.
     * Use {@link #open} to reverse it.
     */
    String seal(String plainText) throws Exception;

    /**
     * Seals plaintext with a specific cipher key.
     * Useful when you want to control which algorithm is used.
     */
    String seal(String plainText, CryptoKey key) throws Exception;

    /** Opens a token produced by {@link #seal}. Cipher metadata is embedded in the token. */
    String open(String token) throws Exception;

    // ── CryptoKey ────────────────────────────────────────────────────────────

    /**
     * A fully-specified cipher configuration. Immutable and safe to cache.
     *
     * @param algo    JCE algorithm string, e.g. {@code "AES/GCM/NoPadding"}
     * @param tag     GCM auth-tag length in <em>bits</em> (0 for non-AEAD)
     * @param iv      IV / nonce size in <em>bytes</em> (0 for ARCFOUR)
     * @param algoKey Key algorithm name for {@link SecretKeySpec}, e.g. {@code "AES"}
     * @param keyBits Key size in bits
     */
    record CryptoKey(String algo, int tag, int iv, String algoKey, int keyBits) {

        public CryptoKey {
            boolean isGcm = algo.contains("GCM");
            if (isGcm && tag == 0)
                throw new IllegalArgumentException("GCM requires non-zero tag (bits): " + algo);
            if (!isGcm && tag != 0)
                throw new IllegalArgumentException("tag must be 0 for non-AEAD algo: " + algo);
            if (iv < 0)
                throw new IllegalArgumentException("iv (bytes) cannot be negative");
        }

        /**
         * Serializes to a compact colon-delimited string safe for DB storage.
         * Format: {@code algo:tag:iv:algoKey:keyBits}  (slashes in algo escaped as pipes)
         */
        public String serialize() {
            return algo.replace("/", "|") + ":" + tag + ":" + iv + ":" + algoKey + ":" + keyBits;
        }

        /** Restores a key from a string produced by {@link #serialize()}. */
        public static CryptoKey deserialize(String token) {
            String[] p = token.split(":");
            if (p.length != 5)
                throw new IllegalArgumentException("Invalid CryptoKey token: " + token);
            return new CryptoKey(
                p[0].replace("|", "/"),
                Integer.parseInt(p[1]),
                Integer.parseInt(p[2]),
                p[3],
                Integer.parseInt(p[4])
            );
        }

        /** True if this cipher provides authenticated encryption (AEAD). */
        public boolean isAead() {
            return algo.contains("GCM") || algo.contains("Poly1305")
                || algo.contains("EAX") || algo.contains("CCM") || algo.contains("OCB");
        }

        /** True if this cipher is considered cryptographically strong (AEAD or modern stream). */
        public boolean isStrong() {
            return isAead()
                || algo.startsWith("ChaCha20")
                || algo.startsWith("Salsa20")
                || algo.startsWith("XSalsa20");
        }

        /** True if this cipher is considered legacy / weak (DES, RC2, RC4, ARCFOUR, …). */
        public boolean isLegacy() {
            String a = algo.toUpperCase();
            return a.startsWith("DES") || a.startsWith("RC2") || a.startsWith("ARCFOUR")
                || a.startsWith("RC4") || a.startsWith("SKIPJACK") || a.startsWith("TEA")
                || a.startsWith("XTEA") || a.startsWith("GOST");
        }
    }

    // ── Key registry (private — implementation detail) ───────────────────────

    /** Builds the full cipher key list. Called once at class load by {@link EncryptionService}. */
    private static List<CryptoKey> buildAllKeysInternal() {
        record ModeSpec(String mode, List<String> paddings) {}

        var aesModes = List.of(
            new ModeSpec("CBC",  List.of("PKCS5Padding", "ISO10126Padding")),
            new ModeSpec("CTR",  List.of("NoPadding")),
            new ModeSpec("CTS",  List.of("NoPadding")),
            new ModeSpec("CFB",  List.of("NoPadding", "PKCS5Padding", "ISO10126Padding")),
            new ModeSpec("CFB8", List.of("NoPadding", "PKCS5Padding", "ISO10126Padding")),
            new ModeSpec("OFB",  List.of("NoPadding", "PKCS5Padding", "ISO10126Padding")),
            new ModeSpec("OFB8", List.of("NoPadding", "PKCS5Padding", "ISO10126Padding")),
            new ModeSpec("PCBC", List.of("PKCS5Padding", "ISO10126Padding")));

        var blowfishModes = List.of(
            new ModeSpec("CBC",  List.of("PKCS5Padding", "ISO10126Padding")),
            new ModeSpec("CFB",  List.of("NoPadding", "PKCS5Padding")),
            new ModeSpec("CFB8", List.of("NoPadding")),
            new ModeSpec("OFB",  List.of("NoPadding", "PKCS5Padding")),
            new ModeSpec("OFB8", List.of("NoPadding")),
            new ModeSpec("CTR",  List.of("NoPadding")),
            new ModeSpec("PCBC", List.of("PKCS5Padding", "ISO10126Padding")));

        var desModes = List.of(
            new ModeSpec("CBC",  List.of("PKCS5Padding", "ISO10126Padding")),
            new ModeSpec("CFB",  List.of("NoPadding")),
            new ModeSpec("CFB8", List.of("NoPadding")),
            new ModeSpec("OFB",  List.of("NoPadding")),
            new ModeSpec("OFB8", List.of("NoPadding")),
            new ModeSpec("CTR",  List.of("NoPadding")),
            new ModeSpec("PCBC", List.of("PKCS5Padding", "ISO10126Padding")));

        var rc2Modes = List.of(
            new ModeSpec("CBC", List.of("PKCS5Padding", "ISO10126Padding")),
            new ModeSpec("CFB", List.of("NoPadding")),
            new ModeSpec("OFB", List.of("NoPadding")),
            new ModeSpec("CTR", List.of("NoPadding")));

        var bcBlock128Modes = List.of(
            new ModeSpec("CBC", List.of("PKCS5Padding", "ISO10126Padding")),
            new ModeSpec("CTR", List.of("NoPadding")),
            new ModeSpec("CFB", List.of("NoPadding")),
            new ModeSpec("OFB", List.of("NoPadding")));

        var bcBlock64Modes = List.of(
            new ModeSpec("CBC", List.of("PKCS5Padding")),
            new ModeSpec("CTR", List.of("NoPadding")),
            new ModeSpec("CFB", List.of("NoPadding")),
            new ModeSpec("OFB", List.of("NoPadding")));

        var all = new ArrayList<CryptoKey>();

        // ── JDK SunJCE ───────────────────────────────────────────────────────
        for (var m : aesModes)
            for (var pad : m.paddings())
                for (int ks : new int[]{128, 192, 256})
                    all.add(new CryptoKey("AES/" + m.mode() + "/" + pad, 0, 16, "AES", ks));

        for (int tag : new int[]{96, 104, 112, 120, 128})
            for (int ks : new int[]{128, 192, 256})
                all.add(new CryptoKey("AES/GCM/NoPadding", tag, 12, "AES", ks));

        for (var m : blowfishModes)
            for (var pad : m.paddings())
                for (int ks : new int[]{128, 192, 256, 448})
                    all.add(new CryptoKey("Blowfish/" + m.mode() + "/" + pad, 0, 8, "Blowfish", ks));

        for (var m : desModes)
            for (var pad : m.paddings())
                all.add(new CryptoKey("DES/" + m.mode() + "/" + pad, 0, 8, "DES", 64));

        for (var m : desModes)
            for (var pad : m.paddings())
                all.add(new CryptoKey("DESede/" + m.mode() + "/" + pad, 0, 8, "DESede", 192));

        for (var m : rc2Modes)
            for (var pad : m.paddings())
                for (int ks : new int[]{40, 64, 128})
                    all.add(new CryptoKey("RC2/" + m.mode() + "/" + pad, 0, 8, "RC2", ks));

        for (int ks : new int[]{40, 56, 64, 80, 128})
            all.add(new CryptoKey("ARCFOUR", 0, 0, "ARCFOUR", ks));

        all.add(new CryptoKey("ChaCha20",        0, 12, "ChaCha20", 256));
        all.add(new CryptoKey("ChaCha20-Poly1305",0, 12, "ChaCha20", 256));

        // ── BouncyCastle — 128-bit block ─────────────────────────────────────
        for (String algo : new String[]{"Twofish", "Serpent", "Camellia", "CAST6",
                                        "ARIA", "SEED", "RC6", "Noekeon"}) {
            int[] keySizes = algo.equals("SEED") || algo.equals("Noekeon")
                ? new int[]{128} : new int[]{128, 192, 256};
            for (var m : bcBlock128Modes)
                for (var pad : m.paddings())
                    for (int ks : keySizes)
                        all.add(new CryptoKey(algo + "/" + m.mode() + "/" + pad, 0, 16, algo, ks));
        }

        // GCM variants for BC 128-bit block ciphers
        for (String algo : new String[]{"Twofish", "Camellia", "ARIA", "SM4"}) {
            int[] keySizes = algo.equals("SM4") ? new int[]{128} : new int[]{128, 192, 256};
            int gcmIv = algo.equals("Twofish") ? 16 : 12;
            for (int ks : keySizes)
                all.add(new CryptoKey(algo + "/GCM/NoPadding", 128, gcmIv, algo, ks));
        }

        // SM4 non-GCM modes
        for (var m : bcBlock128Modes)
            for (var pad : m.paddings())
                all.add(new CryptoKey("SM4/" + m.mode() + "/" + pad, 0, 16, "SM4", 128));

        // DSTU7624 / Kalyna
        for (var m : bcBlock128Modes)
            for (var pad : m.paddings())
                for (int ks : new int[]{128, 256})
                    all.add(new CryptoKey("DSTU7624/" + m.mode() + "/" + pad, 0, 16, "DSTU7624", ks));

        // ── BouncyCastle — 64-bit block ──────────────────────────────────────
        for (var m : bcBlock64Modes) for (var pad : m.paddings())
            for (int ks : new int[]{40, 64, 128})
                all.add(new CryptoKey("CAST5/" + m.mode() + "/" + pad, 0, 8, "CAST5", ks));

        for (String algo : new String[]{"IDEA", "TEA", "XTEA"})
            for (var m : bcBlock64Modes) for (var pad : m.paddings())
                all.add(new CryptoKey(algo + "/" + m.mode() + "/" + pad, 0, 8, algo, 128));

        for (var m : bcBlock64Modes) for (var pad : m.paddings())
            all.add(new CryptoKey("SKIPJACK/" + m.mode() + "/" + pad, 0, 8, "SKIPJACK", 80));

        for (var m : bcBlock64Modes) for (var pad : m.paddings())
            all.add(new CryptoKey("GOST28147/" + m.mode() + "/" + pad, 0, 8, "GOST28147", 256));

        // ── BouncyCastle — Stream ciphers ────────────────────────────────────
        all.add(new CryptoKey("HC128",    0, 16, "HC128",    128));
        all.add(new CryptoKey("HC256",    0, 32, "HC256",    256));
        all.add(new CryptoKey("Salsa20",  0,  8, "Salsa20",  256));
        all.add(new CryptoKey("XSalsa20", 0, 24, "XSalsa20", 256));
        all.add(new CryptoKey("Grain128", 0, 12, "Grain128", 128));

        return List.copyOf(all); // immutable
    }

    /** Called once by {@link EncryptionService} static initializer. */
    static List<CryptoKey> buildAllKeys() {
        return buildAllKeysInternal();
    }
}