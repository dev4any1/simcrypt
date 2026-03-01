package net.dev4any1.simcrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Symmetric encryption service covering all JDK SunJCE + BouncyCastle ciphers.
 *
 * <h2>Quickstart</h2>
 * <pre>{@code
 * // Generate and store your master key once:
 * String masterKey = EncryptionService.generateMasterKey();
 *
 * Encryptor sc = new EncryptionService(masterKey);
 *
 * String token = sc.seal("my API key");   // random strong cipher, self-contained
 * String plain  = sc.open(token);
 * }</pre>
 *
 * <h2>Advanced usage</h2>
 * <pre>{@code
 * CryptoKey key = EncryptionService.randomKey();         // any of ~400 ciphers
 * CryptoKey key = EncryptionService.randomStrongKey();   // AEAD / modern stream only
 *
 * String enc = sc.encrypt("data", key);
 * String dec = sc.decrypt(enc, key);
 *
 * String    serial   = key.serialize();
 * CryptoKey restored = CryptoKey.deserialize(serial);
 * }</pre>
 */
public class EncryptionService implements Encryptor {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final List<CryptoKey> ALL_KEYS    = Encryptor.buildAllKeys();
    private static final List<CryptoKey> STRONG_KEYS = ALL_KEYS.stream().filter(CryptoKey::isStrong).toList();
    private static final List<CryptoKey> LEGACY_KEYS = ALL_KEYS.stream().filter(CryptoKey::isLegacy).toList();

    private final byte[] masterKeyBytes;
    private final ConcurrentHashMap<CryptoKey, SecretKeySpec> keyCache = new ConcurrentHashMap<>();

    /** Production constructor — pass your Base64-encoded 32-byte master key. */
    public EncryptionService(String base64MasterKey) {
        this.masterKeyBytes = Base64.getDecoder().decode(base64MasterKey);
    }

    /** Test constructor — uses a random master key. DO NOT use in production. */
    public EncryptionService() {
        this.masterKeyBytes = Base64.getDecoder().decode(generateMasterKey());
    }

    /**
     * Generates a cryptographically random 32-byte master key, Base64-encoded.
     * Run once and store in an environment variable or secrets vault.
     *
     * <pre>{@code
     * System.out.println(EncryptionService.generateMasterKey());
     * // Then: new EncryptionService(System.getenv("ENCRYPTION_KEY"))
     * }</pre>
     */
    public static String generateMasterKey() {
        byte[] key = new byte[32];
        SECURE_RANDOM.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    private SecretKeySpec deriveKey(CryptoKey key) throws Exception {
        SecretKeySpec cached = keyCache.get(key);
        if (cached != null) return cached;

        int requiredBytes = key.keyBits() / 8;
        String digestAlgo = requiredBytes <= 32 ? "SHA-256" : "SHA-512";
        byte[] derived = MessageDigest.getInstance(digestAlgo).digest(masterKeyBytes);
        if (requiredBytes > derived.length)
            throw new IllegalStateException("Derived key too short for " + key.algo()
                + " (" + requiredBytes + " bytes needed, " + derived.length + " available)");

        SecretKeySpec spec = new SecretKeySpec(Arrays.copyOf(derived, requiredBytes), key.algoKey());
        keyCache.put(key, spec);
        return spec;
    }

    private static AlgorithmParameterSpec buildSpec(CryptoKey key, byte[] iv) {
        if (key.algo().contains("GCM"))    return new GCMParameterSpec(key.tag(), iv);
        if (key.algo().equals("ChaCha20")) return new ChaCha20ParameterSpec(iv, 0);
        if (key.iv() > 0)                  return new IvParameterSpec(iv);
        return null;
    }

    @Override
    public String encrypt(String plainText, CryptoKey key) throws Exception {
        byte[] iv = new byte[key.iv()];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(key.algo());
        AlgorithmParameterSpec spec = buildSpec(key, iv);
        if (spec != null) cipher.init(Cipher.ENCRYPT_MODE, deriveKey(key), spec);
        else              cipher.init(Cipher.ENCRYPT_MODE, deriveKey(key));

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] blob = new byte[key.iv() + encrypted.length];
        System.arraycopy(iv,        0, blob, 0,        key.iv());
        System.arraycopy(encrypted, 0, blob, key.iv(), encrypted.length);
        return Base64.getEncoder().encodeToString(blob);
    }

    @Override
    public String decrypt(String encryptedText, CryptoKey key) throws Exception {
        byte[] blob      = Base64.getDecoder().decode(encryptedText);
        byte[] iv        = Arrays.copyOfRange(blob, 0,        key.iv());
        byte[] encrypted = Arrays.copyOfRange(blob, key.iv(), blob.length);

        Cipher cipher = Cipher.getInstance(key.algo());
        AlgorithmParameterSpec spec = buildSpec(key, iv);
        if (spec != null) cipher.init(Cipher.DECRYPT_MODE, deriveKey(key), spec);
        else              cipher.init(Cipher.DECRYPT_MODE, deriveKey(key));

        return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
    }

    @Override
    public String seal(String plainText) throws Exception {
        return seal(plainText, randomStrongKey());
    }

    @Override
    public String seal(String plainText, CryptoKey key) throws Exception {
        String ciphertext  = encrypt(plainText, key);
        byte[] keyBytes    = key.serialize().getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = ciphertext.getBytes(StandardCharsets.UTF_8);

        byte[] blob = new byte[4 + keyBytes.length + cipherBytes.length];
        blob[0] = (byte)(keyBytes.length >> 24);
        blob[1] = (byte)(keyBytes.length >> 16);
        blob[2] = (byte)(keyBytes.length >>  8);
        blob[3] = (byte)(keyBytes.length);
        System.arraycopy(keyBytes,    0, blob, 4,                   keyBytes.length);
        System.arraycopy(cipherBytes, 0, blob, 4 + keyBytes.length, cipherBytes.length);
        return Base64.getEncoder().encodeToString(blob);
    }

    @Override
    public String open(String token) throws Exception {
        byte[] blob  = Base64.getDecoder().decode(token);
        int keyLen   = ((blob[0] & 0xFF) << 24) | ((blob[1] & 0xFF) << 16)
                     | ((blob[2] & 0xFF) <<  8) |  (blob[3] & 0xFF);
        CryptoKey key    = CryptoKey.deserialize(new String(blob, 4, keyLen, StandardCharsets.UTF_8));
        String ciphertext = new String(blob, 4 + keyLen, blob.length - 4 - keyLen, StandardCharsets.UTF_8);
        return decrypt(ciphertext, key);
    }

    public static CryptoKey randomKey()       { return ALL_KEYS.get(SECURE_RANDOM.nextInt(ALL_KEYS.size())); }
    public static CryptoKey randomStrongKey() { return STRONG_KEYS.get(SECURE_RANDOM.nextInt(STRONG_KEYS.size())); }
    public static List<CryptoKey> getAllCryptoKeys() { return ALL_KEYS; }
    public static List<CryptoKey> getStrongKeys()    { return STRONG_KEYS; }
    public static List<CryptoKey> getLegacyKeys()    { return LEGACY_KEYS; }
}