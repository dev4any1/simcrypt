package net.dev4any1.simcrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptionService {

	private String secretKey = "Qcewntjno+YIZEC+M2M9XqWQuvNsmV6lsEZPkUG0KEk=";

	static {
		Security.addProvider(new BouncyCastleProvider());		
	}

	public record CryptoKey(String algo, int tag, int iv, String algoKey, int keyBits) {
	    public CryptoKey {
	        boolean isGcm = algo.contains("GCM");
	        if (isGcm && tag == 0)
	            throw new IllegalArgumentException("GCM requires non-zero tag (bits): " + algo);
	        if (!isGcm && tag != 0)
	            throw new IllegalArgumentException("tag must be 0 for non-AEAD algo: " + algo);
	        if (iv < 0)
	            throw new IllegalArgumentException("iv (bytes) cannot be negative");
	    }
	}

	private SecretKeySpec deriveKey(CryptoKey key) throws Exception {
		int requiredBytes = key.keyBits() / 8;
		byte[] masterBytes = Base64.getDecoder().decode(secretKey);
		// SHA-256 → 32 bytes (up to 256-bit keys)
		// SHA-512 → 64 bytes (Blowfish 448-bit = 56 bytes)
		String digestAlgo = requiredBytes <= 32 ? "SHA-256" : "SHA-512";
		byte[] derived = MessageDigest.getInstance(digestAlgo).digest(masterBytes);
		if (requiredBytes > derived.length)
			throw new IllegalStateException("Derived key too short for " + key.algo());
		return new SecretKeySpec(Arrays.copyOf(derived, requiredBytes), key.algoKey());
	}

	private static AlgorithmParameterSpec buildSpec(CryptoKey key, byte[] iv) {
		if (key.algo().contains("GCM"))
			return new GCMParameterSpec(key.tag(), iv); // tag=bits, iv[]= bytes

		if (key.algo().equals("ChaCha20"))
			return new ChaCha20ParameterSpec(iv, 0); // nonce=12 bytes, counter=0

		if (key.iv() > 0)
			return new IvParameterSpec(iv); // CBC, CTR, CFB, OFB, PCBC, ChaCha20-Poly1305

		return null; // ARCFOUR only
	}

	public String encrypt(String plainText, CryptoKey key) throws Exception {
		byte[] iv = new byte[key.iv()];
		new SecureRandom().nextBytes(iv);

		Cipher cipher = Cipher.getInstance(key.algo());
		AlgorithmParameterSpec spec = buildSpec(key, iv);
		if (spec != null)
			cipher.init(Cipher.ENCRYPT_MODE, deriveKey(key), spec);
		else
			cipher.init(Cipher.ENCRYPT_MODE, deriveKey(key));

		byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
		byte[] encryptedWithIv = new byte[key.iv() + encrypted.length];
		System.arraycopy(iv, 0, encryptedWithIv, 0, key.iv());
		System.arraycopy(encrypted, 0, encryptedWithIv, key.iv(), encrypted.length);
		return Base64.getEncoder().encodeToString(encryptedWithIv);
	}

	public String decrypt(String encryptedText, CryptoKey key) throws Exception {
		byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedText);
		byte[] iv = Arrays.copyOfRange(encryptedWithIv, 0, key.iv());
		byte[] encrypted = Arrays.copyOfRange(encryptedWithIv, key.iv(), encryptedWithIv.length);

		Cipher cipher = Cipher.getInstance(key.algo());
		AlgorithmParameterSpec spec = buildSpec(key, iv);
		if (spec != null)
			cipher.init(Cipher.DECRYPT_MODE, deriveKey(key), spec);
		else
			cipher.init(Cipher.DECRYPT_MODE, deriveKey(key));

		return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
	}

	public static List<CryptoKey> getAllCryptoKeys() {
		record ModeSpec(String mode, List<String> paddings) {
		}

		var aesModes = List.of(new ModeSpec("CBC", List.of("PKCS5Padding", "ISO10126Padding")),
				new ModeSpec("CTR", List.of("NoPadding")), new ModeSpec("CTS", List.of("NoPadding")),
				new ModeSpec("CFB", List.of("NoPadding", "PKCS5Padding", "ISO10126Padding")),
				new ModeSpec("CFB8", List.of("NoPadding", "PKCS5Padding", "ISO10126Padding")),
				new ModeSpec("OFB", List.of("NoPadding", "PKCS5Padding", "ISO10126Padding")),
				new ModeSpec("OFB8", List.of("NoPadding", "PKCS5Padding", "ISO10126Padding")),
				new ModeSpec("PCBC", List.of("PKCS5Padding", "ISO10126Padding")));

		var blowfishModes = List.of(new ModeSpec("CBC", List.of("PKCS5Padding", "ISO10126Padding")),
				new ModeSpec("CFB", List.of("NoPadding", "PKCS5Padding")), new ModeSpec("CFB8", List.of("NoPadding")),
				new ModeSpec("OFB", List.of("NoPadding", "PKCS5Padding")), new ModeSpec("OFB8", List.of("NoPadding")),
				new ModeSpec("CTR", List.of("NoPadding")),
				new ModeSpec("PCBC", List.of("PKCS5Padding", "ISO10126Padding")));

		var desModes = List.of(new ModeSpec("CBC", List.of("PKCS5Padding", "ISO10126Padding")),
				new ModeSpec("CFB", List.of("NoPadding")), new ModeSpec("CFB8", List.of("NoPadding")),
				new ModeSpec("OFB", List.of("NoPadding")), new ModeSpec("OFB8", List.of("NoPadding")),
				new ModeSpec("CTR", List.of("NoPadding")),
				new ModeSpec("PCBC", List.of("PKCS5Padding", "ISO10126Padding")));

		var rc2Modes = List.of(new ModeSpec("CBC", List.of("PKCS5Padding", "ISO10126Padding")),
				new ModeSpec("CFB", List.of("NoPadding")), new ModeSpec("OFB", List.of("NoPadding")),
				new ModeSpec("CTR", List.of("NoPadding")));

		var all = new ArrayList<CryptoKey>();

		// AES block modes: iv=16 bytes, tag=0
		for (var m : aesModes)
			for (var pad : m.paddings())
				for (int ks : new int[] { 128, 192, 256 })
					all.add(new CryptoKey("AES/" + m.mode() + "/" + pad, 0, 16, "AES", ks));

		// AES-GCM: iv=12 bytes, tag in bits
		for (int tag : new int[] { 96, 104, 112, 120, 128 })
			for (int ks : new int[] { 128, 192, 256 })
				all.add(new CryptoKey("AES/GCM/NoPadding", tag, 12, "AES", ks));

		// Blowfish: iv=8 bytes, tag=0
		for (var m : blowfishModes)
			for (var pad : m.paddings())
				for (int ks : new int[] { 128, 192, 256, 448 })
					all.add(new CryptoKey("Blowfish/" + m.mode() + "/" + pad, 0, 8, "Blowfish", ks));

		// DES: iv=8 bytes, tag=0, 64-bit key
		for (var m : desModes)
			for (var pad : m.paddings())
				all.add(new CryptoKey("DES/" + m.mode() + "/" + pad, 0, 8, "DES", 64));

		// DESede: iv=8 bytes, tag=0 — JDK only accepts 192-bit (24 bytes)
		for (var m : desModes)
			for (var pad : m.paddings())
				all.add(new CryptoKey("DESede/" + m.mode() + "/" + pad, 0, 8, "DESede", 192));

		// RC2: iv=8 bytes, tag=0
		for (var m : rc2Modes)
			for (var pad : m.paddings())
				for (int ks : new int[] { 40, 64, 128 })
					all.add(new CryptoKey("RC2/" + m.mode() + "/" + pad, 0, 8, "RC2", ks));

		// ARCFOUR: no iv, no tag
		for (int ks : new int[] { 40, 56, 64, 80, 128 })
			all.add(new CryptoKey("ARCFOUR", 0, 0, "ARCFOUR", ks));

		// ChaCha20 bare stream: no iv, no tag
		all.add(new CryptoKey("ChaCha20", 0, 12, "ChaCha20", 256));

		// ChaCha20-Poly1305: iv=12 bytes, tag handled internally (0 here)
		all.add(new CryptoKey("ChaCha20-Poly1305", 0, 12, "ChaCha20", 256));

		// ── BouncyCastle algorithms ──────────────────────────────────────────────

		// Twofish: 128-bit block, iv=16
		var twofishModes = List.of(
		    new ModeSpec("CBC",  List.of("PKCS5Padding", "ISO10126Padding")),
		    new ModeSpec("CTR",  List.of("NoPadding")),
		    new ModeSpec("CFB",  List.of("NoPadding")),
		    new ModeSpec("CFB8", List.of("NoPadding")),
		    new ModeSpec("OFB",  List.of("NoPadding")),
		    new ModeSpec("GCM",  List.of("NoPadding")));  // BC supports GCM for Twofish

		for (var m : twofishModes)
		    for (var pad : m.paddings())
		        for (int ks : new int[]{128, 192, 256})
		            if (m.mode().equals("GCM"))
		                all.add(new CryptoKey("Twofish/GCM/NoPadding", 128, 16, "Twofish", ks));
		            else
		                all.add(new CryptoKey("Twofish/" + m.mode() + "/" + pad, 0, 16, "Twofish", ks));

		// Serpent: 128-bit block, iv=16
		var serpentModes = List.of(
		    new ModeSpec("CBC",  List.of("PKCS5Padding", "ISO10126Padding")),
		    new ModeSpec("CTR",  List.of("NoPadding")),
		    new ModeSpec("CFB",  List.of("NoPadding")),
		    new ModeSpec("OFB",  List.of("NoPadding")));

		for (var m : serpentModes)
		    for (var pad : m.paddings())
		        for (int ks : new int[]{128, 192, 256})
		            all.add(new CryptoKey("Serpent/" + m.mode() + "/" + pad, 0, 16, "Serpent", ks));

		// Camellia: 128-bit block, iv=16
		for (var m : serpentModes)
		    for (var pad : m.paddings())
		        for (int ks : new int[]{128, 192, 256})
		            all.add(new CryptoKey("Camellia/" + m.mode() + "/" + pad, 0, 16, "Camellia", ks));

		// CAST5: 64-bit block, iv=8, key 40-128 bits
		var cast5Modes = List.of(
		    new ModeSpec("CBC",  List.of("PKCS5Padding")),
		    new ModeSpec("CTR",  List.of("NoPadding")),
		    new ModeSpec("CFB",  List.of("NoPadding")),
		    new ModeSpec("OFB",  List.of("NoPadding")));

		for (var m : cast5Modes)
		    for (var pad : m.paddings())
		        for (int ks : new int[]{40, 64, 128})
		            all.add(new CryptoKey("CAST5/" + m.mode() + "/" + pad, 0, 8, "CAST5", ks));

		// CAST6: 128-bit block, iv=16
		for (var m : serpentModes)
		    for (var pad : m.paddings())
		        for (int ks : new int[]{128, 192, 256})
		            all.add(new CryptoKey("CAST6/" + m.mode() + "/" + pad, 0, 16, "CAST6", ks));

		// IDEA: 64-bit block, iv=8, fixed 128-bit key
		for (var m : cast5Modes)
		    for (var pad : m.paddings())
		        all.add(new CryptoKey("IDEA/" + m.mode() + "/" + pad, 0, 8, "IDEA", 128));

		// SEED: 128-bit block, iv=16, fixed 128-bit key (Korean standard)
		for (var m : serpentModes)
		    for (var pad : m.paddings())
		        all.add(new CryptoKey("SEED/" + m.mode() + "/" + pad, 0, 16, "SEED", 128));

		// ARIA: 128-bit block, iv=16 (Korean standard)
		for (var m : serpentModes)
		    for (var pad : m.paddings())
		        for (int ks : new int[]{128, 192, 256})
		            all.add(new CryptoKey("ARIA/" + m.mode() + "/" + pad, 0, 16, "ARIA", ks));

		// SM4: 128-bit block, iv=16, fixed 128-bit key (Chinese standard)
		for (var m : serpentModes)
		    for (var pad : m.paddings())
		        all.add(new CryptoKey("SM4/" + m.mode() + "/" + pad, 0, 16, "SM4", 128));

		// ── BC stream ciphers ────────────────────────────────────────────────────

		// HC-128: 128-bit key, 128-bit iv
		all.add(new CryptoKey("HC128", 0, 16, "HC128", 128));

		// HC-256: 256-bit key, 256-bit iv
		all.add(new CryptoKey("HC256", 0, 32, "HC256", 256));

		// Salsa20: 256-bit key, 8-byte iv
		all.add(new CryptoKey("Salsa20", 0, 8, "Salsa20", 256));

		// XSalsa20: 256-bit key, 24-byte iv
		all.add(new CryptoKey("XSalsa20", 0, 24, "XSalsa20", 256));

		// GRAIN-128: 128-bit key, 12-byte iv
		all.add(new CryptoKey("Grain128", 0, 12, "Grain128", 128));

		return all;
	}

	public static CryptoKey getRandomCryptoKey() {
		List<CryptoKey> all = getAllCryptoKeys();
		return all.get(new SecureRandom().nextInt(all.size()));
	}
}