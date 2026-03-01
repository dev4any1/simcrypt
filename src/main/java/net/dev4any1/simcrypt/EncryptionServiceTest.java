package net.dev4any1.simcrypt;

import net.dev4any1.simcrypt.Encryptor.CryptoKey;

/**
 * Manual smoke-test for EncryptionService. Run with: javac + java, or from your
 * IDE.
 */
public class EncryptionServiceTest {

	public static void main(String... args) throws Exception {
		Encryptor enc = new EncryptionService();
		String word = "TestToMatch16Bytes";

		// ── 1. Full cipher suite roundtrip ───────────────────────────────────
		System.out.println("=== Full cipher suite ===");
		int pass = 0, fail = 0;
		for (CryptoKey key : EncryptionService.getAllCryptoKeys()) {
			try {
				String encWord = enc.encrypt(word, key);
				String decWord = enc.decrypt(encWord, key);
				if (word.equals(decWord)) {
					pass++;
				} else {
					System.err.println("MISMATCH: " + key);
					fail++;
				}
			} catch (Exception e) {
				System.err.println("ERROR [" + key.algo() + "]: " + e.getMessage());
				fail++;
			}
		}
		System.out.println("Total: " + (pass + fail) + "  Pass: " + pass + "  Fail: " + fail);

		// ── 2. seal / open (self-contained token) ────────────────────────────
		System.out.println("\n=== seal / open ===");
		String token = enc.seal(word);
		System.out.println("Token  : " + token);
		String opened = enc.open(token);
		System.out.println("Opened : " + opened);
		System.out.println("Match  : " + word.equals(opened));

		// ── 3. CryptoKey serialization ───────────────────────────────────────
		System.out.println("\n=== CryptoKey serialize / deserialize ===");
		CryptoKey original = EncryptionService.randomStrongKey();
		String serial = original.serialize();
		CryptoKey restored = CryptoKey.deserialize(serial);
		System.out.println("Original  : " + original);
		System.out.println("Serialized: " + serial);
		System.out.println("Restored  : " + restored);
		System.out.println("Match     : " + original.equals(restored));

		// ── 4. Key tier stats ────────────────────────────────────────────────
		System.out.println("\n=== Key tiers ===");
		System.out.println("All    : " + EncryptionService.getAllCryptoKeys().size());
		System.out.println("Strong : " + EncryptionService.getStrongKeys().size());
		System.out.println("Legacy : " + EncryptionService.getLegacyKeys().size());
	}
}