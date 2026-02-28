package net.dev4any1.simcrypt;

import net.dev4any1.simcrypt.EncryptionService.CryptoKey;

public class EncryptionServiceTest {

	public static void main(String... args) throws Exception {
		EncryptionService enc = new EncryptionService();
		String word = "TestToMatch16Bytes";
		int i = 0;
		for (CryptoKey key : EncryptionService.getAllCryptoKeys()) {
			String encWord = enc.encrypt(word, key);
			String decWord = enc.decrypt(encWord, key);
			if (word.equals(decWord)) {
				System.out.println(key);
			} else {
				System.err.println(i++ + " Not a match for key - " + key);
			}
		}
	}
}
