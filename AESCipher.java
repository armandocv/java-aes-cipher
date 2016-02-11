import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implementation of AES Supports Oracle's default AES mode
 * (AES/CBC/PKCS5Padding)
 * 
 * @author Armando Carrasco
 */

public class AESCipher {

	// default block size
	public static int blockSize = 16;

	// ciphers
	Cipher encryptCipher = null;
	Cipher decryptCipher = null;

	// key
	byte[] key = null;
	// the initialization vector needed by the CBC mode
	byte[] IV = null;

	public AESCipher() {
		// private key
		key = "YOUR_KEY".getBytes();
		// default IV value initialized with 0
		IV = new byte[blockSize];
	}

	public AESCipher(String pass, byte[] iv) {
		// get the key and the IV
		key = pass.getBytes();
		IV = new byte[blockSize];
		System.arraycopy(iv, 0, IV, 0, iv.length);
	}

	public AESCipher(byte[] pass, byte[] iv) {
		// get the key and the IV
		key = new byte[pass.length];
		System.arraycopy(pass, 0, key, 0, pass.length);
		IV = new byte[blockSize];
		System.arraycopy(iv, 0, IV, 0, iv.length);
	}

	public void initCiphers() throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		// create ciphers
		encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		// create the key
		SecretKey keyValue = new SecretKeySpec(key, "AES");
		// create the IV
		AlgorithmParameterSpec IVspec = new IvParameterSpec(IV);

		// init ciphers
		encryptCipher.init(Cipher.ENCRYPT_MODE, keyValue, IVspec);
		decryptCipher.init(Cipher.DECRYPT_MODE, keyValue, IVspec);
	}

	public void resetCiphers() {
		encryptCipher = null;
		decryptCipher = null;
	}

	public String cbcEncrypt(String input) throws IllegalBlockSizeException,
			BadPaddingException {
		byte[] bytes = encryptCipher.doFinal(input.getBytes());
		return toHexString(bytes);
	}

	public String cbcDecrypt(String input) throws IllegalBlockSizeException,
			BadPaddingException {
		byte[] bytes = decryptCipher.doFinal(hexStringToByteArray(input));
		return new String(bytes);
	}

	private static String toHexString(byte buf[]) {
		StringBuilder strbuf = new StringBuilder(buf.length * 2);
		int i;

		for (i = 0; i < buf.length; i++) {
			if (((int) buf[i] & 0xff) < 0x10) {
				strbuf.append("0");
			}
			strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
		}

		return strbuf.toString();
	}

	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
					.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	public static void main(String args[]) {
		try {
			AESCipher cipher = new AESCipher();
			cipher.initCiphers();
			String encrypted = cipher.cbcEncrypt("HelloWorld!");
			String decrypted = cipher.cbcDecrypt(encrypted);

			System.out.println(encrypted);
			System.out.println(decrypted);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
