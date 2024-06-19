package AMDTest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class RSAEncryptionDecryptionDemo {

	public static void main(String[] args) throws Exception {
		// generate RSA key pair

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair pair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();

		// save then key files

		saveKeyToFile("public_key.der", publicKey.getEncoded());
		saveKeyToFile("private_key.der", privateKey.getEncoded());

		// File paths

		String originalFilePath = "test.txt";
		String encryptedFilePath = "encryption_file.bin";
		String decryptedFilePath = "decryption_file.txt";

		// create encrypt file

		String data = "This is a RSA encrypted and decrypted implementation";
		try (FileOutputStream fos = new FileOutputStream(originalFilePath)) {
			fos.write(data.getBytes());
		}
		// encrypt file

		encryptFile(originalFilePath, encryptedFilePath, publicKey);
		// decrypt file
		decryptFile(encryptedFilePath, decryptedFilePath, privateKey);

	}

	private static void decryptFile(String inputFilePath, String outputFilePath, PrivateKey privateKey)
			throws Exception {
		byte[] inputBytes = readFileToFileBytes(inputFilePath);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedBytes = cipher.doFinal(inputBytes);

		try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
			fos.write(decryptedBytes);
		}
	}

	private static byte[] readFileToFileBytes(String filePath) throws FileNotFoundException, IOException {
		File file = new File(filePath);
		byte[] filedata = new byte[(int) file.length()];
		try (FileInputStream fis = new FileInputStream(file)) {
			fis.read(filedata);
		}
		return filedata;
	}

	private static void encryptFile(String inputFilePath, String outputFilePath, PublicKey publicKey) throws Exception {
		byte[] inputBytes = readFileToFileBytes(inputFilePath);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedBytes = cipher.doFinal(inputBytes);

		try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
			fos.write(encryptedBytes);
		}

	}

	public static PublicKey loadPublicKeyFromFile(String filePath) throws Exception {

		byte[] keyBytes = readFileToFileBytes(filePath);
		X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(encodedKeySpec);
	}

	public static PrivateKey loadPrivateKeyFromFile(String filePath) throws Exception {

		byte[] keyBytes = readFileToFileBytes(filePath);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(spec);
	}

	private static void saveKeyToFile(String filename, byte[] key) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(filename)) {
			fos.write(key);
		}
	}

}
