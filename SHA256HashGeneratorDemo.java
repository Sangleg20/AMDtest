package AMDTest;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256HashGeneratorDemo {

	public static void main(String[] args) throws Exception {

		if (args.length != 1) {
			System.out.println("Used java SH256HashGeneratorDemo<file Path>");
			return;
		}
		String filePath = args[0];
		try {
			byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
			byte[] hash = generateSHA256Hash(fileBytes);
			System.out.println(bytesToHex(hash));

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	private static String bytesToHex(byte[] hash) {
		StringBuilder stringBuilder = new StringBuilder();
		for (byte b : hash) {
			String hex = Integer.toHexString(0xff & b);
			if (hex.length() == 1) {
				stringBuilder.append('0');
			}
			stringBuilder.append(hex);
		}
		return stringBuilder.toString();
	}

	private static byte[] generateSHA256Hash(byte[] input) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		return messageDigest.digest(input);
	}
}
