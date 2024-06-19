package AMDTest;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAKeyPairGeneratorDemo {

	public static void main(String[] args) throws Exception {
		try {
			// generate RSA Key Pair
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			// get the pririvate and public keys
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			// save the Private key
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
			try (FileOutputStream fos = new FileOutputStream("private_key.pem")) {
				fos.write(Base64.getDecoder().decode(spec.getEncoded()));
			}
			// save the Public key
			X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
			try (FileOutputStream fos = new FileOutputStream("public_key.pem")) {
				fos.write(Base64.getEncoder().encode(encodedKeySpec.getEncoded()));
			}
			System.out.println("RSA Key Pair Generated and save private and public key");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

	}

}
