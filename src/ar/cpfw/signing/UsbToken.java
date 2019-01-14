package ar.cpfw.signing;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Objects;

import sun.security.pkcs11.SunPKCS11;

public class UsbToken {

	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA1withRSA";
	private String tokenLibraryPath;
	
	public UsbToken(String tokenLibraryPath) {
		Objects.nonNull(tokenLibraryPath);
		if (Files.notExists(Paths.get(tokenLibraryPath))) {
			throw new RuntimeException("The library file is not found, check if the path is correct");
		}
		this.tokenLibraryPath = tokenLibraryPath;
	}

	public PublicKey publicKey(String tokenPassword) {	
		try {
			KeyStore keyStore = retrieveKeyStore(tokenPassword);
			return keyStore.getCertificate(keyStore.aliases().nextElement()).getPublicKey();

		} catch (Exception e) {
			throw new RuntimeException("Ups, something went wrong... ", e);
		} 
	}
	
	/**
	 * Digital Sign a text string.
	 * 
	 * @return a signature hash value
	 * @param signatureAlgorithm valid values:
	 * 	 https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature
	 * */
	public byte[] signText(String textToSign, String tokenPassword, String signatureAlgorithm) {	
		Objects.nonNull(textToSign); 
		Objects.nonNull(tokenPassword);
		Objects.nonNull(signatureAlgorithm);

		try {
			KeyStore keyStore = retrieveKeyStore(tokenPassword);
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStore.aliases().nextElement(), null);

			Signature signature = Signature.getInstance(signatureAlgorithm);
			signature.initSign(privateKey);
			byte[] toBeSigned = textToSign.getBytes();
			signature.update(toBeSigned);
			return signature.sign();
			
		} catch (Exception e) {
			throw new RuntimeException("Ups, something went wrong... ", e);
		} 
	}

	/**
	 * Digital Sign a text string using SHA1withRSA signature algorithm
	 * 
	 * @return a signature hash value
	 * @param signatureAlgorithm valid values:
	 * 	 https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature
	 * */
	public byte[] signText(String textToSign, String tokenPassword) {	
		return this.signText(textToSign, tokenPassword, DEFAULT_SIGNATURE_ALGORITHM);
	}
	
	private KeyStore retrieveKeyStore(String tokenPassword) throws Exception {
		Objects.nonNull(tokenPassword);
		
		File tmpConfigFile = File.createTempFile("pkcs11-", "conf");
		tmpConfigFile.deleteOnExit();
		try (PrintWriter configWriter = new PrintWriter(new FileOutputStream(tmpConfigFile), true)) {
			configWriter.println("name=anyname");
			configWriter.println("library=" + this.tokenLibraryPath); 
		}

		SunPKCS11 provider = new SunPKCS11(tmpConfigFile.getAbsolutePath());
		Security.addProvider(provider);

		KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
		keyStore.load(null, tokenPassword.toCharArray());

		return keyStore;
	}
}
