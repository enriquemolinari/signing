package ar.cpfw.signing;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import sun.security.pkcs11.SunPKCS11;

public class UsbToken {

	private String tokenLibraryPath;
	
	public UsbToken(String tokenLibraryPath) {
		//TODO: validate input...
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
	
	public byte[] signText(String textToSign, String tokenPassword) {	
		//TODO: validate input...
		try {
			KeyStore keyStore = retrieveKeyStore(tokenPassword);
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStore.aliases().nextElement(), null);

			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKey);
			byte[] toBeSigned = textToSign.getBytes();
			signature.update(toBeSigned);
			return signature.sign();
			
		} catch (Exception e) {
			throw new RuntimeException("Ups, something went wrong... ", e);
		} 
	}
	
	private KeyStore retrieveKeyStore(String tokenPassword) throws Exception {
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
