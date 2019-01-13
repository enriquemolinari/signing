package ar.pjrn.firma;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JOptionPane;

import sun.security.pkcs11.SunPKCS11;

public class Main {

	public static void main(String[] args) throws Exception {
		File tmpConfigFile = File.createTempFile("pkcs11-", "conf");
		tmpConfigFile.deleteOnExit();
		PrintWriter configWriter = new PrintWriter(new FileOutputStream(tmpConfigFile), true);
		configWriter.println("name=PruebaTokenMacromedia");
		configWriter.println("library=c:\\windows\\System32\\asepkcs.dll");

		SunPKCS11 provider = new SunPKCS11(tmpConfigFile.getAbsolutePath());
		Security.addProvider(provider);
		
//		KeyStore.CallbackHandlerProtection callbackHandler = new KeyStore.CallbackHandlerProtection(new CallbackHandler() {
//			@Override
//			public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
//				Callback callback = callbacks[0];
//				PasswordCallback pc = (PasswordCallback)callback;
//				String password = JOptionPane.showInputDialog("Password...");
//				pc.setPassword(password.toCharArray());
//			}
//		});
//		
//		KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", null, callbackHandler);
//		KeyStore keyStore = builder.getKeyStore();

//		Hardcoded password
		KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
		char[] pin = { 'R', 'u', 's', 'i', 'a', '2', '0', '1', '8' };
		keyStore.load(null, pin);

		PrivateKey privateKey = null;
		X509Certificate cert = null;
		
		Enumeration<String> aliasesEnum = keyStore.aliases();
		while (aliasesEnum.hasMoreElements()) {
			String alias = (String) aliasesEnum.nextElement();
			System.out.println("Alias: " + alias);
			cert = (X509Certificate) keyStore.getCertificate(alias);
			System.out.println("Certificate: " + cert);
			privateKey = (PrivateKey) keyStore.getKey(alias, null);
		}

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(privateKey);
		byte[] toBeSigned = "hello world".getBytes();
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();
		
		System.out.println("valida?: " 
					+ verifySignature("hello world".getBytes(), signatureValue, cert.getPublicKey()));
	}

	private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(publicKey);
		sig.update(data);
		return sig.verify(signature);
	}
}
