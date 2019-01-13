package ar.cpfw.signing;

import java.security.PublicKey;
import java.security.Signature;

public class Main {

	public static void main(String[] args) throws Exception {
		
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
		
		UsbToken token = new UsbToken("c:\\windows\\System32\\asepkcs.dll");
		byte[] signValue = token.signText("Hola Enrique", "Rusia2018");
		
		
		System.out.println("valido:" + verifySignature("Hola Enrique".getBytes(), signValue, token.publicKey("Rusia2018")));
	}

	private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(publicKey);
		sig.update(data);
		return sig.verify(signature);
	}
}
