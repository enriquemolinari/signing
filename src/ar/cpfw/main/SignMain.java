package ar.cpfw.main;

import ar.cpfw.signing.Notary;
import ar.cpfw.signing.UsbToken;

public class SignMain {

	public static void main(String[] args) throws Exception {

		// linux library
		UsbToken tokenUnix = new UsbToken("/my/path/library.so");

		// windows library
		// UsbToken tokenWin = new UsbToken("c:\\my\\path\\library.dll");

		byte[] signValue = tokenUnix.signText("text to sign...", "passwordOfMyUsbToken");

		boolean valid = new Notary().verifySignature("text to sign...".getBytes(), signValue,
				tokenUnix.publicKey("passwordOfMyUsbToken"));

		System.out.println("is valid?: " + valid);
	}
}
