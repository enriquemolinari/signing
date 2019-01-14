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

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;

import sun.security.pkcs11.SunPKCS11;

public class UsbToken {

	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA1withRSA";
	private SunPKCS11 provider;
	
	public UsbToken(String tokenLibraryPath) {
		Objects.nonNull(tokenLibraryPath);
		if (Files.notExists(Paths.get(tokenLibraryPath))) {
			throw new RuntimeException("The library file is not found, check if the path is correct");
		}
		
		this.provider = this.buildProvider(tokenLibraryPath);
	}

	private SunPKCS11 buildProvider(String tokenLibraryPath) {
		try {
			File tmpConfigFile = File.createTempFile("pkcs11-", "conf");
			tmpConfigFile.deleteOnExit();
			try (PrintWriter configWriter = new PrintWriter(new FileOutputStream(tmpConfigFile), true)) {
				configWriter.println("name=anyname");
				configWriter.println("library=" + tokenLibraryPath); 
			}
	
			return new SunPKCS11(tmpConfigFile.getAbsolutePath());
		} catch(Exception e) {
			throw new RuntimeException("Ups, something went wrong... ", e);
		}
	}

	/**
	 * Retrieve the public key from the usb token.
	 * 
	 * @return PublicKey 
	 * @param tokenPassword
	 * */
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

	/**
	 * Digital Sign a PDF. It use itext7.
	 * 
	 * @param src source path of the Pdf to be signed.
	 * @param dest destination path of the signed Pdf.
	 * @param tokenPassword
	 * @param reason Reason to sign, it will be displayed in a signature box inside de pdf.
	 * @param location it will be displayed in a signature box inside de pdf.
	 * */
	public void signPdf(String src, String dest, String tokenPassword, String reason, String location) {
		try { 
			KeyStore keyStore = retrieveKeyStore(tokenPassword);
			String alias = keyStore.aliases().nextElement();
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
			
			// Creating the reader and the signer
			PdfReader reader = new PdfReader(src);
			PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());
			// Creating the appearance
			PdfSignatureAppearance appearance = signer.getSignatureAppearance().setReason(reason).setLocation(location)
					.setReuseAppearance(false);
			Rectangle rect = new Rectangle(36, 648, 200, 100);
			appearance.setPageRect(rect).setPageNumber(1);
			signer.setFieldName("sig");
			// Creating the signature
			IExternalSignature pks = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, this.provider.getName());
			IExternalDigest digest = new BouncyCastleDigest();
			signer.signDetached(digest, pks, keyStore.getCertificateChain(alias), null, null, null, 0, PdfSigner.CryptoStandard.CMS);
		} catch (Exception e) {
			throw new RuntimeException("Ups, something went wrong... ", e);
		}
	}
	
	private KeyStore retrieveKeyStore(String tokenPassword) throws Exception {
		Objects.nonNull(tokenPassword);

		Security.addProvider(this.provider);
		KeyStore keyStore = KeyStore.getInstance("PKCS11", this.provider);
		keyStore.load(null, tokenPassword.toCharArray());

		return keyStore;
	}
}
