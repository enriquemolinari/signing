package ar.cpfw.main;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

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

public class MainPdf {

	public static final String SRC = "./resources/hello.pdf";
    public static final String DEST = "./resources/hello_signed.pdf";

	public static void main(String args[]) throws Exception {
		File tmpConfigFile = File.createTempFile("pkcs11-", "conf");
		tmpConfigFile.deleteOnExit();
		PrintWriter configWriter = new PrintWriter(new FileOutputStream(tmpConfigFile), true);
		configWriter.println("name=PruebaTokenMacromedia");
		configWriter.println("library=c:\\windows\\System32\\asepkcs.dll");

		SunPKCS11 provider = new SunPKCS11(tmpConfigFile.getAbsolutePath());
		Security.addProvider(provider);

//		Hardcoded password
		KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
		char[] pin = {  };
		keyStore.load(null, pin);

		String alias = keyStore.aliases().nextElement();
		PrivateKey pk = (PrivateKey) keyStore.getKey(alias, null);
		Certificate[] chain = keyStore.getCertificateChain(alias);								
		sign(SRC, String.format(DEST, 1), chain, pk, DigestAlgorithms.SHA256, provider.getName(),
				PdfSigner.CryptoStandard.CMS, "firmar", "Río Negro");
	}

	public static void sign(String src, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
			String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
			throws GeneralSecurityException, IOException {
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
		IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
		IExternalDigest digest = new BouncyCastleDigest();
		signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
	}
}
