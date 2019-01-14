package ar.cpfw.signing;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

public class Notary {

	private String signatureAlgorithm;
	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA1withRSA";

	public Notary(String signatureAlgorithm) {
		Objects.nonNull(signatureAlgorithm);
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public Notary() {
		this(DEFAULT_SIGNATURE_ALGORITHM);
	}
	
	public boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) {
		Objects.nonNull(publicKey);
		
		try {
			Signature sig = Signature.getInstance(this.signatureAlgorithm);
			sig.initVerify(publicKey);
			sig.update(data);
			return sig.verify(signature);
		} catch(Exception e) {
			throw new RuntimeException("Ups, something went wrong... ", e);
		}
	}

}
