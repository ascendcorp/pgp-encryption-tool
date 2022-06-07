package PgpCrypto.PgpCrypto.crypto;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.io.Streams;
import org.springframework.stereotype.Component;

@Component
public class PgpDecryption {

    private PgpHelper pgpHelper = new PgpHelper();
    
    public PgpDecryption(PgpHelper pgpHelper) {
    	this.pgpHelper = pgpHelper;
    }
    

    public void decryptAndVerify(InputStream in,
                                 OutputStream fOut,
                                 InputStream publicKeyIn,
                                 InputStream privateKeyIn,
                                 String password) throws IOException, SignatureException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory objectFactory = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
        PGPEncryptedDataList pgpEncryptedDataList;

        Object o = objectFactory.nextObject();
        // the first object might be a PGP marker packet.
        if (o instanceof PGPEncryptedDataList) {
            pgpEncryptedDataList = (PGPEncryptedDataList) o;
        } else {
            pgpEncryptedDataList = (PGPEncryptedDataList) objectFactory.nextObject();
        }

        // find the secret key
        Iterator<PGPEncryptedData> it = pgpEncryptedDataList.getEncryptedDataObjects();
        PGPPrivateKey privateKey = null;
        PGPEncryptedData encryptedData = null;
        PGPSecretKey pgpSecretKey = pgpHelper.readSecretKey(privateKeyIn);
        while (privateKey == null && it.hasNext()) {
            encryptedData = it.next();
            PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                    .build(password.toCharArray());
            if (pgpSecretKey != null) {
                privateKey = pgpSecretKey.extractPrivateKey(decryptor);
            }
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Unable to find secret key to decrypt the message");
        }

        InputStream clear = ((PGPPublicKeyEncryptedData) encryptedData)
                .getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));

        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

        Object message;

        PGPOnePassSignatureList onePassSignatureList = null;
        PGPSignatureList signatureList = null;
        PGPCompressedData compressedData;

        message = plainFact.nextObject();
        ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

        while (message != null) {
            if (message instanceof PGPCompressedData) {
                compressedData = (PGPCompressedData) message;
                plainFact = new PGPObjectFactory(compressedData.getDataStream(), new BcKeyFingerprintCalculator());
                message = plainFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                // have to read it and keep it somewhere.
                Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
            } else if (message instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) message;
            } else if (message instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) message;
            }
            else {
                throw new PGPException("message unknown message type.");
            }
            message = plainFact.nextObject();
        }
        actualOutput.close();
        PGPPublicKey pgpPublicKey = pgpHelper.readPublicKey(publicKeyIn);

        byte[] output = actualOutput.toByteArray();
        if (onePassSignatureList == null || signatureList == null) {
            throw new PGPException("Poor PGP. Signatures not found.");
        } else {
            for (int i = 0; i < onePassSignatureList.size(); i++) {
                PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);
                if (pgpPublicKey != null) {
                    onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), pgpPublicKey);
                    onePassSignature.update(output);
                    PGPSignature signature = signatureList.get(i);
                    if (onePassSignature.verify(signature)) {
                        Iterator<?> userIds = pgpPublicKey.getUserIDs();
                        while (userIds.hasNext()) {
                            String userId = (String) userIds.next();
                        }
                    } else {
                        throw new SignatureException("Signature verification failed");
                    }
                }
            }
        }

        if (encryptedData.isIntegrityProtected() && !encryptedData.verify()) {
            throw new PGPException("Data is integrity protected but integrity is lost.");
        } else if (pgpPublicKey == null) {
            throw new SignatureException("Signature not found");
        } else {
            fOut.write(output);
            fOut.flush();
            fOut.close();
        }
    }

    public boolean verifySignature(
            String fileName,
            FileInputStream signatureIn,
            InputStream publicKeyIn)
            throws IOException, PGPException {
        PGPObjectFactory objectFactory = new PGPObjectFactory(signatureIn, new BcKeyFingerprintCalculator());
        PGPSignatureList signatureList = null;

        Object o = objectFactory.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData) o;
            objectFactory = new PGPObjectFactory(c1.getDataStream(), new BcKeyFingerprintCalculator());
            signatureList = (PGPSignatureList) objectFactory.nextObject();
        } else {
            signatureList = (PGPSignatureList) o;
        }

        PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(publicKeyIn, new BcKeyFingerprintCalculator());

        PGPSignature signature = signatureList.get(0);
        PGPPublicKey publicKey = pgpPubRingCollection.getPublicKey(signature.getKeyID());
        signature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);

        try (InputStream dIn = new BufferedInputStream(new FileInputStream(fileName))) {
            int ch;
            while ((ch = dIn.read()) >= 0) {
                signature.update((byte) ch);
            }
        }

        return signature.verify();
    }
}
