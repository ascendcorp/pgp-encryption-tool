package PgpCrypto.PgpCrypto.crypto;

import static org.bouncycastle.bcpg.CompressionAlgorithmTags.ZIP;
import static org.bouncycastle.bcpg.HashAlgorithmTags.SHA256;
import static org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.springframework.stereotype.Component;

@Component
public class PgpEncryption {

    private PgpHelper pgpHelper;
    
    public PgpEncryption(PgpHelper pgpHelper) {
    	this.pgpHelper = pgpHelper;
    }


    public void signAndEncryptFile(
            OutputStream out,
            String fileName,
            InputStream publicKeyIn,
            InputStream privateKeyIn,
            String password,
            boolean armor,
            boolean withIntegrityCheck) throws PGPException, IOException {

        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        // Initialize encrypted data generator
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                new BcPGPDataEncryptorBuilder(AES_256)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom()));
        PGPPublicKey pgpPublicKey = pgpHelper.readPublicKey(publicKeyIn);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pgpPublicKey));
        OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[1024]);

        // Initialize compressed data generator
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(ZIP);
        try (OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte [1024])) {

            // Initialize signature generator
            PGPSecretKey pgpSecretKey = pgpHelper.readSecretKey(privateKeyIn);
            PGPSignatureGenerator signatureGenerator = getPgpSignatureGenerator(pgpSecretKey, password, compressedOut);

            // Initialize literal data generator
            PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
            try (
                    OutputStream literalOut = literalDataGenerator.open(
                            compressedOut,
                            PGPLiteralData.BINARY,
                            fileName,
                            new Date(),
                            new byte[1024]);
                    FileInputStream in = new FileInputStream(fileName)
            ) {
                // Main loop - read the "in" stream, compress, encrypt and write to the "out" stream
                byte[] buf = new byte[1024];
                int len;
                while ((len = in.read(buf)) > 0) {
                    literalOut.write(buf, 0, len);
                    signatureGenerator.update(buf, 0, len);
                }
                literalDataGenerator.close();
            }

            // Generate the signature, compress, encrypt and write to the "out" stream
            signatureGenerator.generate().encode(compressedOut);
            compressedDataGenerator.close();
            encryptedDataGenerator.close();
        }
        if (armor) {
            out.close();
        }
    }

    private static PGPSignatureGenerator getPgpSignatureGenerator(PGPSecretKey secretKey, String password, OutputStream compressedOut) throws PGPException, IOException {
        PGPPrivateKey privateKey = extractPrivateKey(secretKey, password.toCharArray());

        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
        spGen.setSignerUserID(false, secretKey.getPublicKey().getUserIDs().next());

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(
                secretKey.getPublicKey().getAlgorithm(),
                SHA256));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        signatureGenerator.setHashedSubpackets(spGen.generate());
        signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

        return signatureGenerator;
    }

    private static PGPPrivateKey extractPrivateKey(PGPSecretKey secretKey, char[] passPhrase) throws PGPException {
        return secretKey.extractPrivateKey(
                new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                        .build(passPhrase));
    }

    public void createSignature(
            String          fileName,
            InputStream privateKeyIn,
            OutputStream    out,
            String          password,
            boolean         armor)
            throws IOException, PGPException
    {
        PGPSecretKey pgpSecretKey = pgpHelper.readSecretKey(privateKeyIn);
        PGPPrivateKey privateKey = pgpSecretKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(password.toCharArray()));
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(pgpSecretKey.getPublicKey().getAlgorithm(), SHA256));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(byteOut);

        BCPGOutputStream bcpgOutputStream = new BCPGOutputStream(byteOut);

        try (InputStream fIn = new BufferedInputStream(new FileInputStream(fileName))) {
            int ch;
            while ((ch = fIn.read()) >= 0) {
                signatureGenerator.update((byte) ch);
            }
            aOut.endClearText();
        }
        signatureGenerator.generate().encode(bcpgOutputStream);
        if (armor)
        {
            aOut.close();
        }

        out.write(byteOut.toByteArray());
    }
}