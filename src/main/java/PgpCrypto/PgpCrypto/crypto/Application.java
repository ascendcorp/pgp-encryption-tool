package PgpCrypto.PgpCrypto.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SignatureException;

import org.bouncycastle.openpgp.PGPException;

import com.ascendcorp.crypto.CryptoException;

public class Application {
	
	private static final String PGP_FILE_TYPE = ".pgp";
	private static final String CTRL_FILE_TYPE = ".ctrl";

	private static PgpHelper pgpHelper = new PgpHelper();
	private static PgpEncryption pgpEncryptUtil = new PgpEncryption(pgpHelper);
	private static PgpDecryption pgpDecryptUtil = new PgpDecryption(pgpHelper);

	public static void main(String[] args) throws IOException, CryptoException, PGPException, SignatureException {
		
		try {
			
			if (args.length == 5 && "encrypt".equalsIgnoreCase(args[0])) {
			
				// Encrypt + Create control file
				// -- Encrypt
				String inputFilePath = args[1];
				String publicKeyPath = args[2];
				String privateKeyPath = args[3];
				String passphase = args[4];

				String outputFilePath = inputFilePath + PGP_FILE_TYPE;
				String ctrlFilePath = inputFilePath + CTRL_FILE_TYPE;

				System.out.println("Start encryption.");

				try (FileOutputStream outputStream = new FileOutputStream(outputFilePath);
						InputStream tmnPublicKeyIn = new FileInputStream(publicKeyPath);
						InputStream partnerPrivateKeyIn = new FileInputStream(privateKeyPath);) {
					pgpEncryptUtil.signAndEncryptFile(outputStream, inputFilePath, tmnPublicKeyIn, partnerPrivateKeyIn,
							passphase, false, true);
				} catch (Exception e) {
					throw e;
				}

				System.out.println("Encryption success.");

				// Create control file
				try (FileOutputStream signatureOut = new FileOutputStream(ctrlFilePath);
						InputStream partnerPrivateKeyIn = new FileInputStream(privateKeyPath);) {
					pgpEncryptUtil.createSignature(outputFilePath, partnerPrivateKeyIn, signatureOut, passphase, false);
					System.out.println("success");
				} catch (Exception e) {
					throw e;
				}
			
				System.out.println("Create control file success.");
			
			} else if (args.length == 6 && "decrypt".equalsIgnoreCase(args[0])) {
				
				// Decrypt with control file
				String inputEncryptFilePath = args[1];
				String inputCtrlFilePath = args[2];
				String publicKeyPath = args[3];
				String privateKeyPath = args[4];
				String passphase = args[5];
				
				if (inputEncryptFilePath.substring(inputEncryptFilePath.length() - PGP_FILE_TYPE.length(), inputEncryptFilePath.length()).equals(PGP_FILE_TYPE)) {
					
					// - Decrypt
					String outputFilePath = inputEncryptFilePath.substring(0, inputEncryptFilePath.length() - PGP_FILE_TYPE.length());
					
					System.out.println("Start decryption.");
					try (
				    		 FileInputStream cipheredIn = new FileInputStream(inputEncryptFilePath);
				    		 InputStream tmnPrivateKeyIn = new FileInputStream(privateKeyPath);
				    		 InputStream partnerPublicKeyIn = new FileInputStream(publicKeyPath);
				             FileOutputStream plainTextFileIs = new FileOutputStream(new File(outputFilePath))
				        ){
				            pgpDecryptUtil.decryptAndVerify(
				                    cipheredIn,
				                    plainTextFileIs,
				                    partnerPublicKeyIn,
				                    tmnPrivateKeyIn,
				                    passphase
				            );
				        } catch (Exception e) {
				        	throw e;
				        }
					System.out.println("Decryption success.");
					
					// - Verify control file
					try (FileInputStream signatureIn = new FileInputStream(new File(inputCtrlFilePath));
							InputStream publicKeyIn = new FileInputStream(publicKeyPath);) {
							//InputStream publicKeyIn = new FileInputStream(publicKeyPairVerifyControlFile);) {
						System.out.println(signatureIn);
						System.out.println(publicKeyIn);
						System.out.println(inputEncryptFilePath);
						System.out.println("Control file verify result: " + pgpDecryptUtil.verifySignature(inputEncryptFilePath, signatureIn, publicKeyIn));
					} catch (Exception e) {
						e.printStackTrace();
			        	throw e;
			        }
				} else {
					throw new Exception("File type must be GPG.");
				}
				
			} else {
				throw new Exception("Invalid command.");
			}
			
			
		} catch (Exception e) {
			System.out.println(e.getMessage());
			System.out.println("PGP Platform tool have 2 features.");
			System.out.println("- 'encrypt' require 5 args ('encrypt', rawFilePath, publicKey, privateKey, passphase)");
			System.out.println("- 'decrypt' require 6 args ('decrypt', encryptFilePath, ctrlFilePath, publicKey, privateKey, passphase)");
		}
	}
}
