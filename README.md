### PGP encryption & decryption tool

TrueMoney Disbursement platform process the file that encrypt with PGP standard and verify signature in control file. This tool require key parameters as .gpg file format. 

Download jar file to use tool: [Ascend's tool](pgp-encryption-tool.jar)


You can modify the source and build with runnable jar file to use the tool.

<h1>Tools commands</h1>

Encryption :

```
java -jar ./pgp-encryption-tool.jar encrypt ${csv_input_file_path} ${tmn_public_key} ${partner_private_key} ${partner_password}
```

Decryption :

```
java -jar ./pgp-encryption-tool.jar decrypt ${encrypt_input_file} ${control_input_file} ${tmn_public_key} ${partner_private_key} ${partner_password}
```


Example:

```
// encrypt
java -jar ./pgp-encryption-tool.jar encrypt CheckProfile_IGN_2022-05-03.csv keys/truemoney_pub.gpg keys/partner_pri.gpg password

// decrypt
java -jar ./pgp-encryption-tool.jar decrypt CheckProfile_IGN_2022-05-03_Result.csv.pgp CheckProfile_IGN_2022-05-03_Result.csv.ctrl keys/truemoney_pub.gpg keys/partner_pri.gpg password
```
