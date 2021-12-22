/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package Security;

/**
 *
 * @author Velez
 */
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.IllegalFormatException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created on 06/10/2021, 08:53:44 Adapted from Luis Lopes
 *
 * @author IPT - computer
 * @version 1.0
 */
public class SecurityUtils {

    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    //:::::::::      I N T E G R I T Y         :::::::::::::::::::::::::::::::::    
    ///////////////////////////////////////////////////////////////////////////
    public static byte[] getHash(byte[] data, String algorithm)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(data);
        return md.digest();
    }

    public static String getHash(String data, String algorithm) throws Exception {
        return TextUtils.byteToString(getHash(data.getBytes(), algorithm));
    }

    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    //:::::::::       K E Y S        :::::::::::::::::::::::::::::::::    
    ///////////////////////////////////////////////////////////////////////////
    /**
     * Gera uma chave de criptogradia simetrica TrippleDes
     *
     * @param keySize tamanho da chave
     * @return chave cahve simétrica gerada
     * @throws Exception muito improvável de ocurrer
     */
    public static Key generateAESKey(int keySize) throws Exception {
        // gerador de chaves
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        //tamanho da chave
        keyGen.init(keySize);
        //gerar a chave
        Key key = keyGen.generateKey();
        return key;
    }

    /**
     * Gera um par de chave para elliptic curves
     *
     * @param size tamanho da chave ( 224 , 256 , 384 , 521 )
     * @return par de chaves EC
     * @throws Exception
     */
    public static KeyPair generateECKeyPair(int size) throws Exception {
        String secCurve;
        //tamanho da chave
        switch (size) {
            case 224:
                secCurve = "secp224r1";
                break;
            case 256:
                secCurve = "secp256r1";
                break;
            case 384:
                secCurve = "secp384r1";
                break;
            case 521:
                secCurve = "secp521r1";
                break;
            default: //caso o tamanho dado nao seja permitido
                throw new Exception("Só são permitidos os eguintes tamanhos: 224, 256, 384 e 521");
        }
        // gerador de chaves Eliptic curve
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");

        // gerador de chaves Eliptic Curves Criptografy
        ECGenParameterSpec generationParam = new ECGenParameterSpec(secCurve);
        keyGen.initialize(generationParam, new SecureRandom());
        //devolve o par de chaves gerado
        return keyGen.generateKeyPair();
    }

    /**
     * Gera um par de chave para elliptic curves
     *
     * @param size tamanho da chave ( 224 , 256 , 384 , 521 )
     * @return par de chaves EC
     * @throws Exception
     */
    public static KeyPair generateRSAKeyPair(int size) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        //tamanho da chave
        keyGen.initialize(size);
        //devolve o par de chaves gerado
        return keyGen.generateKeyPair();
    }

    /**
     * Transforma um array de bytes representante de uma chave publica em chave
     * publica
     *
     * @param pubData array de bytes representante da chave
     * @return a chave publica em forma de chave
     * @throws Exception Caso ocorra algum erro:
     * <code>NoSuchAlgorithmException</code>,<code>InvalidKeySpecException</code>,<code>NullPointerException</code>
     * e <code>NoSuchProviderException</code>
     */
    public static PublicKey getPublicKey(byte[] pubData) throws Exception {
        //especifacção do encoding da chave publica X509
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubData);
        KeyFactory keyFactory;
        //objecto para grerar a chave RSA
        //test RSA
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            //Gerar a chave pública
            return keyFactory.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NullPointerException ex) {
            //test EC
            try {
                keyFactory = KeyFactory.getInstance("EC");
                //Gerar a chave pública
                return keyFactory.generatePublic(pubSpec);
            } catch (Exception ex2) {
                throw new InvalidAlgorithmParameterException();
            }
        }
    }

    /**
     * Transforma um array de bytes representante de uma chave privada em chave
     * privada
     *
     * @param privData array de bytes representante da chave
     * @return a chave privada em forma de chave
     * @throws Exception Caso ocorra algum erro:
     * <code>NoSuchAlgorithmException</code>,<code>InvalidKeySpecException</code>,<code>NullPointerException</code>
     * e <code>NoSuchProviderException</code>
     */
    public static PrivateKey getPrivateKey(byte[] privData) throws Exception {
        //especificações da chave privada PKCS8
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privData);
        KeyFactory keyFactory;
        //objecto para grerar a chave RSA
        //test RSA
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            //Gerar a chave privada
            return keyFactory.generatePrivate(privSpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NullPointerException ex) {
            //test EC
            try {
                keyFactory = KeyFactory.getInstance("EC");
                //Gerar a chave privada
                return keyFactory.generatePrivate(privSpec);
            } catch (Exception ex2) {
                throw new InvalidAlgorithmParameterException();
            }
        }
    }

    /**
     * Gera uma chave AES
     *
     * @param key chave em array de bytes
     * @return chave chave carregada através da base64
     */
    public static Key getAESKey(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }

    /**
     * nomraliza o nome do ficheiro de chaves
     *
     * @param key chave para guardar
     * @param file nome do ficheiro
     * @return nome do ficheiro com a extensão correta
     * @throws IllegalFormatException
     */
    private static String normalizeKeyFileName(Key key, String file) {
        //remove extension
        if (file.contains(".")) {
            file = file.substring(0, file.lastIndexOf('.'));
        }
        //put extension
        if (key instanceof PublicKey) {
            return file + "." + PUBLIC_KEY_EXTENSION_FILE;
        } else if (key instanceof PrivateKey) {
            return file + "." + PRIVATE_KEY_EXTENSION_FILE;
        } else {
            return file + "." + KEY_EXTENSION_FILE;
        }
    }

    /**
     * Guarda uma chave num ficheiro
     *
     * @param key chave a ser armazenada
     * @param file nome do ficheiro
     * @throws IOException caso não haja permissão para aceder ou escrever ao
     * ficheiro indicado
     */
    public static void saveKey(KeyPair key, String file) throws IOException {
        saveKey(key.getPublic(), file);
        saveKey(key.getPrivate(), file);
    }

    /**
     * Guarda uma chave num ficheiro
     *
     * @param key chave a ser armazenada
     * @param file nome do ficheiro
     * @throws IOException caso não haja permissão para aceder ou escrever ao
     * ficheiro indicado
     */
    public static void saveKey(Key key, String file) throws IOException {
        Files.write(Paths.get(normalizeKeyFileName(key, file)), key.getEncoded());
    }

    public static PrivateKey loadPrivateKey(String file) throws IOException {
        //remove extension
        if (file.contains(".")) {
            file = file.substring(0, file.lastIndexOf('.'));
        }
        return (PrivateKey) loadKey(file + "." + PRIVATE_KEY_EXTENSION_FILE);
    }

    public static PublicKey loadPublicKey(String file) throws IOException {
        //remove extension
        if (file.contains(".")) {
            file = file.substring(0, file.lastIndexOf('.'));
        }
        return (PublicKey) loadKey(file + "." + PUBLIC_KEY_EXTENSION_FILE);
    }

    public static SecretKey loadRSAKey(String file) throws IOException {
        //remove extension
        if (file.contains(".")) {
            file = file.substring(0, file.lastIndexOf('.'));
        }
        return (SecretKey) loadKey(file + "." + KEY_EXTENSION_FILE);
    }

    /**
     * Carrega uma chave de um ficheiro
     *
     * @param file nome do ficheiro
     * @return a chave que estava armazenada no ficheiro
     * @throws IOException caso não haja permissão para aceder ou ler ao
     * ficheiro indicado
     */
    public static Key loadKey(String file) throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(file));
        try {
            return getPublicKey(encoded);
        } catch (Exception e) {
            try {
                return getPrivateKey(encoded);
            } catch (Exception ex) {
                return getAESKey(encoded);
            }
        }
    }

    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    //:::::::::       S I G N A T U R E        :::::::::::::::::::::::::::::::::    
    ///////////////////////////////////////////////////////////////////////////
    /**
     * Assina os dados passados com a chave privada passada
     *
     * @param data dados a serem utilizados para a assinatura
     * @param key chave que irá assinar os dados
     * @return A assinatura em um array de bytes
     * @throws Exception Caso ocorra algum erro, como por exemplo o algoritmo
     * não existir
     */
    public static byte[] sign(byte[] data, PrivateKey key) throws Exception {
        Signature shaWith;
        //verifica qual o algoritmo a ser utilizado
        switch (key.getAlgorithm()) {
            case "RSA":
                shaWith = Signature.getInstance("SHA256withRSA");
                break;
            case "EC":
                shaWith = Signature.getInstance("SHA256withECDSA");
                break;
            default: //caso o algoritmo pedido não exista
                throw new InvalidAlgorithmParameterException();
        }
        //inicializa a assinatura com a chave
        shaWith.initSign(key);
        //assina os dados
        shaWith.update(data);
        //devolve a assinatura
        return shaWith.sign();
    }

    /**
     * Verifica se assinatura é valida
     *
     * @param data dados assinados a serem validados com a assinatura
     * @param signature assinatura a ser validado
     * @param key cahve publica que faz par com a chave privada que foi
     * utilizada na assinatura
     * @return se a assinatura é valida
     * @throws Exception Caso ocorra algum erro, como por exemplo o algoritmo
     * não existir
     */
    public static boolean verifySign(byte[] data, byte[] signature, PublicKey key) throws Exception {
        Signature shaWith;
        //verifica qual o algoritmo a ser utilizado
        switch (key.getAlgorithm()) {
            case "RSA":
                shaWith = Signature.getInstance("SHA256withRSA");
                break;
            case "EC":
                shaWith = Signature.getInstance("SHA256withECDSA");
                break;
            default: //caso o algoritmo pedido não exista
                throw new InvalidAlgorithmParameterException();
        }
        //inicializa a validação da assinatura com a chave
        shaWith.initVerify(key);
        //verifica se assinatura é valida para os dados dados e para assinatura dada
        shaWith.update(data);
        return shaWith.verify(signature);

    }
    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::   
    //:::::::::::::     E N C R Y P T    /   D E C R Y P T   :::::::::::::::::::
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Encripta um array de dados
     *
     * @param data dados a serem encriptados
     * @param key chave a ser utilizada na encriptação
     * @return os dados encriptados em um array de dados
     * @throws Exception Caso ocorra algum erro, como por exemplo o algoritmo
     * não existir
     */
    public static byte[] encrypt(byte[] data, Key key) throws Exception {

        //criar um objecto de cifragem da chave
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        //configurar o objecto para cifrar
        cipher.init(Cipher.ENCRYPT_MODE, key);
        //cifrar os dados
        return cipher.doFinal(data);
    }

    /**
     * Desencripta um array de dados
     *
     * @param data dados a serem desencriptados
     * @param key chave a ser utilizada na desencriptação
     * @return os dados encriptados em um array de dados
     *
     */
    public static byte[] decrypt(byte[] data, Key key) throws Exception {
        //criar um objecto de cifragem da chave
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        //configurar o objecto para cifrar
        cipher.init(Cipher.DECRYPT_MODE, key);
        //decifrar os dados
        return cipher.doFinal(data);
    }
    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    //:::::::::::        PASSWORD BASED ENCRYPTATION                 :::::::::::
    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

    /**
     * Cria um objecto de cifragem com PBE SHA1 e triple DES
     *
     * @param mode Cipher.DECRYPT_MODE ou Cipher.ENCRYPT_MODE
     * @param password password de da cifra
     * @return Objecto de cifragem
     * @throws Exception
     */
    public static Cipher createCipherPBE(int mode, String password) throws Exception {
        //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
        //:::::::::   1 - gerar uma chave secreta  :::::::::::::::::::::::::::::
        //transformar a password nos parametros na chave
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        //algoritmo de cifragem
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithSHA1AndDESede");
        //gerar a chave
        SecretKey key = keyFactory.generateSecret(keySpec);
        //::::::::: 2 -  adicionar sal á chave  :::::::::::::::::::::::::::::::
        // usar a password para inicializar o secure
        //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
        //::::::::: 2 -  adicionar sal á chave  :::::::::::::::::::::::::::::::
        // usar o SHA1 para gerar um conjunto de  bytes a partir da password
        MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(password.getBytes());
        //usar os primeiros 8 bytes
        byte[] digest = Arrays.copyOf(md.digest(), 8);
        //fazer 1000 iterações com o sal
        PBEParameterSpec paramSpec = new PBEParameterSpec(digest, 1000);

        //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
        //:::::::::::   3 - Gerar o objecto de cifragem      :::::::::::::::::::
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
        //:::::::::   4 - iniciar a cifra ::::::::: ::::::::: ::::::::: ::::::::: 
        // iniciar o objeto de cifragem com os parâmetros
        cipher.init(mode, key, paramSpec);
        return cipher;
    }

    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    //:::::::::::               ENCRYPT /  DECRYPT                   :::::::::::
    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    /**
     * encripta dados usando uma password de texto
     *
     * @param data dados para encriptar
     * @param password password de encriptação
     * @return dados encriptados
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, String password) throws Exception {
        //criar um objecto de cifragem da chave
        Cipher cipher = createCipherPBE(Cipher.ENCRYPT_MODE, password);
        //cifrar os dados
        return cipher.doFinal(data);
    }

    /**
     * desencripta dados usando uma password de texto
     *
     * @param data dados para desencriptar
     * @param password password de desencriptação
     * @return dados desencriptados
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, String password) throws Exception {
        //criar um objecto de cifragem da chave
        Cipher cipher = createCipherPBE(Cipher.DECRYPT_MODE, password);
        //cifrar os dados
        return cipher.doFinal(data);
    }

    /**
     * Extensão utilizada para armazenar chaves privadas em ficheiros
     */
    public static String KEY_EXTENSION_FILE = "key";
    /**
     * Extensão utilizada para armazenar chaves privadas em ficheiros
     */
    public static String PRIVATE_KEY_EXTENSION_FILE = "privkey";
    /**
     * Extensão utilizada para armazenar chaves publicas em ficheiros
     */
    public static String PUBLIC_KEY_EXTENSION_FILE = "pubkey";

//::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    private static final long serialVersionUID = 202110060853L;
    //:::::::::::::::::::::::::::  Copyright(c) M@nso  2021  :::::::::::::::::::
    ///////////////////////////////////////////////////////////////////////////
}

