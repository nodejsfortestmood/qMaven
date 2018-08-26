package org.test.demo.qMaven;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.apache.commons.codec.binary.Base64;

public class DigitalSignatureMain {
	
	/** 指定公钥存放文件 */
	private static String PUBLIC_KEY_FILE = "PublicKey";
	/** 指定私钥存放文件 */
	private static String PRIVATE_KEY_FILE = "PrivateKey";
	
	public static void main(String[] args)  throws Exception {
        String content = "study hard and make progress everyday";
        System.out.println("content :"+content);

        KeyPair keyPair = getKeyPair();
//        PublicKey publicKey =  keyPair.getPublic(); 
        PublicKey publicKey =  (PublicKey) getKey(PUBLIC_KEY_FILE);
        System.out.println(publicKey);
//        PrivateKey privateKey = keyPair.getPrivate();
        PrivateKey privateKey = (PrivateKey) getKey(PRIVATE_KEY_FILE);
        System.out.println(privateKey);
        
        String md5Sign  = getMd5Sign(content,privateKey);
        System.out.println("sign with md5 and rsa :"+ md5Sign);
        boolean md5Verifty = verifyWhenMd5Sign(content,md5Sign,publicKey);
        System.out.println("verify sign with md5 and rsa :"+ md5Verifty);

        String sha1Sign  = getSha1Sign(content,privateKey);
        System.out.println("sign with sha1 and rsa :"+ sha1Sign);
        boolean sha1Verifty = verifyWhenSha1Sign(content,sha1Sign,publicKey);
        System.out.println("verify sign with sha1 and rsa :"+ sha1Verifty);

    }

    //生成密钥对
    static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512); //可以理解为：加密后的密文长度，实际原文要小些 越大 加密解密越慢
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }

    //用md5生成内容摘要，再用RSA的私钥加密，进而生成数字签名
    static String getMd5Sign(String content , PrivateKey privateKey) throws Exception {
        byte[] contentBytes = content.getBytes("utf-8");
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(privateKey);
        signature.update(contentBytes);
        byte[] signs = signature.sign();
        return Base64.encodeBase64String(signs);
    }

    //对用md5和RSA私钥生成的数字签名进行验证
    static boolean verifyWhenMd5Sign(String content, String sign, PublicKey publicKey) throws Exception {
        byte[] contentBytes = content.getBytes("utf-8");
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initVerify(publicKey);
        signature.update(contentBytes);
        return signature.verify(Base64.decodeBase64(sign));
    }

    //用sha1生成内容摘要，再用RSA的私钥加密，进而生成数字签名
    static String getSha1Sign(String content , PrivateKey privateKey) throws Exception {
        byte[] contentBytes = content.getBytes("utf-8");
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(contentBytes);
        byte[] signs = signature.sign();
        return Base64.encodeBase64String(signs);
    }

    //对用md5和RSA私钥生成的数字签名进行验证
    static boolean verifyWhenSha1Sign(String content, String sign, PublicKey publicKey) throws Exception {
        byte[] contentBytes = content.getBytes("utf-8");
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(publicKey);
        signature.update(contentBytes);
        return signature.verify(Base64.decodeBase64(sign));
    }
    
    private static Key getKey(String fileName) throws Exception, IOException {
		Key key;
		ObjectInputStream ois = null;
		try {
			/** 将文件中的私钥对象读出 */
			ois = new ObjectInputStream(new FileInputStream(fileName));
			key = (Key) ois.readObject();
		} catch (Exception e) {
			throw e;
		} finally {
			ois.close();
		}
		return key;
	}

}
