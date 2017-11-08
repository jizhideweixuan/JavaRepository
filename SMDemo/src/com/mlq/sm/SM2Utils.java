package com.mlq.sm;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

public class SM2Utils 
{
	/**
	 *  国密规范正式公钥
	 */
	private final static String pubk = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";
	// 国密规范正式私钥
    private final static String prik = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";
			
			
	//生成随机秘钥对
	public static void generateKeyPair(){
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();
		
		System.out.println("公钥: " + Util.byteToHex(publicKey.getEncoded()));
		System.out.println("私钥: " + Util.byteToHex(privateKey.toByteArray()));
	}
	
	//数据加密
	public static String encrypt(byte[] publicKey, byte[] data) throws IOException
	{
		if (publicKey == null || publicKey.length == 0)
		{
			return null;
		}
		
		if (data == null || data.length == 0)
		{
			return null;
		}
		
		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);
		
		Cipher cipher = new Cipher();
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);
		
		ECPoint c1 = cipher.Init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);
		
//		System.out.println("C1 " + Util.byteToHex(c1.getEncoded()));
//		System.out.println("C2 " + Util.byteToHex(source));
//		System.out.println("C3 " + Util.byteToHex(c3));
		//C1 C2 C3拼装成加密字串
		return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) + Util.byteToHex(c3);
		
	}
	
	//数据解密
	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException
	{
		if (privateKey == null || privateKey.length == 0)
		{
			return null;
		}
		
		if (encryptedData == null || encryptedData.length == 0)
		{
			return null;
		}
		//加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
		String data = Util.byteToHex(encryptedData);
		/***分解加密字串
		 * （C1 = C1标志位2位 + C1实体部分128位 = 130）
		 * （C3 = C3实体部分64位  = 64）
		 * （C2 = encryptedData.length * 2 - C1长度  - C2长度）
		 */
		byte[] c1Bytes = Util.hexToByte(data.substring(0,130));
		int c2Len = encryptedData.length - 97;
		byte[] c2 = Util.hexToByte(data.substring(130,130 + 2 * c2Len));
		byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 * c2Len));
		
		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);
		
		//通过C1实体字节来生成ECPoint
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);
		
		//返回解密结果
		return c2;
	}
	public static String encrpt(String plainText) throws IllegalArgumentException, IOException{
		byte[] publicKey=Util.hexToByte(pubk);
		byte[] data=plainText.getBytes();
		return SM2Utils.encrypt(publicKey, data);
	}
	public static String decrypt(String cipherText) throws IllegalArgumentException, IOException{
		byte[] privateKey=Util.hexToByte(prik);
		byte[] encryptedData=Util.hexToByte(cipherText);
		
		return new String(SM2Utils.decrypt(privateKey, encryptedData));
	}
	
	public static void main(String[] args) throws Exception 
	{
		//生成密钥对
	    //generateKeyPair();
		/**
		 * 公钥: 049FF575F0C2F20391C37A4016E7B96F55178843125263702527B4C5017511567D7DBF435C121C4F6077116FDF01BAADBFD24BBBE24947B0E74F54D3A588BC2218
私钥: 44EB1BB601724BCF97ABEA564F3CB73127AD48B60842F9880E0074F469771873
		 */
		String plainText = "ererfeiisgod/4344%!342433423中国chinaiChina4324324234324324234324";
//		String cipherText=SM2Utils.encrpt(plainText);
//		System.out.println(cipherText);
		String cipherText="04DAD0EC331175DECDE02B8336A62692DCC0DEE1C66AC325AC3EA45830AB765585A23951DA79A967C17018FA91D38AE931069BABA64A1270B09E3F4B55A318891D7040A69DB4AE9B66CCED3C1CF566AE264026328798FAC897CCE9B779796A1A878DA32F5F18D06DFE75781CC902F488ECC0F6BA574B381388FAF5493FB2AE48F3C02397BAE91124AB3997DCCD4EB5F8600DBD6EBC4998B7F739B2CAC065B23D7AFCBC5E";
		System.out.println(SM2Utils.decrypt(cipherText));
		
	}
}
