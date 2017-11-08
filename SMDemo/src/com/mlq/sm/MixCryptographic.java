package com.mlq.sm;

import java.io.IOException;
import java.util.HashMap;

public class MixCryptographic {
	public static final String ENCRPT_KEY="encrptKey";
	public static final String ENCRPT_DATA="encrptData";
	/**
	 * 
	 * @param plainText 明文
	 * @param key 密码 长度为16位字符
	 * @return 密码密文以及内容密文
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public static HashMap<String,String> encrpt(String plainText) throws IllegalArgumentException, IOException{
		
		String key=RandomKey.generateKey();//必须是16位数字或者字谜
		
		HashMap<String ,String > encrptDataMap=new HashMap<String,String>();
		//对密钥进行加密
		String encrptKey=SM2Utils.encrpt(key);
		encrptDataMap.put(ENCRPT_KEY, encrptKey);
		
		SM4Utils sm4=new SM4Utils();
		sm4.secretKey=key;
		String encrptData=sm4.encryptData_ECB(plainText);
		encrptDataMap.put(ENCRPT_DATA, encrptData);
		return encrptDataMap;
		
	}
	public static String decrpt(String plainText,String encrptKey) throws IllegalArgumentException, IOException{
		
		String key=SM2Utils.decrypt(encrptKey);
		SM4Utils sm4=new SM4Utils();
		sm4.secretKey=key;
		String encrptData=sm4.decryptData_ECB(plainText);
		return encrptData;
	}
	public static void main(String args[]){
		for(int i=0;i<10000000;i++){
		
		String plainText="我是明文我是明文";
		try {
			/**
			 * 加密
			 */
			HashMap<String,String> encrptDataMap=MixCryptographic.encrpt(plainText);
			
			String encrptKey=encrptDataMap.get(MixCryptographic.ENCRPT_KEY);
			System.out.println("密钥密文："+encrptKey);
			
			String encrptData=encrptDataMap.get(MixCryptographic.ENCRPT_DATA);
			System.out.println("内容密文："+encrptData);
			
			/**
			 * 解密
			 */
			plainText=MixCryptographic.decrpt(encrptData, encrptKey);
			System.out.println("内容明文："+plainText);
			
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	}

}
