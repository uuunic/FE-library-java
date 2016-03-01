package cn.edu.buaa.crypto.util;

public class LibraryUtil {
	public static String concatStringArray(String[] strArray){
		String concatStr = "";
		for (String str: strArray){
			concatStr = concatStr.concat(str);
		}
		return concatStr;
	}
	
	public static String IdentityVectorToString(String[] identityVector){
		String concatIV = "(";
		for (int i=0; i<identityVector.length - 1; i++){
			concatIV = concatIV.concat(identityVector[i] + ", ");
		}
		concatIV = concatIV.concat(identityVector[identityVector.length - 1] + ")");
		return concatIV;
	}
}
