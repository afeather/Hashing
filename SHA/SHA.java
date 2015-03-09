package SHA;
import java.io.FileInputStream;
import java.io.IOException;

import KECCAK.KECCAK32;
import KECCAK.KECCAK64;
import SHA2.SHA256;
import SHA2.SHA512;
import SHA3.SHA32;
import SHA3.SHA64;


public abstract class SHA {
	
	public static void main(String[] args) {
		
		System.out.printf("%12s %12s %s\n", "Algorithm", "Digest Len", "Digest");
		System.out.printf("%12s %12s %s\n", "SHA2"     , "224 bits"       , new SHA256().new SHA224().printHash());
		System.out.printf("%12s %12s %s\n", ""         , "256 bits"       , new SHA256().printHash());
		System.out.printf("%12s %12s %s\n", ""         , "384 bits"       , new SHA512().new SHA384().printHash());
		System.out.printf("%12s %12s %s\n", ""         , "512 bits"       , new SHA512().printHash());
		System.out.printf("%12s %12s %s\n", "KECCAK 32", "224 bits"       , new KECCAK32(224).printHash());
		System.out.printf("%12s %12s %s\n", ""         , "256 bits"       , new KECCAK32().printHash());
		System.out.printf("%12s %12s %s\n", "KECCAK 64", "224 bits"       , new KECCAK64(224).printHash());
		System.out.printf("%12s %12s %s\n", ""         , "256 bits"       , new KECCAK64(256).printHash());
		System.out.printf("%12s %12s %s\n", ""         , "384 bits"       , new KECCAK64(384).printHash());
		System.out.printf("%12s %12s %s\n", ""         , "512 bits"       , new KECCAK64().printHash());
		System.out.printf("%12s %12s %s\n", "SHA3 32"  , "224 bits"       , new SHA32(224).printHash());
		System.out.printf("%12s %12s %s\n", ""         , "256 bits"       , new SHA32().printHash());
		System.out.printf("%12s %12s %s\n", "SHA3 64"  , "224 bits"       , new SHA64(224).printHash());
		System.out.printf("%12s %12s %s\n", ""         , "256 bits"       , new SHA64(256).printHash());
		System.out.printf("%12s %12s %s\n", ""         , "384 bits"       , new SHA64(384).printHash());
		System.out.printf("%12s %12s %s\n", ""         , "512 bits"       , new SHA64().printHash());
		
	}
	
	public abstract void update(byte b);
	public void update(byte[] b) { for (int i=0;i<b.length;i++) update(b[i]); }
	public void update(String filename) {};
	public void update(FileInputStream in) throws IOException { int next; while ((next = in.read()) != -1) { update((byte)(next & 0xFF)); } };
	
	public abstract void processBuffer();
	
	public abstract void addPadding();
	
	public abstract byte[] getHash();
	
	public abstract void reset();
	
	public String printHash() { return printBytes(getHash()); }
	
	public static String printBytes(byte[] b) {
		
		if (b == null) return "NULL";
		
		String s = "", str = "";
		
		for (int i = 0; i < b.length; i++) {
			
			s = "00" + Integer.toHexString(b[i] & 0xFF);
			str += s.substring(s.length()-2);
			
		}
		
		return str;
	}
	
	public static String printBytes(int[] b) {
		
		if (b == null) return "NULL";
		
		String s = "", str = "";
		
		for (int i = 0; i < b.length; i++){
			s = "00000000" + Integer.toHexString(b[i] & 0xFF);
			str += s.substring(s.length() - 8);
		}
			
		return str;
		
	}
	
	public static String printBytes(long[] b) {
		if (b == null) return "NULL";
		
		String s = "", str = "";
		
		for (int i = 0; i < b.length; i++){
			s = "0000000000000000" + Long.toHexString(b[i] & 0xFFFFFFFFFFFFFFFFL);
			str += s.substring(s.length() - 16);
		}
			
		return str;
	}
	
}