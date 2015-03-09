package SHA;

import KECCAK.KECCAK32;
import KECCAK.KECCAK64;
import SHA2.SHA256;
import SHA2.SHA512;
import SHA3.SHA64;

public class HASH {
	
	public static void main(String[] args) {
		
		final int SHA2 = 0;
		final int KECCAK = 1;
		final int SHA3 = 2;
		
		SHA sha = null;
		
		int argcount = 0;
		String arg;
		
		int algorithm = 0;
		int wordlength = 64;
		int digestlen = 256;
		
		boolean isfile = false;
		String message = "";
		
		while (argcount < args.length && args[argcount].startsWith("-")) {
			
			arg = args[argcount];
			
			if (arg.equals("-SHA2")) algorithm = 0;
			else if (arg.equals("-KECCAK")) algorithm = 1;
			else if (arg.equals("-SHA3")) algorithm = 2;
			
			else if (arg.equals("-wordlength")) {
				argcount++;
				if (argcount < args.length && args[argcount].equals("32")) wordlength = 32;
				else if (argcount < args.length && args[argcount].equals("64")) wordlength = 64;
				else printUsage("INVALID WORDLENGTH");
			}
			
			else if (arg.equals("-digest")) {
				argcount++;
				if (argcount < args.length && args[argcount].equals("224")) digestlen = 224;
				else if (argcount < args.length && args[argcount].equals("256")) digestlen = 256;
				else if (argcount < args.length && args[argcount].equals("384")) digestlen = 384;
				else if (argcount < args.length && args[argcount].equals("512")) digestlen = 512;
				else printUsage("INVALID DIGEST LENGTH");
			}
			
			else if (arg.equals("-file")) {
				isfile = true;
			}
			
			else printUsage("INVALID ARGUMENT");
			
			argcount++;
			
		}
		
		if (argcount < args.length) message = args[argcount];
		else printUsage("INVALID MESSAGE");
		
		switch (algorithm) {
		case SHA2:
			
			switch (digestlen) {
			case 224:
				sha = new SHA256().new SHA224(); break;
			case 256:
				sha = new SHA256(); break;
			case 384:
				sha = new SHA512().new SHA384(); break;
			case 512:
				sha = new SHA512();
			} break;
			
		case KECCAK:
			
			switch (wordlength) {
			case 32:
				//sha = new KECCAK32(digestlen); break;
			case 64:
				sha = new KECCAK64(digestlen); break;
			} break;
			
		case SHA3:
			
			switch (wordlength) {
			case 32:
				//sha = new SHA32(digestlen); break;
			case 64:
				sha = new SHA64(digestlen); break;
			} break;
			
		}
		
		if (isfile) sha.update(message);
		else sha.update(message.getBytes());
		
		System.out.println(sha.printHash());
		
	}
	
	public static void printUsage() {
		
		System.out.println("USAGE");
		System.out.println("java HASH [ OPTIONS ] MESSAGE");
		System.out.println("OPTIONS");
		System.out.println("\t-SHA2                     : uses the SHA2 algorithm to hash the message.");
		System.out.println("\t-SHA3                     : uses the SHA3 algorithm to hash the message.");
		System.out.println("\t-KECCAK                   : uses the KECCAK algorithm to hash the message.");
		System.out.println("\t-wordlength [32|64]       : sets the wordlength for the KECCAK and SHA3 algorithms. Default is 64.");
		System.out.println("\t-digest [224|256|384|512] : sets the digest length to a specified number. Default is 256.");
		System.out.println("\t-file                     : message is the contents of given file.");
		
		System.exit(-1);
		
	}
	
	public static void printUsage(String message) { 
		
		System.out.println(message);
		System.out.println();
		
		printUsage();
		
	}

}
