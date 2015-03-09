package SHA3;

import KECCAK.KECCAK32;

public class SHA32 extends KECCAK32 {
	
	public SHA32(int digestlen) { super(digestlen); }
	public SHA32() { super(); }
	
	public void addPadding() {
		
		if (buffercount == blocklen) buffer[buffercount/4] = buffer[buffercount/4] | ((int)(0x86) << (buffercount % 4)) * 8;
		else {
	
			buffer[buffercount/4] = buffer[buffercount/4] | ((int)(0x06) << (buffercount % 4) * 8);
			buffercount++;
			
			while (buffercount < blocklen - 1) {
				buffer[buffercount/4] = buffer[buffercount/4] | ((int)(0x00) << (buffercount % 4) * 8);
				buffercount++;
			}
	
			buffer[buffercount/4] = buffer[buffercount/4] | ((int)(0x80) << (buffercount % 4) * 8);
		}
		
		processBuffer();
		
	}

}
