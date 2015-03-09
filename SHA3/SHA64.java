package SHA3;

import KECCAK.KECCAK64;

public class SHA64 extends KECCAK64 {
	
	public SHA64(int digestlen) { super(digestlen); }
	public SHA64() { super(); }
	
	public void addPadding() {
		
		/*
		 * As of April 2014 the NIST updated how the hash functions and extendable output functions would differ.
		 * Hash functions would append bits 01 to the message before padding, and XOF would append bits 11 before
		 * adding padding. This is reflected in the add padding method.
		 * 
		 * Message || 01 || 1 0* 1
		 * Message || 011 0* 1
		 * Message || 0b01100000 || 0b00000000 * || 0b00000001 (big endian)
		 * Message || 0b00000110 || 0b00000000 * || 0b10000000 (little endian)
		 * Message || 0x06 || 0x00 || 0x80                     (little endian)
		 * 
		 * So we append byte 0x06 then byte 0x80 instead of 0x01 then 0x80.
		 */
		
		if (buffercount == blocklen) buffer[buffercount/8] = buffer[buffercount/8] | ((long)(0x86) << (buffercount % 8)) * 8;
		else {
	
			buffer[buffercount/8] = buffer[buffercount/8] | ((long)(0x06) << (buffercount % 8) * 8);
			buffercount++;
			
			while (buffercount < blocklen - 1) {
				buffer[buffercount/8] = buffer[buffercount/8] | ((long)(0x00) << (buffercount % 8) * 8);
				buffercount++;
			}
	
			buffer[buffercount/8] = buffer[buffercount/8] | ((long)(0x80) << (buffercount % 8) * 8);
		}
		
		processBuffer();
		
	}
	
}
