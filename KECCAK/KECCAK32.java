package KECCAK;

import SHA.SHA;

public class KECCAK32 extends SHA {
	
	private final int[] RC = new int[] {
		0x00000000, 0x00000000, 0x80000000,
		0x80000000, 0x00000000, 0x00000000,
		0x80000000, 0x80000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x80000000, 0x80000000,
		0x80000000, 0x80000000, 0x80000000,
		0x00000000, 0x80000000, 0x80000000,
		0x80000000, 0x00000000, 0x80000000
	};
	
	private final int[] R = new int[] {
		0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
		25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
	};
	
	final int wordlength = 32;
	final int b = 25 * wordlength;
	
	final int L =  (int) (Math.log(wordlength) / Math.log(2));;
	final int rounds = 12 + 2 * L;
	
	int digestlen;
	int c;
	int r;
	protected int blocklen;
	
	int[] state;
	
	protected int[] buffer;
	protected int buffercount;
	
	public KECCAK32() {
		digestlen = 256;
		
		c = 2 * digestlen;
		r = b - c;
		
		blocklen = r/8;
		buffer = new int[blocklen/4];
		
		reset();
	}
	
	public KECCAK32(int digestlen) {
		this.digestlen = digestlen;
		
		c = 2 * digestlen;
		r = b - c;
		
		blocklen = r/8;
		buffer = new int[blocklen/4];
		
		reset();
	}
	
	private void absorb() {
		
		for (int i = 0; i < blocklen/8; i++) {
			state[i] ^= buffer[i];
		}
		
		keccakf();
		
	}
	
	private byte[] squeeze() {
		
		byte[] digest = new byte[blocklen];
		
		for (int i = 0; i < blocklen; i+=4) {
			digest[i  ] = (byte)((state[i/4]       ) & 0xFF);
			digest[i+1] = (byte)((state[i/4] >>  8 ) & 0xFF);
			digest[i+2] = (byte)((state[i/4] >> 16 ) & 0xFF);
			digest[i+3] = (byte)((state[i/4] >> 24 ) & 0xFF);
		}
		
		keccakf();
		
		return digest;
		
	}
	
	public void keccakf() {
		
		int[] B, C, D;
		
		for (int round = 0; round < rounds; round++) {
		
			B = new int[25];
			C = new int[5];
			D = new int[5];
			
			for (int i = 0; i < 5; i++) 
				C[i] = state[index(i,0)] ^ state[index(i,1)] 
					 ^ state[index(i,2)] ^ state[index(i,3)] 
					 ^ state[index(i,4)];
			
			for (int i = 0; i < 5; i++) {
				
				D[i] =   C[index(i-1)] 
					 ^ ((C[index(i+1)] << 1) | (C[index(i+1)] >>> (64 - 1)));
				
				for (int j = 0; j < 5; j++) 
					state[index(i, j)] ^= D[i];
				
			}
			
			for (int i = 0; i < 5; i++) 
				for (int j = 0; j < 5; j++) 
					B[index(j, i * 2 + 3 * j)] = ((state[index(i,j)] << R[index(i,j)]) 
					| (state[index(i,j)] >>> (64 - R[index(i,j)])));
				
			for (int i = 0; i < 5; i++) 
				for (int j = 0; j < 5; j++) 
					state[index(i,j)] = B[index(i,j)] ^ (~B[index(i+1, j)] 
									  & B[index(i+2, j)]);
			
			state[0] ^= RC[round];
			
		}
		
	}
	
	private final int index(int a)        { return ( a + 5 ) % 5; }
	
	private final int index(int a, int b) { return index( a ) + ( 5 * index( b )); }
	
	public void update(byte b) {
		
		buffer[buffercount/4] = buffer[buffercount/4] | ((int)(b & 0xFF) << ((buffercount % 4) * 8));
		buffercount++;
		
		if (buffercount == blocklen) processBuffer();
	}

	public void processBuffer() {

		absorb();
		
		buffercount = 0;
		
	}
	
	public void addPadding() {
		
		if (buffercount == blocklen) buffer[buffercount/4] = buffer[buffercount/4] | ((int)(0x81) << (buffercount % 4)) * 8;
		else {
	
			buffer[buffercount/4] = buffer[buffercount/4] | ((int)(0x01) << (buffercount % 4) * 8);
			buffercount++;
			
			while (buffercount < blocklen - 1) {
				buffer[buffercount/4] = buffer[buffercount/4] | ((int)(0x00) << (buffercount % 4) * 8);
				buffercount++;
			}
	
			buffer[buffercount/4] = buffer[buffercount/4] | ((int)(0x80) << (buffercount % 4) * 8);
		}
		
		processBuffer();
		
	}

	public byte[] getHash() {
		
		addPadding();
		
		byte[] digest = new byte[digestlen/8];
		byte[] temp;
		int digestcount = 0;
		
		while (digestcount < digestlen) {
			
			temp = squeeze();
			
			if (digestcount + (temp.length * 8) < digestlen )
				System.arraycopy(temp, 0, digest, digestcount/8, temp.length);
			else
				System.arraycopy(temp, 0, digest, digestcount/8, (digestlen - digestcount) / 8);
			
			digestcount += temp.length * 8;
			
		}
		
		reset();
		
		return digest;
	}

	public void reset() {
		
		state = new int[25];
		buffercount = 0;

	}
	
}