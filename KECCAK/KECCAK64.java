package KECCAK;

import SHA.SHA;

public class KECCAK64 extends SHA {
	
	private final long[] RC = new long[] {
		0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
		0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
		0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
		0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
		0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
		0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
		0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
		0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
	};
	
	private final int[] R = new int[] {
		0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
		25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
	};
	
	final int wordlength = 64;
	final int b = 25 * wordlength;
	
	final int L =  (int) (Math.log(wordlength) / Math.log(2));;
	final int rounds = 12 + 2 * L;
	
	int digestlen;
	int c;
	int r;
	protected int blocklen;
	
	long[] state;
	
	protected long[] buffer;
	protected int buffercount;
	
	public KECCAK64() {
		digestlen = 512;
		
		c = 2 * digestlen;
		r = b - c;
		
		blocklen = r/8;
		buffer = new long[blocklen/8];
		
		reset();
	}
	
	public KECCAK64(int digestlen) {
		this.digestlen = digestlen;
		
		c = 2 * digestlen;
		r = b - c;
		
		blocklen = r/8;
		buffer = new long[blocklen/8];
		
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
		
		for (int i = 0; i < blocklen; i+=8) {
			digest[i  ] = (byte)((state[i/8]       ) & 0xFF);
			digest[i+1] = (byte)((state[i/8] >>  8 ) & 0xFF);
			digest[i+2] = (byte)((state[i/8] >> 16 ) & 0xFF);
			digest[i+3] = (byte)((state[i/8] >> 24 ) & 0xFF);
			digest[i+4] = (byte)((state[i/8] >> 32 ) & 0xFF);
			digest[i+5] = (byte)((state[i/8] >> 40 ) & 0xFF);
			digest[i+6] = (byte)((state[i/8] >> 48 ) & 0xFF);
			digest[i+7] = (byte)((state[i/8] >> 56 ) & 0xFF);
		}
		
		keccakf();
		
		return digest;
		
	}
	
	public void keccakf() {
		
		long[] B, C, D;
		
		for (int round = 0; round < rounds; round++) {
		
			B = new long[25];
			C = new long[5];
			D = new long[5];
			
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
		
		buffer[buffercount/8] = buffer[buffercount/8] | ((long)(b & 0xFF) << ((buffercount % 8) * 8));
		buffercount++;
		
		if (buffercount == blocklen) processBuffer();
	}

	public void processBuffer() {

		absorb();
		
		buffercount = 0;
		
	}
	
	public void addPadding() {
		
		if (buffercount == blocklen) buffer[buffercount/8] = buffer[buffercount/8] | ((long)(0x81) << (buffercount % 8)) * 8;
		else {
	
			buffer[buffercount/8] = buffer[buffercount/8] | ((long)(0x01) << (buffercount % 8) * 8);
			buffercount++;
			
			while (buffercount < blocklen - 1) {
				buffer[buffercount/8] = buffer[buffercount/8] | ((long)(0x00) << (buffercount % 8) * 8);
				buffercount++;
			}
	
			buffer[buffercount/8] = buffer[buffercount/8] | ((long)(0x80) << (buffercount % 8) * 8);
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
		
		state = new long[25];
		buffercount = 0;

	}
	
}