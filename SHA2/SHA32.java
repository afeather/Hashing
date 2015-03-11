package SHA2;
import SHA.SHA;

public class SHA256 extends SHA {
	
	public final int[] k = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	public int[] hash = new int[8];
	public long  messagelength;

	public int[] buffer = new int[16];
	public int buffercount;
	
	public SHA256() { reset(); }

	public void update(byte b) {
		int index = buffercount / 4;
		int offset = buffercount % 4;
		
		buffer[index] = buffer[index] | ((int) (b & 0xFF) << ( (3 - offset) * 8));
		
		buffercount++;
		messagelength += 8;
		
		if (buffercount == 64) processBuffer();
	}

	public void processBuffer() {
		
		int[] temp = hash.clone(), w = new int[64];
		int S0, S1, s1, ch, temp1, s0, maj, temp2;
		
		System.arraycopy(buffer, 0, w, 0, 16);
		
		for (int i = 0; i < 16; i++) {
			
			s1    = (Integer.rotateRight(temp[4], 6)) ^ (Integer.rotateRight(temp[4], 11)) ^ (Integer.rotateRight(temp[4], 25));
			ch    = (temp[4] & temp[5]) ^ ((~temp[4]) & temp[6]);
			temp1 =  temp[7] + s1 + ch + k[i] + w[i];
			s0    = (Integer.rotateRight(temp[0], 2)) ^ (Integer.rotateRight(temp[0], 13)) ^ (Integer.rotateRight(temp[0], 22));
			maj   = (temp[0] & temp[1]) ^ (  temp[0]  & temp[2]) ^ (temp[1] & temp[2]);
			temp2 =  s0 + maj;
			
			temp[7] =  temp[6];
			temp[6] =  temp[5];
			temp[5] =  temp[4];
			temp[4] = (temp[3] + temp1) & 0xFFFFFFFF;
			temp[3] =  temp[2];
			temp[2] =  temp[1];
			temp[1] =  temp[0];
			temp[0] = (temp1 + temp2) & 0xFFFFFFFF;
		}
		
		for (int i = 16; i < 64; i++) {
			
			S0 = (Integer.rotateRight(w[i-15], 7 )) ^ (Integer.rotateRight(w[i-15], 18)) ^ (w[i-15] >>> 3 );
			S1 = (Integer.rotateRight(w[i-2 ], 17)) ^ (Integer.rotateRight(w[i-2 ], 19)) ^ (w[i-2 ] >>> 10);
			
			w[i] = w[i-16] + S0 + w[i-7] + S1;
			
			s1    = (Integer.rotateRight(temp[4], 6)) ^ (Integer.rotateRight(temp[4], 11)) ^ (Integer.rotateRight(temp[4], 25));
			ch    = (temp[4] & temp[5]) ^ ((~temp[4]) & temp[6]);
			temp1 =  temp[7] + s1 + ch + k[i] + w[i];
			s0    = (Integer.rotateRight(temp[0], 2)) ^ (Integer.rotateRight(temp[0], 13)) ^ (Integer.rotateRight(temp[0], 22));
			maj   = (temp[0] & temp[1]) ^ (  temp[0]  & temp[2]) ^ (temp[1] & temp[2]);
			temp2 =  s0 + maj;
			
			temp[7] =  temp[6];
			temp[6] =  temp[5];
			temp[5] =  temp[4];
			temp[4] = (temp[3] + temp1) & 0xFFFFFFFF;
			temp[3] =  temp[2];
			temp[2] =  temp[1];
			temp[1] =  temp[0];
			temp[0] = (temp1 + temp2) & 0xFFFFFFFF;
		}
		
		for (int i = 0; i < 8; i++) hash[i] = (hash[i] + temp[i]) & 0xFFFFFFFF;
		
		buffercount = 0;
		
	}

	public void addPadding() {
		buffer[buffercount / 4] = buffer[buffercount / 4] | ((int) (0x80) << ( (3 - buffercount % 4) * 8));
		buffercount++;
		
		if (buffercount > 56) {	
			
			while (buffercount % 4 > 0) { 
				buffer[buffercount / 4] = buffer[buffercount / 4] | ((int) (0x00) << ( (3 - buffercount % 4) * 8));
				buffercount++;
			}
			
			while (buffercount < 64 ) {
				buffer[buffercount / 4] = (int) 0x00000000;
				buffercount += 4;
			}

			processBuffer();
		}
		
		if (buffercount < 56) {
			
			while (buffercount % 4 > 0) { 
				buffer[buffercount / 4] = buffer[buffercount / 4] | ((int) (0x00) << ( (3 - buffercount % 4) * 8));
				buffercount++;
			}
			
			while (buffercount < 56 ) {
				buffer[buffercount / 4] = (int) 0x00000000;
				buffercount += 4;
			}
			
		}
		
		buffer[14] = (int)(messagelength >> 32);
		buffer[15] = (int)(messagelength      );
		
		processBuffer();
	}

	public byte[] getHash() {
		addPadding();
		
		byte[] digest = new byte[32];
		int nextInt;
		
		for (int i = 0; i < 8; i++) {
			nextInt = hash[i];
			
			digest[i*4    ] = (byte)((nextInt >>> 24) & 0xFF);
			digest[i*4 + 1] = (byte)((nextInt >>> 16) & 0xFF);
			digest[i*4 + 2] = (byte)((nextInt >>> 8 ) & 0xFF);
			digest[i*4 + 3] = (byte)((nextInt       ) & 0xFF);
		}
		
		reset();
		
		return digest; 
	}
	
	public void reset() {
		hash[0] = 0x6a09e667;
		hash[1] = 0xbb67ae85;
		hash[2] = 0x3c6ef372;
		hash[3] = 0xa54ff53a;
		hash[4] = 0x510e527f;
		hash[5] = 0x9b05688c;
		hash[6] = 0x1f83d9ab;
		hash[7] = 0x5be0cd19;
		
		messagelength = 0;
		buffercount = 0;
	}
	
	public class SHA224 extends SHA256 {
		
		public void reset() {
			hash[0] = 0xc1059ed8;
			hash[1] = 0x367cd507;
			hash[2] = 0x3070dd17;
			hash[3] = 0xf70e5939;
			hash[4] = 0xffc00b31;
			hash[5] = 0x68581511;
			hash[6] = 0x64f98fa7;
			hash[7] = 0xbefa4fa4;
			
			messagelength = 0;
			buffercount = 0;
		}
		
		public byte[] getHash() {
			addPadding();
			
			byte[] digest = new byte[28];
			int nextInt;
			
			for (int i = 0; i < 7; i++) {
				nextInt = hash[i];
				
				digest[i*4    ] = (byte)((nextInt >>> 24) & 0xFF);
				digest[i*4 + 1] = (byte)((nextInt >>> 16) & 0xFF);
				digest[i*4 + 2] = (byte)((nextInt >>> 8 ) & 0xFF);
				digest[i*4 + 3] = (byte)((nextInt       ) & 0xFF);
			}
			
			reset();
			
			return digest; 
		}
	}

}
