#include<iostream>
#include<string>
#include<vector>
#include<cstdio>
#include<fstream>

namespace  md5 {
	//UINT4 defines a four byte word
	typedef unsigned int UINT4;
	typedef unsigned char* POINTER;

	//define four auxiliary functions
#define F(x,y,z) (((x)&(y))|((~x)&(z)))
#define G(x,y,z) (((x)&(z))|((y)&(~z)))
#define H(x,y,z) ((x)^(y)^(z))
#define I(x,y,z) ((y)^((x)|(~z)))

#define  ROTATE_LEFT(x,n) (((x)<<(n))| ((x)>>(32-(n))))

	using std::string;
	using std::cin;
	using std::cout;
	using std::endl;

	//
	void FF(UINT4& a, UINT4 b, UINT4 c, UINT4 d, UINT4 m, UINT4 s, UINT4 t)
	{

		a = b + ROTATE_LEFT((a + F(b, c, d) + m + t), s);
	}
	void GG(UINT4& a, UINT4 b, UINT4 c, UINT4 d, UINT4 m, UINT4 s, UINT4 t)
	{
		a = b + ROTATE_LEFT((a + G(b, c, d) + m + t), s);
	}
	void HH(UINT4& a, UINT4 b, UINT4 c, UINT4 d, UINT4 m, UINT4 s, UINT4 t)
	{
		a = b + ROTATE_LEFT((a + H(b, c, d) + m + t), s);
	}
	void II(UINT4& a, UINT4 b, UINT4 c, UINT4 d, UINT4 m, UINT4 s, UINT4 t)
	{
		a = b + ROTATE_LEFT((a + I(b, c, d) + m + t), s);
	}


	typedef struct {
		UINT4 state[4];                                   /* state (ABCD) */
		UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
		unsigned char buffer[64];                         /* input buffer */
	} MD5_CTX;

	//Initialize MD Buffer
	void MD5Init(MD5_CTX* context)
	{
		context->count[0] = context->count[1] = 0;
		/* Load magic initialization constants.
	   */
		context->state[0] = 0x67452301;
		context->state[1] = 0xefcdab89;
		context->state[2] = 0x98badcfe;
		context->state[3] = 0x10325476;
	}

	//k[i]=4294967296*abs(sin(i))
	const unsigned int t[] = {
			0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
			0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,
			0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,
			0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,
			0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
			0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,
			0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,
			0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,
			0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
			0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,
			0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,
			0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,
			0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
	//循环左移位数
	const unsigned int  s[] = {
		7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
		5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
		4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
		6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
	};

	static unsigned char PADDING[] =
	{
	 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	static void MD5_memcpy(POINTER output, POINTER input, unsigned int len)
	{
		unsigned int i;
		for (i = 0; i < len; i++)
			output[i] = input[i];
	}

	static void MD5_memset(POINTER output, int value, unsigned int len)
	{
		unsigned int i;
		for (i = 0; i < len; i++)
			((char*)output)[i] = (char)value;
	}

	static void MD5_print(unsigned char digest[16])
	{
		unsigned int i;
		for (i = 0; i < 16; i++)
		{
			printf("%02x", digest[i]);
		}
	}
	//8->32
	static void Decode(UINT4* output, unsigned char* input, unsigned int len)
	{
		unsigned int i, j;

		for (i = 0, j = 0; j < len; j += 4, i++)
		{
			output[i] = ((UINT4)input[j]) | (((UINT4)input[j + 1]) << 8) | (((UINT4)input[j + 2]) << 16) | (((UINT4)input[j + 3]) << 24);
		}
	}
	//32->8
	static void Encode(unsigned char* output, UINT4* input, unsigned int len)
	{
		unsigned int i, j;
		for (i = 0, j = 0; j < len; i++, j += 4)
		{
			output[j] = (unsigned char)(input[i] & 0xff);
			output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
			output[j + 2] = (unsigned  char)((input[i] >> 16) & 0xff);
			output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);

		}
	}
	//md5基本转换
	static void  MD5Transform(UINT4 state[4], unsigned char block[64])
	{
		UINT4 a = state[0], b = state[1], c = state[2], d = state[3], M[16];
		Decode(M, block, 64);
		int i = 0;
		FF(a, b, c, d, M[0], s[i], t[i]); i++;
		FF(d, a, b, c, M[1], s[i], t[i]); i++;
		FF(c, d, a, b, M[2], s[i], t[i]); i++;
		FF(b, c, d, a, M[3], s[i], t[i]); i++;
		FF(a, b, c, d, M[4], s[i], t[i]); i++;
		FF(d, a, b, c, M[5], s[i], t[i]); i++;
		FF(c, d, a, b, M[6], s[i], t[i]); i++;
		FF(b, c, d, a, M[7], s[i], t[i]); i++;
		FF(a, b, c, d, M[8], s[i], t[i]); i++;
		FF(d, a, b, c, M[9], s[i], t[i]); i++;
		FF(c, d, a, b, M[10], s[i], t[i]); i++;
		FF(b, c, d, a, M[11], s[i], t[i]); i++;
		FF(a, b, c, d, M[12], s[i], t[i]); i++;
		FF(d, a, b, c, M[13], s[i], t[i]); i++;
		FF(c, d, a, b, M[14], s[i], t[i]); i++;
		FF(b, c, d, a, M[15], s[i], t[i]); i++;

		GG(a, b, c, d, M[1], s[i], t[i]); i++;
		GG(d, a, b, c, M[6], s[i], t[i]); i++;
		GG(c, d, a, b, M[11], s[i], t[i]); i++;
		GG(b, c, d, a, M[0], s[i], t[i]); i++;
		GG(a, b, c, d, M[5], s[i], t[i]); i++;
		GG(d, a, b, c, M[10], s[i], t[i]); i++;
		GG(c, d, a, b, M[15], s[i], t[i]); i++;
		GG(b, c, d, a, M[4], s[i], t[i]); i++;
		GG(a, b, c, d, M[9], s[i], t[i]); i++;
		GG(d, a, b, c, M[14], s[i], t[i]); i++;
		GG(c, d, a, b, M[3], s[i], t[i]); i++;
		GG(b, c, d, a, M[8], s[i], t[i]); i++;
		GG(a, b, c, d, M[13], s[i], t[i]); i++;
		GG(d, a, b, c, M[2], s[i], t[i]); i++;
		GG(c, d, a, b, M[7], s[i], t[i]); i++;
		GG(b, c, d, a, M[12], s[i], t[i]); i++;

		HH(a, b, c, d, M[5], s[i], t[i]); i++;
		HH(d, a, b, c, M[8], s[i], t[i]); i++;
		HH(c, d, a, b, M[11], s[i], t[i]); i++;
		HH(b, c, d, a, M[14], s[i], t[i]); i++;
		HH(a, b, c, d, M[1], s[i], t[i]); i++;
		HH(d, a, b, c, M[4], s[i], t[i]); i++;
		HH(c, d, a, b, M[7], s[i], t[i]); i++;
		HH(b, c, d, a, M[10], s[i], t[i]); i++;
		HH(a, b, c, d, M[13], s[i], t[i]); i++;
		HH(d, a, b, c, M[0], s[i], t[i]); i++;
		HH(c, d, a, b, M[3], s[i], t[i]); i++;
		HH(b, c, d, a, M[6], s[i], t[i]); i++;
		HH(a, b, c, d, M[9], s[i], t[i]); i++;
		HH(d, a, b, c, M[12], s[i], t[i]); i++;
		HH(c, d, a, b, M[15], s[i], t[i]); i++;
		HH(b, c, d, a, M[2], s[i], t[i]); i++;

		II(a, b, c, d, M[0], s[i], t[i]); i++;
		II(d, a, b, c, M[7], s[i], t[i]); i++;
		II(c, d, a, b, M[14], s[i], t[i]); i++;
		II(b, c, d, a, M[5], s[i], t[i]); i++;
		II(a, b, c, d, M[12], s[i], t[i]); i++;
		II(d, a, b, c, M[3], s[i], t[i]); i++;
		II(c, d, a, b, M[10], s[i], t[i]); i++;
		II(b, c, d, a, M[1], s[i], t[i]); i++;
		II(a, b, c, d, M[8], s[i], t[i]); i++;
		II(d, a, b, c, M[15], s[i], t[i]); i++;
		II(c, d, a, b, M[6], s[i], t[i]); i++;
		II(b, c, d, a, M[13], s[i], t[i]); i++;
		II(a, b, c, d, M[4], s[i], t[i]); i++;
		II(d, a, b, c, M[11], s[i], t[i]); i++;
		II(c, d, a, b, M[2], s[i], t[i]); i++;
		II(b, c, d, a, M[9], s[i], t[i]); i++;

		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;

		MD5_memset((POINTER)M, 0, sizeof(M));
	}

	void MD5_Update(MD5_CTX* context, unsigned char* input, unsigned int inputLen)
	{
		unsigned int i, index, partLen;

		//padding
		index = (UINT4)((context->count[0] >> 3) & 0x3F);

		//进位 
		if ((context->count[0] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3))
		{
			context->count[1]++;
		}

		context->count[1] += ((UINT4)inputLen >> 29);

		partLen = 64 - index;

		if (inputLen >= partLen)
		{
			MD5_memcpy((POINTER)&context->buffer[index], (POINTER)input, partLen);
			MD5Transform(context->state, context->buffer);


			for (i = partLen; i + 63 < inputLen; i += 64)
				MD5Transform(context->state, &input[i]);

			index = 0;
		}
		else
			i = 0;

		MD5_memcpy
		((POINTER)&context->buffer[index], (POINTER)&input[i], inputLen - i);

	}

	string toHex(UINT4 num)
	{
		int x;
		string tp;
		char HexArray[] = "0123456789abcdef";
		string str = "";
		for (int i = 0; i < 4; i++)
		{
			tp = "";
			x = ((num >> i * 8) % (1 << 8)) & 0xff;
			for (int j = 0; j < 2; j++)
			{
				tp.insert(0, 1, HexArray[x % 16]);
				x /= 16;
			}
			str += tp;
		}
		return str;
	}


	string MD5_Final(unsigned char digest[16], MD5_CTX* context)
	{
		unsigned char bits[8];
		unsigned int index, padLen;
		Encode(bits, context->count, 8);


		//填充操作
		index = (unsigned int)((context->count[0] >> 3) & 0x3f);
		padLen = (index < 56) ? (56 - index) : (120 - index);
		MD5_Update(context, PADDING, padLen);
		//长度
		MD5_Update(context, bits, 8);

		string s = "";
		for (int i = 0; i < 4; i++)
			s += toHex(context->state[i]);
		cout << s;
		//摘要中的存储状态
		Encode(digest, context->state, 16);

		MD5_memset((POINTER)context, 0, sizeof(*context));

		return s;
	}



	string MDString(char* string)
	{
		MD5_CTX context;
		char* digest = new char[16];
		unsigned int len = strlen(string);

		MD5Init(&context);
		MD5_Update(&context, (unsigned char*)string, len);
		std::string  s = MD5_Final((unsigned char*)digest, &context);

		//MD5_print((unsigned char*)digest);

		return s;
	}

	string MDFile(char* filename)
	{
		MD5_CTX context;
		int len;
		unsigned char buffer[1024], digest[16];
		std::fstream inFile;
		inFile.open(filename, std::ios::binary | std::ios::in);
		if (!inFile.is_open()) {
			cout << "Could not open the file:" << endl;
			cout << "Program terminating!\n";
			exit(EXIT_FAILURE);
		}
		else
		{
			MD5Init(&context);
			while (inFile.good() && !inFile.eof())
			{
				inFile.read((char*)buffer, 1024);
				MD5_Update(&context, buffer, inFile.gcount());
			}
			std::string s = MD5_Final(digest, &context);

			//MD5_print(digest);
			return s;
		}

	}

}