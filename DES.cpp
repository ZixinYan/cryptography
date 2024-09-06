#define use_CRT_SECURE_NO_WARNINGS
#include<iostream>
#include<stdio.h>
#include<string.h>
#include<fstream>
#include<Windows.h>
using namespace std;

std::string filePath = "C:\\Users\\76991\\source\\repos\\DES\\plaintext.txt";
std::string filePath2 = "C:\\Users\\76991\\source\\repos\\DES\\ciphertext.txt";
char masterkey[9];//masterkey
int key[64];//key(64 bit)
int keyPC[56];//key(56 bit)
int leftKey_28[28];//leftkey(28 bit
int rightKey_28[28];//right key(28 bit
int keyAB[56];//after ring shift left
int K[16][48];//generate key that use in DES
char plaintext[8];
int M[64];//plaintext stream
int M_ip[64];//after transposition
int L0[32];//left plaintext
int R0[32];//right plaintext
int Li[32];//temp
int Ri[32];//temp
int RE0[48];//after transposition
int RK[48];//XOR with key
int r[8], c[8];//tranposition with S
int RKS[8];//after S
int SP[32];//32 bit after S
int RKSP[32];//After P
int cipher[64];
int cipher_ip[64];
int H[300];
int C[1000];
int text[64];//store Bianry
int text_end[64];
int text_out[39][64];
int res[38][64];//ciphertext
char MiWen[300];
char* buffer;//plaintext
char* buffer_cipher;//ciphertext
int MingWen[38][8];

int IP[64] = {     //初始换位表
		13, 50, 42, 34, 26, 18, 27, 2,
		60, 52, 44, 30, 28, 20, 12, 4,
		62, 31, 46, 38, 36, 22, 14, 64,
		6, 56, 41, 7, 32, 24, 16, 8,
		57, 49, 48, 45, 25, 17, 9, 1,
		59, 51, 43, 35, 10, 19, 3, 11,
		61, 53, 33, 37, 29, 21, 58, 5,
		63, 55, 47, 39, 54, 23, 15, 40
};

int moveK[16] = { 1,1,2,2,2,2,2,1,1,2,2,2,1,1,2,1 };//ring shift left

int E[48] = { //扩展换位表
		32, 1, 2, 3, 4, 5,
		4, 5, 6, 7, 8, 9,
		8, 9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1 };

int PC1[56] = { //PC1换位表（64—>56）
		20, 2, 50, 33, 26, 17, 5,
		1, 58, 41, 42, 34, 25, 18,
		10, 48, 59, 4, 44, 35, 27,
		19, 11, 3, 60, 52, 43, 36,
		63, 55, 45, 39, 31, 23, 15,
		7, 62, 54, 47, 38, 30, 22,
		14, 6, 61, 53, 46, 37, 29,
		21, 13, 9, 28, 57, 12, 51 };

int PC2[48] = { //PC2换位表（56—>48）
		14, 17, 11, 24, 1, 5,
		3, 28, 15, 6, 21, 10,
		23, 19, 12, 4, 26, 8,
		16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32 };

int S1[4][16] = { //S换位表
	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
};
int S2[4][16] = {
	15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
	3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
	13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
};
int S3[4][16] = {
	10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
	13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
};
int S4[4][16] = {
	7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
	13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
};
int S5[4][16] = {
	2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
	14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
	11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
};
int S6[4][16] = {
	12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
};
int S7[4][16] = {
	4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
};
int S8[4][16] = {
	13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
};
int P[32] = { //P换位表
	16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
	2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
};


void getPlaintext(const std::string& filePath) {
	std::ifstream file(filePath, std::ios::binary | std::ios::ate); // 打开文件并定位到文件末尾
	if (!file.is_open()) {
		std::cerr << "Failed to open file: " << filePath << std::endl;
		return;
	}
	// 获取文件大小
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg); // 将文件指针重新定位到文件开头
	// 分配足够大的char数组来存储文件内容
	buffer = new char[size];
	// 读取文件内容到char数组
	if (file.read(buffer, size)) {
		buffer[size] = '\0';
		// 成功读取，处理buffer中的数据
		std::cout << "File content:" << std::endl;
		std::cout.write(buffer, size);
		std::cout << std::endl;
	}
	else {
		std::cerr << "Failed to read file: " << filePath << std::endl;
	}
	// 关闭文件并释放内存
	file.close();
}

void getCiphertext(const std::string& filePath) {
	std::ifstream file(filePath, std::ios::binary | std::ios::ate); // 打开文件并定位到文件末尾
	if (!file.is_open()) {
		std::cerr << "Failed to open file: " << filePath << std::endl;
		return;
	}
	// 获取文件大小
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg); // 将文件指针重新定位到文件开头
	// 分配足够大的char数组来存储文件内容
	buffer_cipher = new char[size];
	// 读取文件内容到char数组
	if (file.read(buffer_cipher, size)) {
		buffer_cipher[size] = '\0';
		// 成功读取，处理buffer中的数据
		std::cout << "File content:" << std::endl;
		std::cout.write(buffer_cipher, size);
		std::cout << std::endl;
	}
	else {
		std::cerr << "Failed to read file: " << filePath << std::endl;
	}
	// 关闭文件并释放内存
	file.close();
}


void intit_key() {
	cout << "Please enter key(8bit): " << endl;
	gets_s(masterkey);
	int m = 0;
	for (int i = 0; i < 8; i++) {       //Change to 64 bit
		int a[8] = { 0,0,0,0,0,0,0,0 }; 
		m = masterkey[i];
		for (int j = 0; m != 0; j++) {
			a[j] = m % 2;
			m = m / 2;
		}
		for (int j = 0; j < 8; j++) {
			key[(i * 8) + j] = a[7 - j];
		}
	}
	//check
	//cout << "Key(64 bit):" << endl;
	//for (int i = 0; i < 64; i++) {
	//	cout << key[i];
	//}
	//change to 56 bit
	for (int i = 0; i < 56; i++) {
		keyPC[i] = key[PC1[i] - 1];
	}
	//spreate key
	for (int i = 0; i < 28; i++) {
		leftKey_28[i] = keyPC[i];
		rightKey_28[i] = keyPC[i + 28];
	}
	//ring shift left
	for (int t = 0; t < 16; t++) {
		int flag = moveK[t];
		char temp[28];
		//deal left
		for (int m = 0; m < flag; m++) {
			temp[m] = leftKey_28[m];
		}
		for (int j = 0; j < 27; j++) {
			leftKey_28[j] = leftKey_28[j + flag];
		}
		for (int m = flag; m > 0; m--) {
			leftKey_28[28 - m] = temp[m - 1];
		}
		//deal right
		for (int m = 0; m < flag; m++) {
			temp[m] = rightKey_28[m];
		}
		for (int j = 0; j < 27; j++) {
			rightKey_28[j] = rightKey_28[j + flag];
		}
		for (int m = flag; m > 0; m--) {
			rightKey_28[28 - m] = temp[m - 1];
		}
		//generate 56 bit key again
		for (int i = 0; i < 28; i++) {
			keyAB[i] = leftKey_28[i];
			keyAB[i + 28] = rightKey_28[i];
		}
		//change to 48 bit
		for (int i = 0; i < 48; i++) {
			K[t][i] = keyAB[PC2[i] - 1];
		}
	}
}

void Encrypt() {
	cout << "Encryption:" << endl;
	getPlaintext(filePath);
	int i = 0;
	int n = 0;
	while (buffer[i] != '\0') {
		n++;
		i++;
	}
	int k = n % 8;
	n = (n - 1) / 8 + 1;

	for (int l = 0; l < n; l++) {
		if (l == (n - 1) && k != 0) {
			for (int i = 0; i < k; i++) {
				plaintext[i] = buffer[i + (8 * l)];
			}
			for (int i = k; i < 8; i++) {
				plaintext[i] = ' ';
			}
		}
		else {
			for (int i = 0; i < 8; i++) {
				plaintext[i] = buffer[i + (8 * l)];
			}
		}
			//change to 64bit
		for (int i = 0; i < 8; i++) {
			int a[8] = { 0,0,0,0,0,0,0,0 };
			int m = plaintext[i];
			for (int j = 0; m != 0; j++) {
				a[j] = m % 2;
				m = m / 2;
			}
			for (int j = 0; j < 8; j++) {
				M[(i * 8) + j] = a[7 - j];
			}
		}
		//XOR
		for (int i = 0; i < 64; i++) {
			M[i] = text_out[l][i] ^ M[i];
		}
		//transposition with Ip
		for (int i = 0; i < 64; i++) {
			M_ip[i] = M[IP[i] - 1];
		}
		//divide to two part
		for (int i = 0; i < 32; i++) {
			L0[i] = M_ip[i];
			R0[i] = M_ip[i + 32];
		}

		//cycle 16 times
		for (int t = 0; t < 16; t++) {
			//expand to 48bit
			for (int i = 0; i < 48; i++) {
				RE0[i] = R0[E[i] - 1];
			}
			//XOR with key
			for (int i = 0; i < 48; i++) {
				RK[i] = RE0[i] ^ K[t][i];
			}
			//transposition with S
			for (int i = 0; i < 8; i++) {
				r[i] = RK[(i * 6) + 0] * 2 + RK[(i * 6) + 5];
				c[i] = RK[(i * 6) + 1] * 8 + RK[(i * 6) + 2] * 4 + RK[(i * 6) + 3] * 2 + RK[(i * 6) + 4];
			}
			RKS[0] = S1[r[0]][c[0]];
			RKS[1] = S2[r[1]][c[1]];
			RKS[2] = S3[r[2]][c[2]];
			RKS[3] = S4[r[3]][c[3]];
			RKS[4] = S5[r[4]][c[4]];
			RKS[5] = S6[r[5]][c[5]];
			RKS[6] = S7[r[6]][c[6]];
			RKS[7] = S8[r[7]][c[7]];
			//trans to 32 bit
			for (int i = 0; i < 8; i++)
			{
				int b[4] = { 0,0,0,0 };
				int m = RKS[i];
				for (int j = 3; m != 0; j--)
				{
					b[j] = m % 2;
					m = m / 2;
				}
				for (int j = 0; j < 4; j++)
					SP[j + (i * 4)] = b[j];
			}
			//transposition with P
			for (i = 0; i < 32; i++)
				RKSP[i] = SP[P[i] - 1];
			//XOR with left
			for (i = 0; i < 32; i++) 
				Ri[i] = L0[i] ^ RKSP[i];

			for (i = 0; i < 32; i++)
			{
				L0[i] = R0[i];
				R0[i] = Ri[i];
			}
		}
		//exchange left and right
		for (i = 0; i < 32; i++)
			Li[i] = R0[i];
		for (i = 0; i < 32; i++)
			R0[i] = L0[i];
		for (i = 0; i < 32; i++)
			L0[i] = Li[i];
		//Get end
		for (int i = 0; i < 32; i++) {
			text_end[i] = L0[i];
			text_end[i + 32] = R0[i];
		}
		//-1
		for (int i = 0; i < 64; i++) {
			text_out[l + 1][IP[i] - 1] = text_end[i];
		}
		for (int i = 0; i < 64; i++) {
			res[l][i] = text_out[l + 1][i];
		}
	}

	for (int j = 0; j < n; j++) //把result中的二进制密文转成十进制存到数组H中
		for (i = 0; i < 16; i++)
			H[i + (j * 16)] = res[j][0 + (i * 4)] * 8 + res[j][1 + (i * 4)] * 4 + res[j][2 + (i * 4)] * 2 + res[j][3 + (i * 4)];

	//for(i=0;i<l*16;i++)
	//printf("%d,",H[i]);

	for (int i = 0; i < n * 16; i++)
	{
		if (H[i] < 10)
			MiWen[i] = H[i] + 48;
		else if (H[i] == 10)
			MiWen[i] = 'A';
		else if (H[i] == 11)
			MiWen[i] = 'B';
		else if (H[i] == 12)
			MiWen[i] = 'C';
		else if (H[i] == 13)
			MiWen[i] = 'D';
		else if (H[i] == 14)
			MiWen[i] = 'E';
		else if (H[i] == 15)
			MiWen[i] = 'F';
		//else MiWen[i]='\0';
	}
	cout << "Ciper text is: " << endl;
	cout << MiWen << endl;
	puts("");
}
int Decrypt() {
	cout << "Decryption:" << endl;
	getCiphertext(filePath2);
	//get Miwen
	int count = 0;
	while (buffer_cipher[count] != '\0') {
		MiWen[count] = buffer_cipher[count];
		count++;
	}
	//inital array H
	for (int i = 0; i < 300; i++)
		H[i] = 0;
	int i;
	for (i = 0; MiWen[i] != '\0'; i++) //将十六进制密文转化成十进制存放在数组H中
	{
		if (MiWen[i] >= '0' && MiWen[i] <= '9')
			H[i] = MiWen[i] - '0';
		else if (MiWen[i] >= 'A' && MiWen[i] <= 'F')
			H[i] = MiWen[i] - 'A' + 10;
		else if (MiWen[i] >= 'a' && MiWen[i] <= 'f')
			H[i] = MiWen[i] - 'a' + 10;
		else {
			cout << "Error" << endl;
			return 0;
		}
	}

	int n = i;
	if (n % 16 != 0) {
		cout << "Error" << endl;
		return 0;
	}

	//change to H
	for (int i = 0; i < n; i++) {
		int he[4] = { 0,0,0,0 };
		for (int j = 3; H[i] != 0; j--) {
			he[j] = H[i] % 2;
			H[i] = H[i] / 2;
		}
		for (int j = 0; j < 4; j++) {
			C[j + (i * 4)] = he[j];
		}
	}

	int k = n / 16;
	//Decrypt
	for (int l = 0; l < k; l++) {
		//64bit
		for (int i = 0; i < 64; i++) {
			text_out[l + 1][i] = C[i + (l * 64)];
		}
		//teansposition
		for (int i = 0; i < 64; i++) {
			text_end[i] = text_out[l + 1][IP[i] - 1];
		}
		//divide to two parts
		for (int i = 0; i < 32; i++) {
			L0[i] = text_end[i];
			R0[i] = text_end[i + 32];
		}

		//cycle 16 times
		for (int t = 0; t < 16; t++) {
			//expand to 48 bit(!!! right
			for (int i = 0; i < 48; i++) {
				RE0[i] = R0[E[i] - 1];
			}
			//XOR with key
			for (int i = 0; i < 48; i++) {
				RK[i] = RE0[i] ^ K[15 - t][i];
			}
			//transposition P
			for (i = 0; i < 8; i++)
			{
				r[i] = RK[(i * 6) + 0] * 2 + RK[(i * 6) + 5];
				c[i] = RK[(i * 6) + 1] * 8 + RK[(i * 6) + 2] * 4 + RK[(i * 6) + 3] * 2 + RK[(i * 6) + 4];
			}

			RKS[0] = S1[r[0]][c[0]];
			RKS[1] = S2[r[1]][c[1]];
			RKS[2] = S3[r[2]][c[2]];
			RKS[3] = S4[r[3]][c[3]];
			RKS[4] = S5[r[4]][c[4]];
			RKS[5] = S6[r[5]][c[5]];
			RKS[6] = S7[r[6]][c[6]];
			RKS[7] = S8[r[7]][c[7]];
			//trans to 32 bit
			for (i = 0; i < 8; i++) 
			{
				int b[4] = { 0,0,0,0 };
				int m = RKS[i];
				for (int j = 3; m != 0; j--)
				{
					b[j] = m % 2;
					m = m / 2;
				}
				for (int j = 0; j < 4; j++)
					SP[j + (i * 4)] = b[j];
			}
			//transposition P
			for (i = 0; i < 32; i++) 
				RKSP[i] = SP[P[i] - 1];
			//XOR with left
			for (i = 0; i < 32; i++) 
				Ri[i] = L0[i] ^ RKSP[i];

			for (i = 0; i < 32; i++)
			{
				L0[i] = R0[i];
				R0[i] = Ri[i];
			}
		}

		//exchange left and right

		for (i = 0; i < 32; i++)
			Li[i] = R0[i];
		for (i = 0; i < 32; i++)
			R0[i] = L0[i];
		for (i = 0; i < 32; i++)
			L0[i] = Li[i];

		//teansposition

		for (i = 0; i < 32; i++) //combine two parts
			text_end[i] = L0[i];
		for (i = 32; i < 64; i++)
			text_end[i] = R0[i - 32];

		for (i = 0; i < 64; i++) //transposition 
			text[IP[i] - 1] = text_end[i];

	    for (i = 0; i < 64; i++) 
		    res[l][i] = text_out[l][i] ^ text[i];
	}
	//trans to H
	for (int i = 0; i < (n / 16); i++) {
		for (int j = 0; j < 8; j++) {
			MingWen[i][j] = res[i][(j * 8) + 0] * 128 + res[i][(j * 8) + 1] * 64 + res[i][(j * 8) + 2] * 32 
				+ res[i][(j * 8) + 3] * 16 + res[i][(j * 8) + 4] * 8 + res[i][(j * 8) + 5] * 4 
				+ res[i][(j * 8) + 6] * 2 + res[i][(j * 8) + 7];
		}
	}

	cout << "Plaintext is: " << endl;
	for (int i = 0; i < (n / 16); i++)
		for (int j = 0; j < 8; j++)
			printf("%c", (char)MingWen[i][j]);
	puts("");
	puts("");
}
int main() {
	intit_key();
	Encrypt();
	Decrypt();
	Sleep(1999);
}