#define ues_CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <string>
#include<time.h>
#define random(x) (rand()%x)

using namespace std;

int A[12] = { 1,3,5,11,21,44,87,175,349,701,1399,2798 }; //私钥 
int m; //= 5598;
int n;
int B[12];//公钥 
int sum[3000];//加密后的信息 
int sum1[3000];//加密后的摘要 
int ans[3000];//转换后的信息 
int ans1[3000];//转换后的摘要 
int kk;//加密时分组的个数 
int kkz = 0;//摘要分组的个数 
string ming; //输入的明文 
string zhai, zhai1, zhai2;//摘要 
string zu[3000];//加密分组后的信息 
string zuz[3000];//摘要分组后的信息 
string answer, answer1;//解密后的明文 
string flag[3000];//转换后的串 
string flagz[3000];//转换后的串 

string mi[37] = { "000000","000001","000010","000011","000100",
				 "000101","000110","000111","001000","001001",
				 "001010","001011","001100","001101","001110",
				 "001111","010000","010001","010010","010011",
				 "010100","010101","010110","010111","011000",
				 "011001","011010","011011","011100","011101",
				 "011110","011111","100000","100001","100010",
				 "100011","100100" };

char mm[37] = { ' ','a','b','c','d',
			   'e','f','g','h','i',
			   'j','k','l','m','n',
			   'o','p','q','r','s',
			   't','u','v','w','x',
			   'y','z','0','1','2',
			   '3','4','5','6','7',
			   '8','9' };


//最大公约数函数 
int gcd(int a, int b) {
	return b == 0 ? a : gcd(b, a % b);
}

//辗转相除法求逆元 
int ni(int m, int n) {
	int a, q, b[100], my;
	q = 0;
	a = m % n;
	my = m;
	while (a != 0) {
		a = m % n;
		b[q] = m / n;
		q++;
		m = n;
		n = a;
	}
	int bb[100], j = 2, bbb;
	bb[0] = 1;
	bb[1] = b[q - 2];
	int nn;
	nn = q - 2;
	for (int i = nn; i > 0; i--) {
		bb[j] = b[i - 1] * bb[j - 1] + bb[j - 2];
		bbb = bb[j];
		j++;
	}
	if ((q - 1) % 2 == 0) return(bbb);
	else return (my - bbb);
}

void ready() {

	//私钥 
	int sum = 0;
	cout << "私钥为:[ ";
	for (int i = 0; i < 12; i++) {
		sum += A[i];
		cout << A[i] << " ";
		if (i != 11) cout << ",";
	}
	cout << " ]" << endl;
	cout << endl;

	//随机选取m
	srand((int)time(0));
	while (1) {
		int h = random(10);
		if (h) {
			m = sum + h;
			break;
		}
	}
	srand((int)time(0));
	while (1) {
		int k = random(100);
		if (gcd(m, k) == 1 && k != 1) {
			n = k;
			break;
		}
	}


	//生成公钥 
	for (int k = 0; k < 12; k++) {
		B[k] = (A[k] * n) % m;
	}
	cout << "生成的公钥为:[ ";
	for (int i = 0; i < 12; i++) {
		cout << B[i] << " ";
		if (i != 11) cout << ",";
	}
	cout << " ]" << endl;
	cout << endl;
	cout << "随机选取的两个互素数为:" << m << " " << n << endl;
	cout << endl;
}

//加密部分 
void jiami(string ming) {
	int l = ming.length();
	string zu1;
	//int kk = 0;
	for (int k = 0; k < l; k++) {
		for (int j = 0; j < 37; j++) {
			if (mm[j] == ming[k]) {
				zu1 += mi[j];
				if (k % 2 != 0) {
					zu[kk] = zu1;
					zu1 = "";
					kk++;
				}
				if (l % 2 != 0 && k == l - 1) {
					zu1 += "000000";
					zu[kk] = zu1;
					kk++;
				}
				break;
			}
		}
	}
	for (int i = 0; i < kk; i++) {
		int l1 = zu[i].length();
		for (int j = 0; j < l1; j++) {
			if (zu[i][j] == '1') {
				sum[i] += B[j];
			}
		}

	}
	cout << "加密后进行传输的密文为:[ ";
	for (int i = 0; i < kk; i++) {
		cout << sum[i];
		if (i != kk - 1) cout << ",";
	}
	cout << " ]" << endl;
	cout << endl;
}

void jiamizhai(string ming) {

	int l = ming.length();
	string zu1;

	for (int k = 0; k < l; k++) {
		for (int j = 0; j < 37; j++) {
			if (mm[j] == ming[k]) {
				zu1 += mi[j];
				if (k % 2 != 0) {
					zuz[kkz] = zu1;
					zu1 = "";
					kkz++;
				}
				if (l % 2 != 0 && k == l - 1) {
					zu1 += "000000";
					zuz[kkz] = zu1;
					kkz++;
				}
				break;
			}
		}
	}

	for (int i = 0; i < kkz; i++) {
		int l1 = zuz[i].length();
		for (int j = 0; j < l1; j++) {
			if (zuz[i][j] == '1') {
				sum1[i] += A[j];
			}
		}

	}
	cout << "加密后进行传输的摘要为:[ ";
	for (int i = 0; i < kkz; i++) {
		cout << sum1[i];
		if (i != kkz - 1) cout << ",";
	}
	cout << " ]" << endl;
	cout << endl;
}

//解密部分
string jiemi() {
	//已知私钥A，m，n
	if (sum[0] == 0) {
		cout << "请先进行加密！" << endl;
	}
	int niyuan = ni(m, n);
	for (int i = 0; i < kk; i++) {
		ans[i] = sum[i] * niyuan % m;
		string flag1;
		for (int j = 11; j >= 0; j--) {
			if (ans[i] >= A[j]) {
				flag1 += "1";
				ans[i] = ans[i] - A[j];
			}
			else flag1 += "0";
		}
		reverse(flag1.begin(), flag1.end());
		flag[i] = flag1;
	}
	for (int i = 0; i < kk; i++) {
		string flag11, flag12;
		flag11 = flag[i].substr(0, 6);
		flag12 = flag[i].substr(6, 11);
		for (int i = 0; i < 37; i++) {
			if (mi[i] == flag11) {
				answer += mm[i];
			}
		}
		for (int i = 0; i < 37; i++) {
			if (mi[i] == flag12) {
				answer += mm[i];
			}
		}
	}
	if (ming.length() % 2 != 0) {
		answer.erase(answer.find_last_not_of(" ") + 1);
	}
	cout << "解密后的明文为:" << answer << endl;
	cout << endl;
	return answer;
}

string jiemizhai() {
	//已知公钥B，m，n
	answer1 = "";
	int BB[12];
	int niyuan = ni(m, n);
	for (int i = 0; i < 12; i++) {
		BB[i] = B[i] * niyuan % m;
	}
	for (int i = 0; i < kkz; i++) {
		string flag1;
		for (int j = 11; j >= 0; j--) {
			if (sum1[i] >= BB[j]) {
				flag1 += "1";
				sum1[i] = sum1[i] - BB[j];
			}
			else flag1 += "0";
		}
		reverse(flag1.begin(), flag1.end());
		flagz[i] = flag1;
	}
	for (int i = 0; i < kkz; i++) {
		string flag11, flag12;
		flag11 = flagz[i].substr(0, 6);
		flag12 = flagz[i].substr(6, 11);
		for (int i = 0; i < 37; i++) {
			if (mi[i] == flag11) {
				answer1 += mm[i];
			}
		}
		for (int i = 0; i < 37; i++) {
			if (mi[i] == flag12) {
				answer1 += mm[i];
			}
		}
	}

	return answer1;
}

//MD5
#define shift(x, n) (((x) << (n)) | ((x) >> (32-(n))))//右移时高位补零
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476
//strBaye的长度
unsigned int strlength;
//A,B,C,D的临时变量
unsigned int atemp;
unsigned int btemp;
unsigned int ctemp;
unsigned int dtemp;
//常量ti 
const unsigned int k[] = {
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
//向左位移数
const unsigned int s[] = { 7,12,17,22,7,12,17,22,7,12,17,22,7,
		12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
		4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,
		15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
const char str16[] = "0123456789abcdef";
void mainLoop(unsigned int M[])
{
	unsigned int f, g;
	unsigned int a = atemp;
	unsigned int b = btemp;
	unsigned int c = ctemp;
	unsigned int d = dtemp;
	for (unsigned int i = 0; i < 64; i++)
	{
		if (i < 16) {
			f = F(b, c, d);
			g = i;
		}
		else if (i < 32)
		{
			f = G(b, c, d);
			g = (5 * i + 1) % 16;
		}
		else if (i < 48) {
			f = H(b, c, d);
			g = (3 * i + 5) % 16;
		}
		else {
			f = I(b, c, d);
			g = (7 * i) % 16;
		}
		unsigned int tmp = d;
		d = c;
		c = b;
		b = b + shift((a + f + k[i] + M[g]), s[i]);
		a = tmp;
	}
	atemp = a + atemp;
	btemp = b + btemp;
	ctemp = c + ctemp;
	dtemp = d + dtemp;
}
//填充函数

unsigned int* add(string str)
{
	unsigned int num = ((str.length() + 8) / 64) + 1;//以512位,64个字节为一组
	unsigned int* strByte = new unsigned int[num * 16];
	strlength = num * 16;
	for (unsigned int i = 0; i < num * 16; i++)
		strByte[i] = 0;
	for (unsigned int i = 0; i < str.length(); i++)
	{
		strByte[i >> 2] |= (str[i]) << ((i % 4) * 8);
	}
	strByte[str.length() >> 2] |= 0x80 << (((str.length() % 4)) * 8);
	strByte[num * 16 - 2] = str.length() * 8;
	return strByte;
}
string changeHex(int a)
{
	int b;
	string str1;
	string str = "";
	for (int i = 0; i < 4; i++)
	{
		str1 = "";
		b = ((a >> i * 8) % (1 << 8)) & 0xff;   //逆序处理每个字节
		for (int j = 0; j < 2; j++)
		{
			str1.insert(0, 1, str16[b % 16]);
			b = b / 16;
		}
		str += str1;
	}
	return str;
}
string getMD5(string source)
{
	atemp = A;    //初始化
	btemp = B;
	ctemp = C;
	dtemp = D;
	unsigned int* strByte = add(source);
	for (unsigned int i = 0; i < strlength / 16; i++)
	{
		unsigned int num[16];
		for (unsigned int j = 0; j < 16; j++)
			num[j] = strByte[i * 16 + j];
		mainLoop(num);
	}
	return changeHex(atemp).append(changeHex(btemp)).append(changeHex(ctemp)).append(changeHex(dtemp));
}

int main() {

	ready();

	cout << "请输入要加密的明文:" << endl;
	cout << endl;
	cin >> ming;
	jiami(ming);//加密 
	zhai = getMD5(ming);//对发送方明文进行摘要
	cout << "对发送方明文生成的摘要为:" << zhai << endl;
	cout << endl;
	jiamizhai(zhai);//对摘要进行加密 

	answer = jiemi();//解密 
	zhai1 = jiemizhai();//对摘要进行解密 
	zhai2 = getMD5(answer);//对接收方解密后的明文进行摘要
	cout << "对接收方解密后的还原的摘要为:" << zhai1 << endl;
	cout << endl;
	cout << "对接收方解密后的明文生成的摘要为:" << zhai2 << endl;
	cout << endl;
	if (zhai1 == zhai2) cout << "认证成功！" << endl;
	else cout << "认证失败！ " << endl;
	cout << endl;
}



