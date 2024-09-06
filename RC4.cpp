#include<iostream>
#include<string>

using namespace std;

const int N = 1e6 + 10;

// 在C++中，char类型通常被视为有符号类型，其取值范围为-128到127
//无符号整数的取值范围为0到255
unsigned char s[256]; // S盒子

string text; // 明文密文统一用text
string secret_key; // 密钥

void init() // KSA初始化S盒
{
    unsigned key_len = secret_key.size();
    unsigned char T[256] = { 0 }; // 临时数组向量
    for (unsigned int i = 0; i < 256; i++)
    {
        s[i] = i;
        T[i] = secret_key[i % key_len];
    }
    for (int i = 0, j = 0; i < 256; i++)
    {
        j = (j + s[i] + T[i]) % 256;
        swap(s[i], s[j]);
    }
}

void encrypt_encode() // 加密或者解密都是再次经过这个函数
{
    init();
    unsigned int len = text.length();
    unsigned char k, i = 0, j = 0, t;
    for (unsigned int h = 0; h < len; h++)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        swap(s[i], s[j]);
        t = (s[i] + s[j]) % 256;
        k = s[t];
        text[h] ^= k;
    }
}

int main()
{
    cout << "请输入明文" << endl;
    cin >> text;
    cout << "请输入密钥" << endl;
    cin >> secret_key;
    encrypt_encode();
    cout << "加密后的密文：" << text << endl;
    encrypt_encode();
    cout << "解密后的明文：" << text << endl;

    return 0;
}

