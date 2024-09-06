#include<iostream>
#include<string>

using namespace std;

const int N = 1e6 + 10;

// ��C++�У�char����ͨ������Ϊ�з������ͣ���ȡֵ��ΧΪ-128��127
//�޷���������ȡֵ��ΧΪ0��255
unsigned char s[256]; // S����

string text; // ��������ͳһ��text
string secret_key; // ��Կ

void init() // KSA��ʼ��S��
{
    unsigned key_len = secret_key.size();
    unsigned char T[256] = { 0 }; // ��ʱ��������
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

void encrypt_encode() // ���ܻ��߽��ܶ����ٴξ����������
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
    cout << "����������" << endl;
    cin >> text;
    cout << "��������Կ" << endl;
    cin >> secret_key;
    encrypt_encode();
    cout << "���ܺ�����ģ�" << text << endl;
    encrypt_encode();
    cout << "���ܺ�����ģ�" << text << endl;

    return 0;
}

