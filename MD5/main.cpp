#include <iostream>

#include "MD5.hpp"

using namespace std;

int main()
{
	string str;
    str = "nothing";

	MD5 md5;
    md5.encode(str);
    md5.showResult();
}