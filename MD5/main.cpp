#include <iostream>

#include "MD5.hpp"

using std::cout;
using std::endl;

int main()
{
	string str;
    str = "nothing";

	MD5 md5(str);
    
    cout << md5.toStr() << endl;
}