#include <stdio.h>
#include <stdlib.h>

// 如果要用到C++的库，或者C++的一些东西，需要加上extern "C"，以C格式编译，避免重载的重命名
//extern "C"{
// 下面这个函数仅为测试python调用C所用
int fab(int n) 
{ 
  if (n == 1 || n == 0) 
    return 1; 
  else 
    return n * fab(n - 1); 
} 

// 调用SPDK以实现discovery controller


//}
