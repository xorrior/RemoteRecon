#pragma once
/*
MIT License

Copyright (c) 2017 Aaron

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#ifdef _DEBUG
#include <fstream>
#define LOG(x)	do {std::fstream f("LOG.txt", std::ios::app); f << __FILE__ << " : " << __LINE__ << " - " << x << std::endl; f.close();} while(0)
#define LOG_ERROR(x, y) do {std::fstream f("LOG.txt", std::ios::app); f << __FILE__ << " : " << __LINE__ << " - " << x << " - 0x" << std::hex << y <<  std::endl; f.close();} while(0) 
#define EXCEPT(x) std::runtime_error(x)
#else
#define LOG(x)	__LINE__
#define EXCEPT(x)	std::runtime_error(std::to_string(__LINE__))
#define LOG_ERROR(x, y) (void*)0
#endif