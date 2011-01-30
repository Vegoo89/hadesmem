/*
Copyright (c) 2010 Jan Miguel Garcia (bobbysing)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#pragma once

#include "CGUI.h"

struct SKey
{
	char m_vKey;
	bool m_bDown;
	LPARAM m_lParam;

	SKey()
	{
		m_vKey = 0;
		m_bDown = false;
		m_lParam = 0;
	}
	SKey( char vKey, bool bDown )
	{
		m_vKey = vKey;
		m_bDown = bDown;
		m_lParam = 0;
	}
	SKey( char vKey, bool bDown, LPARAM lParam )
	{
		m_vKey = vKey;
		m_bDown = bDown;
		m_lParam = lParam;
	}
};

class CKeyboard
{
	SKey m_sKey;

public:

	bool HandleMessage( unsigned int uMsg, /*__w64*/ unsigned int wParam, /*_w64*/ long lParam );

	void SetKey( SKey sKey );
	SKey GetKey();
};