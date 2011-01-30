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

class CWindow : public CElement
{
	bool m_bMaximized, m_bDragging, m_bVisible;
	CPos posDif;
	std::vector<CElement*> m_vElements;
	CElement * m_pFocussedElement;

	bool m_bCloseButtonEnabled;
	CTimer m_tCloseButtonPressed;

	CColor * pTitle, * pBodyInner, * pBodyBorder;
	CTexture * pTitlebar, * pButton;
public:
	CWindow( TiXmlElement * pElement );
	~CWindow();

	void AddElement( CElement * pElement );

	void Draw();
	void PreDraw();
	void MouseMove( CMouse & pMouse );
	bool KeyEvent( SKey sKey );

	void SetMaximized( bool bMaximized );
	bool GetMaximized();

	void SetVisible( bool bVisible );
	bool IsVisible();

	void SetDragging( bool bDragging );
	bool GetDragging();

	void SetCloseButton( bool bEnabled );
	bool GetCloseButton();

	void SetFocussedElement( CElement * pElement );
	CElement * GetFocussedElement();

	CElement * GetElementByString( const char * pszString, int iIndex = 0 );
	
	void BringToTop( CElement * pElement );

	void UpdateTheme( int iIndex );
};