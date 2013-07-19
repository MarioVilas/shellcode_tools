// NOTE: The "char" type MUST be UNsigned by default!


/** Headers *****************************************************************/


/* 
 * Either define WIN32_LEAN_AND_MEAN, or one or more of NOCRYPT,
 * NOSERVICE, NOMCX and NOIME, to decrease compile time (if you
 * don't need these defines -- see windows.h).
 */
#define WIN32_LEAN_AND_MEAN
/* #define NOCRYPT */
/* #define NOSERVICE */
/* #define NOMCX */
/* #define NOIME */

#include <windows.h>
#include <windowsx.h>
#include <tchar.h>
#include <unknwn.h>		// needed for old versions of Pelle's C
#include <commctrl.h>
#include <commdlg.h>
#include <richedit.h>
#include <shlwapi.h>
#include <imagehlp.h>
#include <string.h>
#include "disasm.h"


/** Resource IDs ************************************************************/


#define IDI_ICON1 100		// Main program icon.
#define IDI_ICON2 101		// "Browse" icon.
#define IDI_ICON3 102		// "Assemble" icon.
#define IDI_ICON4 103		// "Search" icon.

#define IDD_MAIN 1000		// Main dialog box.

#define IDC_LABEL1 1001		// "Library" (label).
#define IDC_EDIT1 1002		// Library filename (edit box).
#define IDC_BUTTON1 1003	// "Browse" (button).
#define IDC_LABEL2 1004		// "Code" (label).
#define IDC_EDIT2 1005		// Assembly single-line command (edit box).
#define IDC_BUTTON2 1006	// "Assemble" (button).
#define IDC_LABEL3 1007		// "Binary" (label).
#define IDC_EDIT3 1008		// Bytecode display (edit box).
#define IDC_BUTTON3 1009	// "Search" (button).
#define IDC_RICHEDIT1 1010	// Results report (rich edit).
#define IDC_LABEL4 1011		// Status messages (label).


/** Prototypes **************************************************************/


static LRESULT CALLBACK MainDlgProc(HWND, UINT, WPARAM, LPARAM);
static LONG CalcFontHeight(int pt);
static BOOL BytecodeToText(TCHAR *output);
static BOOL FindBytecodeInFile(HWND hDlg);
static void FindBytecodeInSection(HWND hDlg, PIMAGE_SECTION_HEADER pSecHdr, PLOADED_IMAGE Image);
static void AppendToReport(HWND hDlg, PIMAGE_SECTION_HEADER pSecHdr, PLOADED_IMAGE Image, int count);
static void AppendText(HWND hRichEdt, TCHAR *pszText);


/** Global variables ********************************************************/


// Module instance handle. We use this to load resources.
static HINSTANCE ghInstance;

// Monospaced font to use in the list box.
static LOGFONT g_lf = {
	0,0,
	0,0,FW_DONTCARE,FALSE,FALSE,FALSE,
	DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,
	FIXED_PITCH | FF_DONTCARE,
	_T("Courier New")
};

// This globals are used to assemble mnemonics.
// (I know it's ugly, but it was the easiest way, honest...)
static int attempt = 0;
static int constsize = 0;
static t_asmmodel asmmodel;

// Paths and filenames buffers. Used for GetOpenFileName().
static TCHAR gsCustomFilter[MAX_PATH];	// Empty on startup, changed later by the user.
static TCHAR gsInitialDir[MAX_PATH];	// %SYSTEM% on app startup, chaged later by user.
static TCHAR gsFilename[MAX_PATH];		// Contains the DLL library filename.
//static TCHAR gsPathname[MAX_PATH * 2];	// Full pathname, generated from gsFilename.

// Valid file type filters. Used for GetOpenFileName().
static const TCHAR gsFilter[] =
	"Dynamic link libraries\0*.dll\0"
	"All PE files\0*.cpl;*.dll;*.exe;*.ocx;*.scr\0"
	"All files\0*.*\0"
	"\0";

// Setup for the GetOpenFileName() dialog box.
static OPENFILENAME gOfn =
{
	sizeof(OPENFILENAME), 0, 0,
	(TCHAR *)gsFilter, (TCHAR *)gsCustomFilter, sizeof(gsCustomFilter), 0,
	(TCHAR *)&gsFilename, sizeof(gsFilename),
	0, 0, (TCHAR *)&gsInitialDir, _T("Browse for DLL..."),
	OFN_FILEMUSTEXIST | OFN_HIDEREADONLY,
	0, 0, _T(".dll"), 0, 0, 0
};	// Unsupported flags: OFN_DONTADDTORECENT, OFN_FORCESHOWHIDDEN


/** Procedures **************************************************************/


static BOOL TryToAssemble(char *psCommand, char *psError)
{
	// Globals:
	// in/out:
	//		attempt
	// 		constsize
	//		asmmodel

	// Try to assemble at the four different const sizes.
	// If we had at least one successful assembly at some const size,
	//  we are allowed to move on to the next attempt.
	// If we fail at attempt 0, const size 0, we just quit.
	// If we get repeated bytecodes, skip them and keep trying.
	// The variables "constsize" and "attempt" are globals, because I wanted
	//  to access them from MainProc.
	t_asmmodel local_asmmodel;
	psError[0] = 0;
	memcpy(&local_asmmodel, &asmmodel, sizeof(local_asmmodel));
	while( TRUE )
	{
		BOOL we_had_a_good_one = ( constsize > 0 );
		while( constsize < 4 )
		{
			int status = Assemble(psCommand, 0, &local_asmmodel, attempt, constsize, psError);
			constsize++;
			if( status > 0 )
			{
				if( memcmp(&(local_asmmodel.code), &(asmmodel.code), sizeof(TEXTLEN)) != 0 )
				{
					memcpy(&asmmodel, &local_asmmodel, sizeof(asmmodel));
					return TRUE;
				};
			}
			else if( attempt == 0 && constsize == 1 )
			{
				constsize = 0;
				return FALSE;
			};
		};
		constsize = 0;
		attempt++;
		if( !we_had_a_good_one ) break;
	};
//	attempt = 0;
	return FALSE;
};


static BOOL BytecodeToText(char *output)
{
	// Globals:
	// in:
	//		asmmodel

	// Converts the opcodes to hexa values for display.
	// Uses ASCIIZ strings only.
	char sTemp[8];		// BOF warning
	int i;
	BOOL iComplete = TRUE;
	output[0] = 0;
	for( i = 0; i < asmmodel.length; i++ )
	{
		char msk = asmmodel.mask[i];
		char ch = asmmodel.code[i] & msk;
		if( msk != 0xFF )
		{
			iComplete = FALSE;
		};
		sTemp[0] = 0;
		wsprintfA((char *)sTemp, "%.2X ", (int)ch);
		lstrcatA(output, (char *)sTemp);
	};
	return iComplete;
};


static BOOL FindBytecodeInFile(HWND hDlg)
{
	BOOL iSuccess = FALSE;
	LOADED_IMAGE Image;

	// Clear the report.
	SetDlgItemText(hDlg, IDC_RICHEDIT1, NULL);

	// Load the PE file into memory.
	if( MapAndLoad((char *)&gsFilename, NULL, &Image, TRUE, TRUE) )
	{
		// For each section...
		__try
		{
			ULONG iSectionCount = Image.NumberOfSections;
			PIMAGE_SECTION_HEADER pSecHdr = Image.Sections;
			while( iSectionCount > 0 )
			{
				// Search for the bytecode in this section.
				if( (*pSecHdr).PointerToRawData != 0 )
				{
					FindBytecodeInSection(hDlg, pSecHdr, &Image);
				};

				// Next section.
				pSecHdr++;
				iSectionCount--;
			};
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			char *pStr;
			pStr = LocalAlloc(LPTR, 512);
			if( pStr == NULL ) pStr = _T("Exception!");
			wsprintf(pStr, _T("Exception %X was thrown!"), exception_code());
			MessageBox(hDlg, pStr, _T("Debug"), MB_OK);
			LocalFree(pStr);
		};

		// Success!
		iSuccess = TRUE;

		// Unload the PE file from memory.
		UnMapAndLoad(&Image);
	};
	return iSuccess;
};


static void FindBytecodeInSection(HWND hDlg, PIMAGE_SECTION_HEADER pSecHdr, PLOADED_IMAGE Image)
{
	char *rawptr;
	int max;
	int count;
	DWORD bcpos;

	rawptr = (char *)((*Image).MappedAddress + (*pSecHdr).PointerToRawData);
	max = (*pSecHdr).SizeOfRawData;
	if( !IsBadReadPtr(rawptr, max) )
	{
		count = 0;
		while( count < (int)(max - asmmodel.length) )
		{
			bcpos = 0;
			while( bcpos < asmmodel.length && asmmodel.code[bcpos] == rawptr[bcpos] )
			{
				bcpos++;
			};
			if( bcpos == asmmodel.length )
			{
				AppendToReport(hDlg, pSecHdr, Image, count);
			};
			rawptr++;
			count++;
		};
	}
	else
	{
		MessageBox(hDlg, _T("Bad read pointer!"), _T("Debug"), MB_OK);
	};
};


static void AppendToReport(HWND hDlg, PIMAGE_SECTION_HEADER pSecHdr, PLOADED_IMAGE Image, int count)
{
	PIMAGE_NT_HEADERS pNtHdr;
	DWORD RVA;
	DWORD RA;
	TCHAR buffer[256];

	pNtHdr = ImageNtHeader((*Image).MappedAddress);
	if( pNtHdr == NULL )
	{
		MessageBox(hDlg, _T("No NT header!"), _T("Debug"), MB_OK);
		return;
	};
	RVA = (*pSecHdr).VirtualAddress + count;
	RA = RVA + (*pNtHdr).OptionalHeader.ImageBase;
	buffer[0] = 0;
	wsprintf(
		(TCHAR *)&buffer,
		_T("Found at 0x%08X (RVA 0x%08X).\n"),
		RA,
		RVA);
	AppendText(GetDlgItem(hDlg, IDC_RICHEDIT1), (TCHAR *)&buffer);
};


static void AppendText(HWND hRichEdt, TCHAR *pszText)
{
	CHARRANGE cr_old;
	CHARRANGE cr_new;

	// Initialize the local variables.
	cr_old.cpMin = cr_old.cpMax = 0;
	cr_new.cpMin = cr_new.cpMax = -1;

	// Lock the window redrawing.
	LockWindowUpdate(hRichEdt);

	// Get the current selection range.
	SendMessage(hRichEdt, EM_EXGETSEL, 0, (LPARAM)&cr_old);

	// Set the selection to the end of the current text.
	SendMessage(hRichEdt, EM_EXSETSEL, 0, (LPARAM)&cr_new);

	// Append the text.
	SendMessage(hRichEdt, EM_REPLACESEL, FALSE, (LPARAM)pszText);

	// Set the previous selection range.
	SendMessage(hRichEdt, EM_EXSETSEL, 0, (LPARAM)&cr_old);

	// Unlock window redrawing.
	LockWindowUpdate(NULL);
};


static LONG CalcFontHeight(int pt)
{
	HWND hWnd = GetDesktopWindow();
	HDC hDC = GetDC(hWnd);
	int height = -((GetDeviceCaps(hDC, LOGPIXELSY) * pt) / 72);
	ReleaseDC(hWnd, hDC);
	return height;
};


int PASCAL WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmdLine, int nCmdShow)
{
	// Globals:
	// out:
	//		ghInstance

	int retval;
	HINSTANCE hLib;
	INITCOMMONCONTROLSEX icce;

	// Keep the instance handle. We'll need it later ot load resources.
	ghInstance = hInstance;

	// Initialize common controls. Also needed for MANIFEST's.
	icce.dwSize = sizeof(icce);
	icce.dwICC = ICC_USEREX_CLASSES;
	InitCommonControlsEx(&icce);
	
	// Initialize the OLE library.
	OleInitialize(NULL);
	
	// Load the Rich Edit library.
	hLib = LoadLibrary(_T("Riched32.dll"));

	// The user interface is a modal dialog box.
	retval = DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, (DLGPROC)MainDlgProc);

	// Unload the Rich Edit library.
	FreeLibrary(hLib);

	// Uninitialize the OLE library.
	OleUninitialize();

	// Return.
	return retval;
}


static LRESULT CALLBACK MainDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// Globals:
	// in:
	//		gsFilter
	// in/out:
	//		ghInstance
	//		attempt
	//		constsize
	//		asmmodel
	//		gsCustomFilter
	//		gsInitialDir
	//		gsFilename
	//		gsPathname

	switch ( uMsg )
	{
		case WM_COMMAND:
		{
			// Decide based on the control ID.
			switch ( wParam & 0x0000FFFF )
			{
				case IDC_EDIT2:			// Edit box notify message.
				{
					// Is is a text change?
					if( ((wParam & 0xFFFF0000) >> 16) == EN_UPDATE )
					{
						// Clear the bytecode display.
						SetDlgItemText(hDlg, IDC_EDIT3, NULL);
						
						// Reset the assembly-related global variables.
						attempt = constsize = 0;
						memset(&asmmodel, 0, sizeof(asmmodel));
					};
				};
				break;

				case IDC_BUTTON1:		// Browse for a DLL library...
				{
					gOfn.hInstance = ghInstance;
					gOfn.hwndOwner = hDlg;
					GetDlgItemText(hDlg, IDC_EDIT1, (TCHAR *)&gsFilename, sizeof(gsFilename));
					if( GetOpenFileName(&gOfn) ) {
						SetDlgItemText(hDlg, IDC_EDIT1, (TCHAR *)&gsFilename);
					};
				};
				break;

				case IDC_BUTTON2:		// Assemble the current command.
				{
					// Get the assembly command.
					char sError[TEXTLEN];
					char sHexa[TEXTLEN];	// BOF warning
					char sCommand[TEXTLEN];
					if( GetDlgItemTextA(hDlg, IDC_EDIT2, (char *)&sCommand, sizeof(sCommand)) )
					{
						// Assemble the command.
						if( TryToAssemble((char *)&sCommand, (char *)&sError) )
						{
							// Parse a display string for the bytecode.
							if( ! BytecodeToText((char *)&sHexa) )
							{
								// If the command is not complete, warn so.
								SetDlgItemText(hDlg, IDC_LABEL4,
									_T("Warning: command is not precise!"));
							}
							else
							{
								// If not, show a status message.
								TCHAR sNum[256];	// BOF warning
								sNum[0] = 0;
								wsprintf((TCHAR *)sNum, _T("Attempt %i, const size %i, assembled %i byte(s)."),
									attempt, constsize - 1, asmmodel.length);
								SetDlgItemText(hDlg, IDC_LABEL4, (TCHAR *)&sNum);
							};

							// Show the bytecode to the user.
							SetDlgItemTextA(hDlg, IDC_EDIT3, (char *)&sHexa);
						}
						else
						{
							// Clear the bytecode display.
							SetDlgItemText(hDlg, IDC_EDIT3, NULL);

							// Set the keyboard focus on the second edit box.
							SetFocus(GetDlgItem(hDlg, IDC_EDIT2));

							// Was it a real error, or just no more attempts?
							if( attempt == 0 )
							{
								// Show the error text.
								SetDlgItemTextA(hDlg, IDC_LABEL4, (char *)&sError);
							}
							else
							{
								// No more attempts allowed.
								SetDlgItemText(hDlg, IDC_LABEL4, _T("No more attempts allowed for this command."));

								// Reset the assembly-related global variables.
								attempt = constsize = 0;
								memset(&asmmodel, 0, sizeof(asmmodel));
							};
						};
					}
					else
					{
						// Error: no command was entered.
						SetDlgItemText(hDlg, IDC_LABEL4, _T("Please enter an assembly command..."));
						// Set the keyboard focus on the second edit box.
						SetFocus(GetDlgItem(hDlg, IDC_EDIT2));
					};
				};
				break;

				case IDC_BUTTON3:		// Search for the bytecode.
				{
					// Make sure we have a valid bytecode.
					if( asmmodel.length > 0 )
					{
						// Try to get the file name.
						gsFilename[0] = 0;
						if( ! GetDlgItemText(hDlg, IDC_EDIT1, (TCHAR *)gsFilename, sizeof(gsFilename)) )
						{
							// No filename was entered, browse for one.
							// (Updates the gFilename global string).
							SendMessage(hDlg, WM_COMMAND, IDC_BUTTON1, 0);
						};
						
						// Do we have the filename?
						if( gsFilename[0] != 0 )
						{
							BOOL bOk;
							HLOCAL hMem = NULL;
							
							// Search for the bytecode.
							SetDlgItemText(hDlg, IDC_LABEL4, _T("Searching..."));
							bOk = FindBytecodeInFile(hDlg);
							
							// Parse a status message from the last error value.
							if( FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
								FORMAT_MESSAGE_IGNORE_INSERTS |	FORMAT_MESSAGE_FROM_SYSTEM |
								FORMAT_MESSAGE_MAX_WIDTH_MASK, 0, GetLastError(),
								0, (void *)&hMem, 1, NULL) )
							{
								// Show the status message.
								SetDlgItemText(hDlg, IDC_LABEL4, (TCHAR *)hMem);
								LocalFree(hMem);
							};

							// Set the keyboard focus on the first edit control, or the list box.
							SetFocus(GetDlgItem(hDlg, bOk ? IDC_RICHEDIT1 : IDC_EDIT1));
						}
						else
						{
							// Error: no filename was entered.
							SetDlgItemText(hDlg, IDC_LABEL4, _T("Please enter a filename..."));
							SetFocus(GetDlgItem(hDlg, IDC_EDIT1));
						};
					}
					else
					{
						// Error: no valid bytecode to search.
						SetDlgItemText(hDlg, IDC_LABEL4, _T("Please enter an assembly command..."));
						SetFocus(GetDlgItem(hDlg, IDC_EDIT2));
					};
				};
				break;

				case IDOK:
				{
					// Depends on the currently focused control...
					HWND hCtrl = GetFocus();
					if( hCtrl == GetDlgItem(hDlg, IDC_EDIT1) )
					{
						// Browse for a DLL library.
						SendMessage(hDlg, WM_COMMAND, IDC_BUTTON1, 0);
					}
					else if( hCtrl == GetDlgItem(hDlg, IDC_EDIT2) )
					{
						// Assemble the command.
						SendMessage(hDlg, WM_COMMAND, IDC_BUTTON2, 0);
					}
					else
					{
						// Search for the bytecode.
						SendMessage(hDlg, WM_COMMAND, IDC_BUTTON3, 0);
					};
				};
				break;

				case IDCANCEL:
				{
					// Close the dialog box.
					EndDialog(hDlg, TRUE);
				};
			};
		};
		break;

		case WM_INITDIALOG:
		{
			// Initialize the disassembler.
			ideal			= FALSE;	// Force IDEAL decoding mode
			lowercase		= FALSE;	// Force lowercase display
			tabarguments	= FALSE;	// Tab between mnemonic and arguments
			extraspace		= TRUE;		// Extra space between arguments
			putdefseg		= FALSE;	// Display default segments in listing
			showmemsize		= TRUE;		// Always show memory size
			shownear		= TRUE;		// Show NEAR modifiers
			shortstringcmds	= TRUE;		// Use short form of string commands
			sizesens		= TRUE;		// How to decode size-sensitive mnemonics
			symbolic		= FALSE;	// Show symbolic addresses in disasm
			farcalls		= TRUE;		// Accept far calls, returns & addresses
			decodevxd		= TRUE;		// Decode VxD calls (Win95/98)
			privileged		= TRUE;		// Accept privileged commands
			iocommand		= TRUE;		// Accept I/O commands
			badshift		= TRUE;		// Accept shift out of range 1..31
			extraprefix		= TRUE;		// Accept superfluous prefixes
			lockedbus		= TRUE;		// Accept LOCK prefixes
			stackalign		= TRUE;		// Accept unaligned stack operations
			iswindowsnt		= TRUE;		// When checking for dangers, assume NT

			// Initialize the gsInitialDir variable.
			GetSystemDirectory((TCHAR *)&gsInitialDir, sizeof(gsInitialDir));

			// Set the main dialog's icon.
			SendMessage(hDlg, WM_SETICON, ICON_SMALL,
				(LPARAM)LoadIcon(ghInstance, MAKEINTRESOURCE(IDI_ICON1)));

			// Set the button icons.
			SendDlgItemMessage(hDlg, IDC_BUTTON1, BM_SETIMAGE, IMAGE_ICON,
				(LPARAM)LoadImage(ghInstance, MAKEINTRESOURCE(IDI_ICON2),
				IMAGE_ICON, 0, 0, LR_CREATEDIBSECTION));
			SendDlgItemMessage(hDlg, IDC_BUTTON2, BM_SETIMAGE, IMAGE_ICON,
				(LPARAM)LoadImage(ghInstance, MAKEINTRESOURCE(IDI_ICON3),
				IMAGE_ICON, 0, 0, LR_CREATEDIBSECTION));
			SendDlgItemMessage(hDlg, IDC_BUTTON3, BM_SETIMAGE, IMAGE_ICON,
				(LPARAM)LoadImage(ghInstance, MAKEINTRESOURCE(IDI_ICON4),
				IMAGE_ICON, 0, 0, LR_CREATEDIBSECTION));

			// Set the rich edit font.
			g_lf.lfHeight = CalcFontHeight(9);
			SendDlgItemMessage(hDlg, IDC_RICHEDIT1, WM_SETFONT,
				(WPARAM)CreateFontIndirect(&g_lf), (LPARAM)TRUE);

			// Enable autocomplete for the filename edit box.
			SHAutoComplete(GetDlgItem(hDlg, IDC_EDIT1), SHACF_FILESYSTEM);

			// Set keyboard focus on the first control in tab order.
			return TRUE;
		};

		case WM_DESTROY:
		{
			// Destroy the main window icon.
			DestroyIcon((HICON)SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)NULL));

			// Destroy the button icons.
			DestroyIcon((HICON)SendDlgItemMessage(hDlg, IDC_BUTTON1, BM_SETIMAGE, IMAGE_ICON, (LPARAM)NULL));
			DestroyIcon((HICON)SendDlgItemMessage(hDlg, IDC_BUTTON2, BM_SETIMAGE, IMAGE_ICON, (LPARAM)NULL));
			DestroyIcon((HICON)SendDlgItemMessage(hDlg, IDC_BUTTON3, BM_SETIMAGE, IMAGE_ICON, (LPARAM)NULL));

			// Destroy the rich edit font.
			DeleteObject((HGDIOBJ)SendDlgItemMessage(hDlg, IDC_RICHEDIT1, WM_SETFONT, 0, TRUE));
		};
	}
	return FALSE;
}


/** End of file *************************************************************/
