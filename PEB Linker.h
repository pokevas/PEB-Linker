#pragma once

#include "NT Func.h"
#include <ctime>

struct RB_TREE_EX
{
	RB_TREE_EX * LocalLeft;
	RB_TREE_EX * LocalRight;

	union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	};

	RTL_BALANCED_NODE * ExLeft;
	RTL_BALANCED_NODE * ExRight;
	RTL_BALANCED_NODE * ExAddr;
};

bool CreateLdrEntry(LDR_DATA_TABLE_ENTRY ** ppEntry, HANDLE hTargetProc, PEB_LDR_DATA * ldr, const wchar_t * szDllPath, BYTE * pModBase, DWORD SizeOfImage, BYTE * pEntrypoint, bool bTLS);