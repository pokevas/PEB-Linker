#include "PEB Linker.h"
#include <iostream>

bool AppendToList(HANDLE hTargetProc, LIST_ENTRY * head, LIST_ENTRY * entry);
void GenerateLocalRbTree(HANDLE hTargetProc, RB_TREE_EX * node);
void CopyLocalRbTree(HANDLE hTargetProc, RB_TREE_EX * node);
bool LinkToRbTree(HANDLE hTargetProc, RB_TREE_EX * pHead, RTL_BALANCED_NODE * pEntry);

bool CreateLdrEntry(LDR_DATA_TABLE_ENTRY ** ppEntry, HANDLE hTargetProc, PEB_LDR_DATA * ldr, const wchar_t * szDllPath, BYTE * pModBase, DWORD SizeOfImage, BYTE * pEntrypoint, bool bTLS)
{
	if (!ppEntry || !hTargetProc || !ldr || !szDllPath || !pModBase || !SizeOfImage || !pEntrypoint)
	{
		return false;
	}

	BYTE * pAllocBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pAllocBase)
	{
		return nullptr;
	}

	int full_len = lstrlenW(szDllPath);
	auto pName = szDllPath + full_len;
	int base_len = 0;
	while (*(pName-- - 1) != '\\')
	{
		++base_len;
	}

	LDR_DATA_TABLE_ENTRY	* pEntry	= reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(pAllocBase);
	LDR_DDAG_NODE			* pDdagNode = reinterpret_cast<LDR_DDAG_NODE*>(pAllocBase + 0x200);
	wchar_t					* pFullName = reinterpret_cast<wchar_t*>(pAllocBase + 0x300);
	wchar_t					* pBaseName = pFullName + full_len - base_len;

	time_t t;
	time(&t);

	LDR_DATA_TABLE_ENTRY entry{ 0 };
	entry.DllBase		= pModBase;
	entry.OriginalBase	= reinterpret_cast<ULONG_PTR>(pModBase);
	entry.EntryPoint	= pEntrypoint;
	entry.SizeOfImage	= SizeOfImage;
	entry.Flags			= 0x000C22CC; //should work for most dlls
	entry.ObsoleteLoadCount = 6;
	entry.LoadTime.QuadPart = 10000000 * (11644473600 + t);
	entry.TlsIndex			= bTLS ? 0xFFFF : 0x0000; //
	entry.LoadReason		= 4;
	entry.ReferenceCount	= 1;
	
	entry.BaseDllName.Length	= base_len * 2;
	entry.BaseDllName.MaxLength = base_len * 2 + 2;
	entry.BaseDllName.szBuffer  = const_cast<wchar_t*>(szDllPath) + full_len - base_len;
	NT::RtlHashUnicodeString(&entry.BaseDllName, TRUE, 0, &entry.BaseNameHashValue); //epic
	entry.BaseDllName.szBuffer = pBaseName;
	
	entry.FullDllName.Length	= full_len * 2;
	entry.FullDllName.MaxLength = full_len * 2 + 2;
	entry.FullDllName.szBuffer	= pFullName;
	
	entry.DdagNode = pDdagNode;
	entry.NodeModuleLink.Flink = reinterpret_cast<LIST_ENTRY*>(pDdagNode);
	entry.NodeModuleLink.Blink = reinterpret_cast<LIST_ENTRY*>(pDdagNode);

	LDR_DDAG_NODE node{ 0 };
	node.Modules.Flink = reinterpret_cast<LIST_ENTRY*>(ADDRESS_OF(pEntry, NodeModuleLink));
	node.Modules.Blink = reinterpret_cast<LIST_ENTRY*>(ADDRESS_OF(pEntry, NodeModuleLink));
	node.LoadCount		= 1;
	node.LowestLink		= 1;
	node.State			= LDR_DDAG_STATE::LdrModulesReadyToRun;
	node.PreorderNumber = 1;

	WriteProcessMemory(hTargetProc, pEntry, &entry, sizeof(entry), nullptr);
	WriteProcessMemory(hTargetProc, pDdagNode, &node, sizeof(node), nullptr);
	WriteProcessMemory(hTargetProc, pFullName, szDllPath, (size_t)full_len * 2, nullptr);
	
	AppendToList(hTargetProc, ADDRESS_OF(ldr, InLoadOrderModuleListHead),			ADDRESS_OF(pEntry, InLoadOrderLinks));
	AppendToList(hTargetProc, ADDRESS_OF(ldr, InMemoryOrderModuleListHead),			ADDRESS_OF(pEntry, InMemoryOrderLinks));
	AppendToList(hTargetProc, ADDRESS_OF(ldr, InInitializationOrderModuleListHead),	ADDRESS_OF(pEntry, InInitializationOrderLinks));

	LIST_ENTRY * _LdrpHashTable = (LIST_ENTRY*)((BYTE*)GetModuleHandleA("ntdll.dll") + 0x165040);
	LIST_ENTRY * p_hash_table_head = _LdrpHashTable + (entry.BaseNameHashValue & 0x1F);
	AppendToList(hTargetProc, p_hash_table_head, ADDRESS_OF(pEntry, HashLinks));

	RB_TREE_EX * LdrpModuleBaseAddressIndex	= (RB_TREE_EX *)((BYTE*)GetModuleHandleA("ntdll.dll") + 0x1662C8);
	RB_TREE_EX * LdrpMappingInfoIndex		= (RB_TREE_EX *)((BYTE*)GetModuleHandleA("ntdll.dll") + 0x1662D8);
	RTL_BALANCED_NODE * pBaseAddressIndexNode		= ADDRESS_OF(pEntry, BaseAddressIndexNode);
	RTL_BALANCED_NODE * pMappingInfoIndexNode		= ADDRESS_OF(pEntry, MappingInfoIndexNode);

	LinkToRbTree(hTargetProc, LdrpModuleBaseAddressIndex, pBaseAddressIndexNode);
	LinkToRbTree(hTargetProc, LdrpMappingInfoIndex, pMappingInfoIndexNode);

	*ppEntry = pEntry;

	return true;
}

bool AppendToList(HANDLE hTargetProc, LIST_ENTRY * head, LIST_ENTRY * entry)
{
	LIST_ENTRY Head;
	LIST_ENTRY Curr;
	LIST_ENTRY Prev;
	
	if (!ReadProcessMemory(hTargetProc, head, &Head, sizeof(LIST_ENTRY), nullptr))
	{
		return false;
	}

	if (!ReadProcessMemory(hTargetProc, Head.Blink, &Prev, sizeof(LIST_ENTRY), nullptr))
	{
		return false;
	}

	Curr.Blink = Head.Blink;
	Curr.Flink = head;
	Head.Blink = entry;
	Prev.Flink = entry;

	BOOL bRet = WriteProcessMemory(hTargetProc, entry, &Curr, sizeof(LIST_ENTRY), nullptr);
	bRet &= WriteProcessMemory(hTargetProc, Curr.Blink, &Prev, sizeof(LIST_ENTRY), nullptr);
	bRet &= WriteProcessMemory(hTargetProc, head, &Head, sizeof(LIST_ENTRY), nullptr);

	return (bRet != FALSE);
}

void GenerateLocalRbTree(HANDLE hTargetProc, RB_TREE_EX * node)
{
	if (node->ExLeft)
	{
		node->LocalLeft = new RB_TREE_EX(); //currently doesnt get deallocated
		node->LocalLeft->ExAddr = node->ExLeft;

		RTL_BALANCED_NODE b;
		ReadProcessMemory(hTargetProc, node->ExLeft, &b, sizeof(RTL_BALANCED_NODE), nullptr);
		node->LocalLeft->ExLeft		= b.Left;
		node->LocalLeft->ExRight	= b.Right;
		node->Red					= b.Red;

		GenerateLocalRbTree(hTargetProc, node->LocalLeft);
	}

	if (node->ExRight)
	{
		node->LocalRight = new RB_TREE_EX(); //currently doesnt get deallocated
		node->LocalRight->ExAddr = node->ExRight;

		RTL_BALANCED_NODE b;
		ReadProcessMemory(hTargetProc, node->ExRight, &b, sizeof(RTL_BALANCED_NODE), nullptr);
		node->LocalRight->ExRight	= b.Right;
		node->LocalRight->ExRight	= b.Right;
		node->Red					= b.Red;

		GenerateLocalRbTree(hTargetProc, node->LocalRight);
	}
}

void CopyLocalRbTree(HANDLE hTargetProc, RB_TREE_EX * node)
{
	if (!node->ExAddr)
	{
		return;
	}

	RTL_BALANCED_NODE to_write{ 0 };
	to_write.ParentValue = node->ParentValue;

	if (node->LocalLeft)
	{
		to_write.Left = node->LocalLeft->ExAddr;

		CopyLocalRbTree(hTargetProc, node->LocalLeft);
	}

	if (node->LocalRight)
	{
		to_write.Right = node->LocalRight->ExAddr;

		CopyLocalRbTree(hTargetProc, node->LocalRight);
	}

	WriteProcessMemory(hTargetProc, node->ExAddr, &to_write, sizeof(RTL_BALANCED_NODE), nullptr);
}

bool LinkToRbTree(HANDLE hTargetProc, RB_TREE_EX * pHead, RTL_BALANCED_NODE * pEntry)
{
	LIST_ENTRY head;
	ReadProcessMemory(hTargetProc, pHead, &head, sizeof(head), nullptr);

	RB_TREE_EX local_head{ 0 };
	local_head.ExLeft	= (RTL_BALANCED_NODE*)head.Flink;
	local_head.ExRight	= (RTL_BALANCED_NODE*)head.Blink;
	local_head.ExAddr	= (RTL_BALANCED_NODE*)pHead;

	RB_TREE_EX local_entry{ 0 };

	GenerateLocalRbTree(hTargetProc, &local_head);
	NT::RtlRbInsertNodeEx((LIST_ENTRY*)&local_head, nullptr, TRUE, (RTL_BALANCED_NODE*)&local_entry);

	if (local_entry.LocalLeft)
	{
		local_entry.ExLeft = local_entry.LocalLeft->ExAddr;
	}

	if (local_entry.LocalRight)
	{
		local_entry.ExRight = local_entry.LocalRight->ExAddr;
	}

	local_entry.ExAddr = pEntry;

	CopyLocalRbTree(hTargetProc, &local_head);
	
	return 0;
}