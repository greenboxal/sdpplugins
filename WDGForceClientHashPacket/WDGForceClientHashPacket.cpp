#include <stdlib.h>
#include <crtdbg.h>

#ifdef _DEBUG
	#ifndef DBG_NEW
		#define DBG_NEW new ( _NORMAL_BLOCK , __FILE__ , __LINE__ )
		#define new DBG_NEW
	#endif // DEBUG_NEW
#endif  // _DEBUG

#include "WDGForceClientHashPacket.h"

WDGPlugin *g_SelfReference = NULL;

void WDGPlugin::Release()
{
	m_diffdata.clear();
	g_SelfReference = NULL;
	delete this;
}

void WDGPlugin::Free(LPVOID memory)
{
	delete memory;
	memory = NULL;
}

LPWDGPLUGININFO WDGPlugin::GetPluginInfo()
{
	static WDGPLUGININFO wpi = 
	{
		TEXT("Force Send Client Hash Packet"),
		TEXT("Forces the client to send a packet with the client MD5 in all service types."),
		TEXT("[Fix]"),
		TEXT(""),
		TEXT("GreenBox"),
		1,
		0,
		{ 0x8c3478be, 0x6da3, 0x4462, { 0xaf, 0xed, 0x7e, 0x67, 0x39, 0xd2, 0x22, 0x90 } },
		TEXT("")
	};

	return &wpi;
}

INT32 WDGPlugin::Enabled()
{
	return 0;
}

INT32 WDGPlugin::Disabled()
{
	return 0;
}

LPCTSTR WDGPlugin::GetInputValue()
{
	return NULL;
}

DiffData *WDGPlugin::GeneratePatch()
{
	WeeDiffGenPlugin::FINDDATA sFindData = {0};
	CHAR szMsg[256];
	m_diffdata.clear();

	UINT32 uOffset = 0;

	try
	{
		ZeroMemory(&sFindData, sizeof(sFindData));
		sFindData.lpData = "\x83\xEC\x38\xA1\xAB\xAB\xAB\xAB\x33\xC4\x89\x44\x24\x34\x8B\x15\xAB\xAB\xAB\xAB\x33\xC0";
		sFindData.uDataSize = 22;
		sFindData.lpszSection = ".text";
		sFindData.chWildCard = '\xAB';
		sFindData.uMask = WFD_SECTION | WFD_WILDCARD;

		uOffset = m_dgc->Match(&sFindData);
	} 
	catch (LPCSTR lpszMsg)
	{
		sprintf_s(szMsg, 256, "WDGForceClientHashPacket :: Part 1 :: %s", lpszMsg);
		m_dgc->LogMsg(szMsg);
		return NULL;
	}

	try
	{
		ZeroMemory(&sFindData, sizeof(sFindData));
		sFindData.lpData = "\x90\x90\x90\x90\x90\x90";
		sFindData.uDataSize = 6;

		m_dgc->Replace(CBAddDiffData, uOffset + 56, &sFindData);
	} 
	catch (LPCSTR lpszMsg)
	{
		sprintf_s(szMsg, 256, "WDGForceClientHashPacket :: Part 2 :: %s", lpszMsg);
		m_dgc->LogMsg(szMsg);
		return NULL;
	}

	try
	{
		ZeroMemory(&sFindData, sizeof(sFindData));
		sFindData.lpData = "\xC6\x44\x24\x2E\xCF\xC6\x44\x24\x2F\x7E\xC6\x44\x24\x30\xF4\x88\x54\x24\x31\xC6\x44\x24\x32\x49";
		sFindData.uDataSize = 24;
		sFindData.lpszSection = ".text";
		sFindData.chWildCard = '\xAB';
		sFindData.uMask = WFD_SECTION | WFD_WILDCARD;

		uOffset = m_dgc->Match(&sFindData);
	} 
	catch (LPCSTR lpszMsg)
	{
		sprintf_s(szMsg, 256, "WDGForceClientHashPacket :: Part 3 :: %s", lpszMsg);
		m_dgc->LogMsg(szMsg);
		return NULL;
	}

	try
	{
		ZeroMemory(&sFindData, sizeof(sFindData));
		sFindData.lpData = "\xEB";
		sFindData.uDataSize = 1;

		m_dgc->Replace(CBAddDiffData, uOffset + 26, &sFindData);
	} 
	catch (LPCSTR lpszMsg)
	{
		sprintf_s(szMsg, 256, "WDGForceClientHashPacket :: Part 4 :: %s", lpszMsg);
		m_dgc->LogMsg(szMsg);
		return NULL;
	}

	try
	{
		ZeroMemory(&sFindData, sizeof(sFindData));
		sFindData.lpData = "\x33\xC0\x89\x44\x24\x02\x89\x44\x24\x06\x89\x44\x24\x0A\xEB\xAB\x83\xF8\x06";
		sFindData.uDataSize = 19;
		sFindData.lpszSection = ".text";
		sFindData.chWildCard = '\xAB';
		sFindData.uMask = WFD_SECTION | WFD_WILDCARD;

		uOffset = m_dgc->Match(&sFindData);
	} 
	catch (LPCSTR lpszMsg)
	{
		sprintf_s(szMsg, 256, "WDGForceClientHashPacket :: Part 5 :: %s", lpszMsg);
		m_dgc->LogMsg(szMsg);
		return NULL;
	}

	try
	{
		ZeroMemory(&sFindData, sizeof(sFindData));
		sFindData.lpData = "\xEB";
		sFindData.uDataSize = 1;

		m_dgc->Replace(CBAddDiffData, uOffset + 19, &sFindData);
	} 
	catch (LPCSTR lpszMsg)
	{
		sprintf_s(szMsg, 256, "WDGForceClientHashPacket :: Part 6 :: %s", lpszMsg);
		m_dgc->LogMsg(szMsg);
		return NULL;
	}

	return &m_diffdata;
}

DiffData *WDGPlugin::GetDiffData()
{
	if(m_diffdata.size() <= 0)
	{
		return NULL;
	}

	return &m_diffdata;
}

extern "C" __declspec(dllexport) WeeDiffGenPlugin::IWDGPlugin *InitPlugin(LPVOID lpData, USHORT unWeeDiffMajorVersion, USHORT unWeeDiffMinorVersion)
{
#ifndef _DEBUG
	// Enable functions to track down memory leaks.
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

	if(g_SelfReference == NULL)
	{
		g_SelfReference = new WDGPlugin(lpData);
	}

	return g_SelfReference;
}

void WDGPlugin::CBAddDiffData(WeeDiffGenPlugin::LPDIFFDATA lpDiffData)
{
	if(g_SelfReference != NULL)
	{
		g_SelfReference->m_diffdata.push_back(*lpDiffData);
	}
}