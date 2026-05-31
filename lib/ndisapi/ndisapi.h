/*************************************************************************/
/*                    Copyright (c) 2000-2024 NT KERNEL.                 */
/*                           All Rights Reserved.                        */
/*                          https://www.ntkernel.com                     */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Vendored C API subset of ndisapi.h — pure C, no C++ class wrapper.   */
/* Links against ndisapi.dll at runtime.                                 */
/*************************************************************************/
#ifndef WINTPROXY_NDISAPI_H
#define WINTPROXY_NDISAPI_H

/* Ensure Windows types are available before Common.h */
#include <windows.h>
#include <ws2tcpip.h>

#include "Common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* === Driver management === */
HANDLE  __stdcall OpenFilterDriver(const wchar_t* pszFileName);
VOID    __stdcall CloseFilterDriver(HANDLE hOpen);
DWORD   __stdcall GetDriverVersion(HANDLE hOpen);
BOOL    __stdcall IsDriverLoaded(HANDLE hOpen);

/* === Adapter enumeration === */
BOOL    __stdcall GetTcpipBoundAdaptersInfo(HANDLE hOpen, PTCP_AdapterList pAdapters);

/* === Adapter mode and event control === */
BOOL    __stdcall SetAdapterMode(HANDLE hOpen, PADAPTER_MODE pMode);
BOOL    __stdcall GetAdapterMode(HANDLE hOpen, PADAPTER_MODE pMode);
BOOL    __stdcall SetPacketEvent(HANDLE hOpen, HANDLE hAdapter, HANDLE hWin32Event);
BOOL    __stdcall SetWANEvent(HANDLE hOpen, HANDLE hWin32Event);
BOOL    __stdcall SetAdapterListChangeEvent(HANDLE hOpen, HANDLE hWin32Event);
BOOL    __stdcall FlushAdapterPacketQueue(HANDLE hOpen, HANDLE hAdapter);
BOOL    __stdcall GetAdapterPacketQueueSize(HANDLE hOpen, HANDLE hAdapter, PDWORD pdwSize);

/* === Single-packet I/O (not used; unsorted batch API preferred) === */
BOOL    __stdcall SendPacketToMstcp(HANDLE hOpen, PETH_REQUEST pPacket);
BOOL    __stdcall SendPacketToAdapter(HANDLE hOpen, PETH_REQUEST pPacket);
BOOL    __stdcall ReadPacket(HANDLE hOpen, PETH_REQUEST pPacket);

/* === Batch I/O === */
BOOL    __stdcall SendPacketsToMstcp(HANDLE hOpen, PETH_M_REQUEST pPackets);
BOOL    __stdcall SendPacketsToAdapter(HANDLE hOpen, PETH_M_REQUEST pPackets);
BOOL    __stdcall ReadPackets(HANDLE hOpen, PETH_M_REQUEST pPackets);

/* === Unsorted batch I/O (primary API used by WinTProxy) === */
BOOL    __stdcall ReadPacketsUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets,
                                       DWORD dwPacketsNum, PDWORD pdwPacketsSuccess);
BOOL    __stdcall SendPacketsToAdaptersUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets,
                                                 DWORD dwPacketsNum, PDWORD pdwPacketSuccess);
BOOL    __stdcall SendPacketsToMstcpUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets,
                                              DWORD dwPacketsNum, PDWORD pdwPacketSuccess);

/* === Buffer pool === */
BOOL    __stdcall GetIntermediateBufferPoolSize(HANDLE hOpen, PDWORD pdwSize);
BOOL    __stdcall InitializeFastIo(HANDLE hOpen, PFAST_IO_SECTION pFastIo, DWORD dwSize);
BOOL    __stdcall AddSecondaryFastIo(HANDLE hOpen, PFAST_IO_SECTION pFastIo, DWORD dwSize);
BOOL    __stdcall SetPoolSize(DWORD dwPoolSize);
DWORD   __stdcall GetPoolSize(void);

/* === Misc === */
DWORD   __stdcall GetBytesReturned(HANDLE hOpen);
BOOL    __stdcall SetMTUDecrement(DWORD dwMTUDecrement);
DWORD   __stdcall GetMTUDecrement(void);
BOOL    __stdcall SetAdaptersStartupMode(DWORD dwStartupMode);
DWORD   __stdcall GetAdaptersStartupMode(void);
BOOL    __stdcall NdisrdRequest(HANDLE hOpen, PPACKET_OID_DATA OidData, BOOL Set);
BOOL    __stdcall GetRasLinks(HANDLE hOpen, HANDLE hAdapter, PRAS_LINKS pLinks);

/* === Static filter table (not used by WinTProxy; classification is user-mode) === */
BOOL    __stdcall SetPacketFilterTable(HANDLE hOpen, PSTATIC_FILTER_TABLE pFilterList);
BOOL    __stdcall ResetPacketFilterTable(HANDLE hOpen);

/* === Adapter name conversion === */
BOOL    __stdcall ConvertWindows2000AdapterName(LPCSTR szAdapterName, LPSTR szUserFriendlyName, DWORD len);

/* === Checksum helpers === */
void    __stdcall RecalculateIPChecksum(PINTERMEDIATE_BUFFER pPacket);
void    __stdcall RecalculateTCPChecksum(PINTERMEDIATE_BUFFER pPacket);
void    __stdcall RecalculateUDPChecksum(PINTERMEDIATE_BUFFER pPacket);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_NDISAPI_H */
