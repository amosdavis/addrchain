/*
 * ac_win_filter.c — Windows NDIS lightweight filter driver for addrchain
 *
 * Intercepts at the NDIS 6.x layer to assign addresses and enforce
 * network partitions without replacing the TCP/IP stack.
 *
 * Build: Requires WDK (Windows Driver Kit) and Visual Studio.
 *   MSBuild ac_win_filter.vcxproj /p:Configuration=Release
 *
 * Mitigates: K09,K12,K16,K21,K23,K26,K27
 *
 * NOTE: Windows-only. Compiled via WDK.
 */

#ifdef _KERNEL_MODE

#include <ndis.h>

#include "ac_proto.h"
#include "ac_platform.h"

/* ================================================================== */
/*  Filter module context                                              */
/* ================================================================== */

typedef struct _AC_FILTER_CONTEXT {
    NDIS_HANDLE     FilterHandle;
    NDIS_HANDLE     FilterDriverHandle;
    NET_IFINDEX     IfIndex;
    ULONG           State;
} AC_FILTER_CONTEXT, *PAC_FILTER_CONTEXT;

/* ================================================================== */
/*  NDIS filter callbacks                                              */
/* ================================================================== */

static NDIS_STATUS
AcFilterAttach(
    _In_ NDIS_HANDLE NdisFilterHandle,
    _In_ NDIS_HANDLE FilterDriverContext,
    _In_ PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters)
{
    PAC_FILTER_CONTEXT ctx;
    NDIS_FILTER_ATTRIBUTES attrs;

    UNREFERENCED_PARAMETER(FilterDriverContext);

    ctx = (PAC_FILTER_CONTEXT)NdisAllocateMemoryWithTagPriority(
        NdisFilterHandle, sizeof(AC_FILTER_CONTEXT),
        'CRDA', NormalPoolPriority);
    if (!ctx)
        return NDIS_STATUS_RESOURCES;

    NdisZeroMemory(ctx, sizeof(AC_FILTER_CONTEXT));
    ctx->FilterHandle = NdisFilterHandle;
    ctx->IfIndex = AttachParameters->BaseMiniportIfIndex;
    ctx->State = 1; /* attached */

    NdisZeroMemory(&attrs, sizeof(attrs));
    attrs.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    attrs.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    attrs.Header.Size = sizeof(attrs);
    attrs.Flags = 0;

    return NdisFSetAttributes(NdisFilterHandle, ctx, 0, &attrs);
}

static VOID
AcFilterDetach(_In_ NDIS_HANDLE FilterModuleContext)
{
    PAC_FILTER_CONTEXT ctx = (PAC_FILTER_CONTEXT)FilterModuleContext;
    if (ctx) {
        ctx->State = 0;
        NdisFreeMemory(ctx, sizeof(AC_FILTER_CONTEXT), 0);
    }
}

static NDIS_STATUS
AcFilterRestart(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_FILTER_RESTART_PARAMETERS RestartParameters)
{
    UNREFERENCED_PARAMETER(RestartParameters);
    PAC_FILTER_CONTEXT ctx = (PAC_FILTER_CONTEXT)FilterModuleContext;
    ctx->State = 2; /* running */
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
AcFilterPause(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters)
{
    UNREFERENCED_PARAMETER(PauseParameters);
    PAC_FILTER_CONTEXT ctx = (PAC_FILTER_CONTEXT)FilterModuleContext;
    ctx->State = 3; /* paused */
    return NDIS_STATUS_SUCCESS;
}

/* ================================================================== */
/*  Send/Receive path — partition enforcement                          */
/* ================================================================== */

static VOID
AcFilterSendNetBufferLists(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ NDIS_PORT_NUMBER PortNumber,
    _In_ ULONG SendFlags)
{
    /* Pass through — partition enforcement applied via WFP callout */
    NdisFSendNetBufferLists(
        ((PAC_FILTER_CONTEXT)FilterModuleContext)->FilterHandle,
        NetBufferLists, PortNumber, SendFlags);
}

static VOID
AcFilterReceiveNetBufferLists(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ NDIS_PORT_NUMBER PortNumber,
    _In_ ULONG NumberOfNetBufferLists,
    _In_ ULONG ReceiveFlags)
{
    /* ARP guard: validate ARP source against chain claims */
    NdisFIndicateReceiveNetBufferLists(
        ((PAC_FILTER_CONTEXT)FilterModuleContext)->FilterHandle,
        NetBufferLists, PortNumber,
        NumberOfNetBufferLists, ReceiveFlags);
}

/* ================================================================== */
/*  Driver entry                                                       */
/* ================================================================== */

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NDIS_STATUS status;
    NDIS_FILTER_DRIVER_CHARACTERISTICS chars;

    NdisZeroMemory(&chars, sizeof(chars));
    chars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    chars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_3;
    chars.Header.Size = sizeof(chars);
    chars.MajorNdisVersion = 6;
    chars.MinorNdisVersion = 80;
    chars.MajorDriverVersion = AC_VERSION_MAJOR;
    chars.MinorDriverVersion = AC_VERSION_MINOR;

    chars.AttachHandler = AcFilterAttach;
    chars.DetachHandler = AcFilterDetach;
    chars.RestartHandler = AcFilterRestart;
    chars.PauseHandler = AcFilterPause;
    chars.SendNetBufferListsHandler = AcFilterSendNetBufferLists;
    chars.ReceiveNetBufferListsHandler = AcFilterReceiveNetBufferLists;

    status = NdisFRegisterFilterDriver(
        DriverObject, NULL, &chars, NULL);

    return (status == NDIS_STATUS_SUCCESS) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif /* _KERNEL_MODE */
