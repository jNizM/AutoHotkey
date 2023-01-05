#include "stdafx.h"
#include "script.h"
#include "globaldata.h"
#include "application.h"
#include "script_func_impl.h"
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


// Enum to specify the type of input
enum class InputType
{
    String,
    File
};


static FResult HashData(InputType atype, StrArg aInput, optl<StrArg> aHmac, optl<int> aAlgorithm, StrRet& aRetVal)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    LPBYTE pbHash = NULL;
    LPBYTE file_buf = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    LPCWSTR AlgId;
    switch (aAlgorithm.value_or(0))
    {
        case 1: AlgId = BCRYPT_MD2_ALGORITHM; break;
        case 2: AlgId = BCRYPT_MD4_ALGORITHM; break;
        case 3: AlgId = BCRYPT_MD5_ALGORITHM; break;
        case 4: AlgId = BCRYPT_SHA1_ALGORITHM; break;
        case 5: AlgId = BCRYPT_SHA256_ALGORITHM; break;
        case 6: AlgId = BCRYPT_SHA384_ALGORITHM; break;
        case 7: AlgId = BCRYPT_SHA512_ALGORITHM; break;
        default:
            AlgId = BCRYPT_SHA1_ALGORITHM;
    }

    ULONG Flags = 0;
    if (aHmac.has_value())
    {
        Flags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
    }

    // open an algorithm handle
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    if (!NT_SUCCESS(Status = BCryptOpenAlgorithmProvider(&hAlgorithm, AlgId, NULL, Flags)))
    {
        goto Cleanup;
    }

    // calculate the length of the hash
    DWORD cbHash = 0;
    DWORD cbData = 0;
    if (!NT_SUCCESS(Status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
    {
        goto Cleanup;
    }

    // allocate the hash buffer on the heap
    pbHash = (LPBYTE)malloc(size_t(cbHash));
    if (NULL == pbHash)
    {
        Status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    // create a hash
    if (aHmac.has_value())
    {
        LPCTSTR Secret = aHmac.value();
        size_t cbSecret = _tcslen(Secret);
        BYTE* pbSecret = new BYTE[cbSecret];
        for (int i = 0; i < cbSecret; i++)
        {
            pbSecret[i] = (BYTE)Secret[i];
        }
        if (!NT_SUCCESS(Status = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, pbSecret, (ULONG)cbSecret, 0)))
        {
            goto Cleanup;
        }
    }
    else
    {
        if (!NT_SUCCESS(Status = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, 0)))
        {
            goto Cleanup;
        }
    }

    // hash some data
    switch (atype)
    {
        case InputType::String:
        {
            size_t cbInput = _tcslen(aInput);
            BYTE* pbInput = new BYTE[cbInput];
            for (int i = 0; i < cbInput; i++)
            {
                pbInput[i] = (BYTE)aInput[i];
            }
            if (!NT_SUCCESS(Status = BCryptHashData(hHash, pbInput, (ULONG)cbInput, 0)))
            {
                goto Cleanup;
            }
            break;
        }
        case InputType::File:
        {
            hFile = CreateFile(aInput, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                Status = ERROR_OPEN_FAILED;
                goto Cleanup;
            }

            file_buf = (LPBYTE)malloc(size_t(1048576)); // 1 MB
            if (!file_buf)
            {
                Status = STATUS_NO_MEMORY;
                goto Cleanup;
            }

            DWORD bytes_read = 0;
            LONG_OPERATION_INIT

            while (true)
            {
                LONG_OPERATION_UPDATE
                // read a chunk of the file
                if (!ReadFile(hFile, file_buf, 1048576, &bytes_read, NULL))
                {
                    break;
                }
                // end of file reached
                if (bytes_read == 0)
                {
                    break;
                }
                // hash the chunk of data
                if (!NT_SUCCESS(Status = BCryptHashData(hHash, file_buf, bytes_read, 0)))
                {
                    goto Cleanup;
                }
            }
            break;
        }
    }

    // close the hash
    if (!NT_SUCCESS(Status = BCryptFinishHash(hHash, pbHash, cbHash, 0)))
    {
        goto Cleanup;
    }

    LPTSTR buf = aRetVal.Alloc(static_cast<size_t>(cbHash) * 2 + 1);
    for (unsigned short i = 0; i < cbHash; i++)
    {
        buf += _stprintf_s(buf, 3, _T("%02X"), pbHash[i]);
    }
    aRetVal.Copy(buf);

    Cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }
    if (file_buf)
    {
        free(file_buf);
    }
    if (pbHash)
    {
        free(pbHash);
    }
    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }
    if (hAlgorithm)
    {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    return Status ? FR_E_WIN32 : OK;
}

bif_impl FResult HashFile(StrArg aText, optl<int> aAlgorithm, StrRet& aRetVal)
{
    return HashData(InputType::File, aText, NULL, aAlgorithm, aRetVal);
}

bif_impl FResult HashString(StrArg aText, optl<StrArg> aHmac, optl<int> aAlgorithm, StrRet& aRetVal)
{
    return HashData(InputType::String, aText, aHmac.value(), aAlgorithm, aRetVal);
}