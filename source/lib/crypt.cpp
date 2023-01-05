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


static FResult HashData(InputType aType, StrArg aInput, optl<StrArg> aAlgorithm, optl<StrArg> aHmac, StrRet& aRetVal)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    LPBYTE pbHash = NULL;
    LPBYTE file_buf = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    LPCWSTR AlgId;
    LPCTSTR algorithm = aAlgorithm.value_or_empty();
    if (!_tcsicmp(algorithm, _T("MD2")))
    {
        AlgId = BCRYPT_MD2_ALGORITHM;
    }
    else if (!_tcsicmp(algorithm, _T("MD4")))
    {
        AlgId = BCRYPT_MD4_ALGORITHM;
    }
    else if (!_tcsicmp(algorithm, _T("MD5")))
    {
        AlgId = BCRYPT_MD5_ALGORITHM;
    }
    else if (!_tcsicmp(algorithm, _T("SHA1")))
    {
        AlgId = BCRYPT_SHA1_ALGORITHM;
    }
    else if (!_tcsicmp(algorithm, _T("SHA256")))
    {
        AlgId = BCRYPT_SHA256_ALGORITHM;
    }
    else if (!_tcsicmp(algorithm, _T("SHA384")))
    {
        AlgId = BCRYPT_SHA384_ALGORITHM;
    }
    else if (!_tcsicmp(algorithm, _T("SHA512")))
    {
        AlgId = BCRYPT_SHA512_ALGORITHM;
    }
    else // default
    {
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
        CStringA utf8_secret;
        LPCTSTR Secret = aHmac.value();
        size_t secret_len = _tcslen(Secret);
        StringTCharToUTF8(Secret, utf8_secret, (INT)secret_len);

        BYTE* pbSecret = new BYTE[utf8_secret.GetLength() * 2];
        for (int i = 0; i < utf8_secret.GetLength(); i++)
        {
            pbSecret[i] = (BYTE)utf8_secret.GetString()[i];
        }

        if (!NT_SUCCESS(Status = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, pbSecret, (ULONG)(utf8_secret.GetLength()), 0)))
        {
            delete[] pbSecret;
            goto Cleanup;
        }
        delete[] pbSecret;
    }
    else
    {
        if (!NT_SUCCESS(Status = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, 0)))
        {
            goto Cleanup;
        }
    }

    // hash some data
    switch (aType)
    {
        case InputType::String:
        {
            CStringA utf8_input;
            size_t input_len = _tcslen(aInput);
            StringTCharToUTF8(aInput, utf8_input, (INT)input_len);

            BYTE* pbInput = new BYTE[utf8_input.GetLength() * 2];
            for (int i = 0; i < utf8_input.GetLength(); i++)
            {
                pbInput[i] = (BYTE)utf8_input.GetString()[i];
            }

            if (!NT_SUCCESS(Status = BCryptHashData(hHash, pbInput, (ULONG)(utf8_input.GetLength()), 0)))
            {
                delete[] pbInput;
                goto Cleanup;
            }

            delete[] pbInput;
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

bif_impl FResult HashFile(StrArg aText, optl<StrArg> aAlgorithm, StrRet& aRetVal)
{
    return HashData(InputType::File, aText, aAlgorithm.value_or_empty(), NULL, aRetVal);
}

bif_impl FResult HashString(StrArg aText, optl<StrArg> aAlgorithm, optl<StrArg> aHmac, StrRet& aRetVal)
{
    return HashData(InputType::String, aText, aAlgorithm.value_or_empty(), aHmac.value(), aRetVal);
}