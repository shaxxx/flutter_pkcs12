#include "include/flutter_pkcs12/flutter_pkcs12_plugin.h"

// This must be included before many other Windows headers.
#include <windows.h>

// For getPlatformVersion; remove unless needed for your plugin implementation.
#include <VersionHelpers.h>

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <map>
#include <memory>
#include <sstream>

using flutter::EncodableList;
using flutter::EncodableMap;
using flutter::EncodableValue;
using namespace std;

#include <windows.h>

#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <io.h>

#include <vector>
#include <codecvt>
#include <locale>

#pragma comment(lib, "Crypt32")

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64_encode(BYTE const *buf, unsigned int bufLen)
{
  std::string ret;
  int i = 0;
  int j = 0;
  BYTE char_array_3[3];
  BYTE char_array_4[4];

  while (bufLen--)
  {
    char_array_3[i++] = *(buf++);
    if (i == 3)
    {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for (i = 0; (i < 4); i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for (j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while ((i++ < 3))
      ret += '=';
  }

  return ret;
}

// Check if the given certificate has the Certificate Sign key usage
BOOL IsCACert(PCCERT_CONTEXT pContext)
{
  BOOL bStatus = FALSE;
  BYTE bKeyUsage;

  // Look at the key usage of the certificate
  if (CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                              pContext->pCertInfo,
                              &bKeyUsage,
                              1))
  {
    if (bKeyUsage & CERT_KEY_CERT_SIGN_KEY_USAGE)
    {
      bStatus = TRUE;
    }
  }
  return bStatus;
}

BOOL GetPublicCert(
    LPBYTE p12Content,
    DWORD p12Size,
    const WCHAR *password,
    std::vector<BYTE> *certResult)
{
  PCCERT_CONTEXT pCertContext = NULL;
  // Decrypt the content of the PFX file
  CRYPT_DATA_BLOB pfxBlob;
  pfxBlob.cbData = p12Size;
  pfxBlob.pbData = p12Content;
  BOOL result = FALSE;

  HCERTSTORE hPfxStore = PFXImportCertStore(&pfxBlob, password, CRYPT_EXPORTABLE);
  if (!hPfxStore)
  {
    if (!password)
    {
      // Empty password case. Try with empty string as advised by MSDN
      hPfxStore = PFXImportCertStore(&pfxBlob, L"", CRYPT_EXPORTABLE);
    }
    else if (wcslen(password) == 0)
    {
      // Empty password case. Try with NULL as advised by MSDN
      hPfxStore = PFXImportCertStore(&pfxBlob, NULL, CRYPT_EXPORTABLE);
    }
  }
  if (!hPfxStore)
  {
    _tprintf(_T("Failed to decrypt PFX file content. Please check you typed the correct password"));
    goto cleanup;
  }
  while ((pCertContext = CertEnumCertificatesInStore(hPfxStore, pCertContext)) != 0 && !result)
  {
    if (!IsCACert(pCertContext))
    {
      certResult->assign(pCertContext->pbCertEncoded, pCertContext->pbCertEncoded + pCertContext->cbCertEncoded);
      result = true;
    }
  }
cleanup:
  if (hPfxStore)
    CertCloseStore(hPfxStore, CERT_CLOSE_STORE_FORCE_FLAG);
  CertFreeCertificateContext(pCertContext);
  return result;
}

void ReverseBuffer(LPBYTE pbData, DWORD cbData)
{
  DWORD i;
  for (i = 0; i < (cbData / 2); i++)
  {
    BYTE t = pbData[i];
    pbData[i] = pbData[cbData - 1 - i];
    pbData[cbData - 1 - i] = t;
  }
}

BOOL Sign(LPBYTE p12Content,
          DWORD p12Size,
          const WCHAR *password,
          std::vector<BYTE> *data,
          DWORD algorithm,
          std::vector<BYTE> *signResult)
{
  PCCERT_CONTEXT pCertContext = NULL;
  // Decrypt the content of the PFX file
  CRYPT_DATA_BLOB pfxBlob{};
  pfxBlob.cbData = p12Size;
  pfxBlob.pbData = p12Content;
  BOOL result = FALSE;
  DWORD cbSize = 0;
  PCRYPT_KEY_PROV_INFO pKeyInfo = NULL;
  HCERTSTORE hPfxStore = PFXImportCertStore(&pfxBlob, password, CRYPT_EXPORTABLE);
  if (!hPfxStore)
  {
    if (!password)
    {
      // Empty password case. Try with empty string as advised by MSDN
      hPfxStore = PFXImportCertStore(&pfxBlob, L"", CRYPT_EXPORTABLE);
    }
    else if (wcslen(password) == 0)
    {
      // Empty password case. Try with NULL as advised by MSDN
      hPfxStore = PFXImportCertStore(&pfxBlob, NULL, CRYPT_EXPORTABLE);
    }
  }
  if (!hPfxStore)
  {
    _tprintf(_T("Failed to decrypt PFX file content. Please check you typed the correct password"));
    goto cleanup;
  }

  BOOL certFound = FALSE;
  BOOL isError = FALSE;
  while ((pCertContext = CertEnumCertificatesInStore(hPfxStore, pCertContext)) != 0 && !certFound)
  {
    if (!IsCACert(pCertContext))
    {
      certFound = TRUE;
      // Check if it has a private key
      if (CertGetCertificateContextProperty(pCertContext,
                                            CERT_KEY_PROV_INFO_PROP_ID,
                                            NULL,
                                            &cbSize))
      {
        // Get private key components
        pKeyInfo = (PCRYPT_KEY_PROV_INFO)LocalAlloc(0, cbSize);
        if (CertGetCertificateContextProperty(pCertContext,
                                              CERT_KEY_PROV_INFO_PROP_ID,
                                              pKeyInfo,
                                              &cbSize))
        {
          if (pKeyInfo)
          {
            // Acquire a context and export the private key
            HCRYPTPROV hProv = NULL;
            HCRYPTKEY hKey = NULL;
            BOOL bStatus = CryptAcquireContextW(&hProv,
                                                pKeyInfo->pwszContainerName,
                                                NULL,
                                                PROV_RSA_AES,
                                                0);

            if (bStatus)
            {
              bStatus = CryptGetUserKey(hProv, pKeyInfo->dwKeySpec, &hKey);
              if (bStatus)
              {
                HCRYPTHASH hHash = NULL;
                //-------------------------------------------------------------------
                // Create the hash object.
                ALG_ID algo = 255;
                switch (algorithm)
                {
                case 0:
                  algo = CALG_SHA1;
                  break;
                case 1:
                  algo = CALG_SHA_256;
                  break;
                case 2:
                  algo = CALG_SHA_512;
                  break;
                default:
                  printf("Unsupporthed algorithm");
                  isError = TRUE;
                }

                if (!isError)
                {
                  if (CryptCreateHash(
                          hProv,
                          algo,
                          0,
                          0,
                          &hHash))
                  {
                    //printf("Hash object created. \n");
                  }
                  else
                  {
                    printf("Error during CryptCreateHash.");
                    isError = TRUE;
                  }
                }
                //-------------------------------------------------------------------
                // Compute the cryptographic hash of the buffer.

                if (!isError)
                {
                  if (CryptHashData(
                          hHash,
                          data->data(),
                          (DWORD)data->size(),
                          0))
                  {
                    //printf("The data buffer has been hashed.\n");
                  }
                  else
                  {
                    printf("Error during CryptHashData.");
                    isError = TRUE;
                  }
                }

                //--------------------------------------------------------------------
                // Determine the size of the signature and allocate memory.
                BYTE *pbSignature = NULL;
                DWORD dwSigLen;
                LPCWSTR szDescription = nullptr;
                dwSigLen = 0;
                if (!isError)
                {
                  if (CryptSignHash(
                          hHash,
                          pKeyInfo->dwKeySpec,
                          szDescription,
                          0,
                          NULL,
                          &dwSigLen))
                  {
                    //printf("Signature length %d found.\n", dwSigLen);
                  }
                  else
                  {
                    printf("Error during CryptSignHash");
                    isError = TRUE;
                  }
                }
                //--------------------------------------------------------------------
                // Allocate memory for the signature buffer.

                if (!isError)
                {
                  if ((pbSignature = (BYTE *)malloc(dwSigLen)) != 0)
                  {
                    //printf("Memory allocated for the signature.\n");
                  }
                  else
                  {
                    printf("Out of memory\n");
                    isError = TRUE;
                  }
                }
                //--------------------------------------------------------------------
                // Sign the hash object.

                if (!isError)
                {
                  if (CryptSignHash(
                          hHash,
                          pKeyInfo->dwKeySpec,
                          szDescription,
                          0,
                          pbSignature,
                          &dwSigLen))
                  {
                    //printf("pbSignature is the hash signature.\n");
                  }
                  else
                  {
                    printf("Error during CryptSignHash.\n");
                    isError = TRUE;
                  }
                }

                //--------------------------------------------------------------------
                // Destroy the hash object.

                if (hHash)
                  CryptDestroyHash(hHash);

                if (!isError)
                {
                  ReverseBuffer(pbSignature, dwSigLen);
                  signResult->assign(pbSignature, pbSignature + dwSigLen);
                  result = true;
                }
                if (pbSignature)
                  free(pbSignature);
                CryptDestroyKey(hKey);
              }
              CryptReleaseContext(hProv, 0);

              // Delete the key and its container from disk
              // We don't want the key to be persistant
              CryptAcquireContextW(&hProv,
                                   pKeyInfo->pwszContainerName,
                                   pKeyInfo->pwszProvName,
                                   pKeyInfo->dwProvType,
                                   CRYPT_DELETEKEYSET);
            }
          }
        }
        LocalFree(pKeyInfo);
      }
    }
  }
cleanup:
  if (hPfxStore)
    CertCloseStore(hPfxStore, CERT_CLOSE_STORE_FORCE_FLAG);
  CertFreeCertificateContext(pCertContext);
  return result;
}

BOOL EchoSignResult(LPBYTE p12Content,
                    DWORD p12Size,
                    const WCHAR *password,
                    std::vector<BYTE> *data,
                    DWORD algorithm)
{

  std::vector<BYTE> signResult;
  BOOL result = Sign(p12Content, p12Size, password, data, algorithm, &signResult);
  if (result)
  {
    cout << base64_encode(signResult.data(), static_cast<unsigned int>(signResult.size()));
    cout << "\n\n";
  }
  return result;
}

namespace
{

  class FlutterPkcs12Plugin : public flutter::Plugin
  {
  public:
    static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

    FlutterPkcs12Plugin();

    virtual ~FlutterPkcs12Plugin();

  private:
    // Called when a method is called on this plugin's channel from Dart.
    void HandleMethodCall(
        const flutter::MethodCall<flutter::EncodableValue> &method_call,
        std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  };

  // static
  void FlutterPkcs12Plugin::RegisterWithRegistrar(
      flutter::PluginRegistrarWindows *registrar)
  {
    auto channel =
        std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
            registrar->messenger(), "flutter_pkcs12",
            &flutter::StandardMethodCodec::GetInstance());

    auto plugin = std::make_unique<FlutterPkcs12Plugin>();

    channel->SetMethodCallHandler(
        [plugin_pointer = plugin.get()](const auto &call, auto result)
        {
          plugin_pointer->HandleMethodCall(call, std::move(result));
        });

    registrar->AddPlugin(std::move(plugin));
  }

  FlutterPkcs12Plugin::FlutterPkcs12Plugin() {}

  FlutterPkcs12Plugin::~FlutterPkcs12Plugin() {}

  void FlutterPkcs12Plugin::HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result)
  {
    const auto *arguments = std::get_if<EncodableMap>(method_call.arguments());
    if (method_call.method_name().compare("getPlatformVersion") == 0)
    {
      std::ostringstream version_stream;
      version_stream << "Windows ";
      if (IsWindows10OrGreater())
      {
        version_stream << "10+";
      }
      else if (IsWindows8OrGreater())
      {
        version_stream << "8";
      }
      else if (IsWindows7OrGreater())
      {
        version_stream << "7";
      }
      result->Success(flutter::EncodableValue(version_stream.str()));
    }
    else if (method_call.method_name().compare("readPublicKey") == 0)
    {
      std::vector<unsigned char> p12Bytes;
      auto p12Bytes_it = arguments->find(EncodableValue("p12Bytes"));
      if (p12Bytes_it != arguments->end())
      {
        p12Bytes = std::get<std::vector<unsigned char>>(p12Bytes_it->second);
      }

      std::string password;
      auto password_it = arguments->find(EncodableValue("password"));
      if (password_it != arguments->end())
      {
        password = std::get<std::string>(password_it->second);
      }
      int wchars_num = MultiByteToWideChar(CP_UTF8, 0, password.c_str(), -1, NULL, 0);
      wchar_t *password_w = new wchar_t[wchars_num];
      MultiByteToWideChar(CP_UTF8, 0, password.c_str(), -1, password_w, wchars_num);
      std::vector<BYTE> certResult;
      BOOL resultp = GetPublicCert(p12Bytes.data(), (DWORD)p12Bytes.size(), password_w, &certResult);
      SecureZeroMemory(password_w, wchars_num * sizeof(wchar_t));
      delete[] password_w;
      password.clear();
      password.shrink_to_fit();
      p12Bytes.clear();
      p12Bytes.shrink_to_fit();

      if (resultp)
      {
        result->Success(EncodableValue(certResult));
      }
      else
      {
        result->Error("CERTIFICATE_ERROR", "readPublicKey failed", EncodableValue(""));
      }
      certResult.clear();
      certResult.shrink_to_fit();
    }
    else if (method_call.method_name().compare("signDataWithP12") == 0)
    {
      std::vector<unsigned char> p12Bytes;
      auto p12Bytes_it = arguments->find(EncodableValue("p12Bytes"));
      if (p12Bytes_it != arguments->end())
      {
        p12Bytes = std::get<std::vector<unsigned char>>(p12Bytes_it->second);
      }

      std::string password;
      auto password_it = arguments->find(EncodableValue("password"));
      if (password_it != arguments->end())
      {
        password = std::get<std::string>(password_it->second);
      }
      int wchars_num = MultiByteToWideChar(CP_UTF8, 0, password.c_str(), -1, NULL, 0);
      wchar_t *password_w = new wchar_t[wchars_num];
      MultiByteToWideChar(CP_UTF8, 0, password.c_str(), -1, password_w, wchars_num);

      std::vector<unsigned char> data;
      auto data_it = arguments->find(EncodableValue("data"));
      if (data_it != arguments->end())
      {
        data = std::get<std::vector<unsigned char>>(data_it->second);
      }

      std::int32_t signatureHashType = -1;
      auto signatureHashType_it = arguments->find(EncodableValue("signatureHashType"));
      if (signatureHashType_it != arguments->end())
      {
        signatureHashType = std::get<std::int32_t>(signatureHashType_it->second);
      }

      std::vector<BYTE> signResult;
      BOOL resultp = Sign(p12Bytes.data(), (DWORD)p12Bytes.size(), password_w, &data, signatureHashType, &signResult);
      SecureZeroMemory(password_w, wchars_num * sizeof(wchar_t));
      delete[] password_w;
      password.clear();
      password.shrink_to_fit();
      p12Bytes.clear();
      p12Bytes.shrink_to_fit();

      if (resultp)
      {
        result->Success(EncodableValue(signResult));
      }
      else
      {
        result->Error("CERTIFICATE_ERROR", "signDataWithP12 failed", EncodableValue(""));
      }
      signResult.clear();
      signResult.shrink_to_fit();
    }
    else
    {
      result->NotImplemented();
    }
  }

} // namespace

void FlutterPkcs12PluginRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar)
{
  FlutterPkcs12Plugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
