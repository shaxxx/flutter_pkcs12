#include "include/flutter_pkcs12/flutter_pkcs12_plugin.h"


#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <sys/utsname.h>

// #include <cstring>

// #include "include/pkcs12/pkcs12.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include "cstring"

// static void Base64Encode(const unsigned char *buffer,
//                          size_t length,
//                          char **base64Text) {
//     BIO *bio, *b64;
//     BUF_MEM *bufferPtr;
//     b64 = BIO_new(BIO_f_base64());
//     bio = BIO_new(BIO_s_mem());
//     bio = BIO_push(b64, bio);
//     BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
//     BIO_write(bio, buffer, length);
//     BIO_flush(bio);
//     BIO_get_mem_ptr(b64, &bufferPtr);
//     BIO_set_close(bio, BIO_NOCLOSE);
//     BIO_free_all(bio);
//     *base64Text = (char *) calloc(sizeof(char), (*bufferPtr).length + 1);
//     strncpy(*base64Text, (*bufferPtr).data, (*bufferPtr).length);
//     BUF_MEM_free(bufferPtr);
// }

bool getPublicCert(
        const unsigned char *p12Content,
        int p12Size,
        const char *password,
        unsigned char **certResult,
        long *certSize
) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    bool result = false;
    BIO *bio = BIO_new_mem_buf(p12Content, p12Size);
    PKCS12 *p12 = d2i_PKCS12_bio(bio, nullptr);

    EVP_PKEY *pkey = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *ca = nullptr;
    char *name = nullptr;
    char *header = nullptr;
    BIO *bp_public = BIO_new(BIO_s_mem());

    if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (PEM_write_bio_X509(bp_public, cert) <= 0) {
        fprintf(stderr, "Error writing user certificate\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (PEM_read_bio(bp_public, &name, &header, certResult, certSize) <= 0) {
        fprintf(stderr, "Error reading user certificate\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    result = true;
    cleanup:
    if (p12)
        PKCS12_free(p12);
    if (bio)
        BIO_free_all(bio);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (cert)
        X509_free(cert);
    if (ca)
        sk_X509_pop_free(ca, X509_free);
    if (name)
        OPENSSL_free(name);
    if (header)
        OPENSSL_free(header);
    if (bp_public)
        BIO_free_all(bp_public);
    /* http://wiki.openssl.org/index.php/Library_Initialization#Cleanup */
    ENGINE_cleanup();
    CONF_modules_unload(1);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return result;
}

// bool echoPublicCert(const char *p12Content,
//                     int p12Size,
//                     const char *password) {
//     unsigned char *certResult;
//     long certSize;
//     bool result = false;
//     char *base64Text = nullptr;
//     if (!getPublicCert(p12Content, p12Size, password, &certResult, &certSize)) {
//         goto cleanup;
//     }
//     Base64Encode(certResult, certSize, &base64Text);
//     if (base64Text){
//         fprintf(stdout, "%s", base64Text);
//         fprintf(stdout, "%s", "\n");
//         result = true;
//     }
//     cleanup:
//     if (certResult)
//         OPENSSL_free(certResult);
//     if (base64Text)
//         free(base64Text);
//     return result;
// }

// bool getPublicKey(
//         const char *p12Content,
//         int p12Size,
//         const char *password,
//         unsigned char **certResult,
//         long *certSize
// ) {
//     OpenSSL_add_all_algorithms();
//     ERR_load_crypto_strings();
//     bool result = false;
//     BIO *bio = BIO_new_mem_buf(p12Content, p12Size);
//     PKCS12 *p12 = d2i_PKCS12_bio(bio, nullptr);

//     EVP_PKEY *pkey = nullptr;
//     X509 *cert = nullptr;
//     STACK_OF(X509) *ca = nullptr;
//     RSA *rsa = nullptr;
//     char *name = nullptr;
//     char *header = nullptr;
//     BIO *bp_public = BIO_new(BIO_s_mem());

//     if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
//         fprintf(stderr, "Error parsing PKCS#12 file\n");
//         ERR_print_errors_fp(stderr);
//         goto cleanup;
//     }
//     rsa = EVP_PKEY_get1_RSA(pkey);
//     if (PEM_write_bio_RSA_PUBKEY(bp_public, rsa) <= 0) {
//         fprintf(stderr, "Error parsing public key\n");
//         ERR_print_errors_fp(stderr);
//         goto cleanup;
//     }

//     if (PEM_read_bio(bp_public, &name, &header, certResult, certSize) <= 0) {
//         fprintf(stderr, "Error writing public key\n");
//         ERR_print_errors_fp(stderr);
//         goto cleanup;
//     }

//     result = true;
//     cleanup:
//     if (p12)
//         PKCS12_free(p12);
//     if (bio)
//         BIO_free_all(bio);
//     if (pkey)
//         EVP_PKEY_free(pkey);
//     if (cert)
//         X509_free(cert);
//     if (ca)
//         sk_X509_pop_free(ca, X509_free);
//     if (name)
//         OPENSSL_free(name);
//     if (header)
//         OPENSSL_free(header);
//     if (bp_public)
//         BIO_free_all(bp_public);
//     if(rsa)
//         RSA_free(rsa);
//     /* http://wiki.openssl.org/index.php/Library_Initialization#Cleanup */
//     ENGINE_cleanup();
//     CONF_modules_unload(1);
//     EVP_cleanup();
//     CRYPTO_cleanup_all_ex_data();
//     ERR_free_strings();
//     return result;
// }

// bool echoPublicKey(const char *p12Content,
//                    int p12Size,
//                    const char *password) {
//     unsigned char *certResult;
//     long certSize;
//     bool result = false;
//     char *base64Text = nullptr;
//     if (!getPublicKey(p12Content, p12Size, password, &certResult, &certSize)) {
//         goto cleanup;
//     }
//     Base64Encode(certResult, certSize, &base64Text);
//     if (base64Text){
//         fprintf(stdout, "%s", base64Text);
//         fprintf(stdout, "%s", "\n");
//         result = true;
//     }
//     cleanup:
//     if (certResult)
//         OPENSSL_free(certResult);
//     if (base64Text)
//         free(base64Text);
//     return result;
// }


bool RSASign(EVP_PKEY ** priKey,
             const unsigned char *Msg,
             size_t MsgLen,
             unsigned char **EncMsg,
             size_t *MsgLenEnc,
             const evp_md_st *algorithm) {
    EVP_MD_CTX *m_RSASignCtx = EVP_MD_CTX_create();
    //EVP_PKEY *priKey = EVP_PKEY_new();
    //EVP_PKEY_assign_RSA(priKey, rsa);
    bool result = false;
    if (EVP_DigestSignInit(m_RSASignCtx, nullptr, algorithm, nullptr, *priKey) <= 0) {
        fprintf(stderr, "EVP_DigestSignInit failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
        fprintf(stderr, "EVP_DigestSignUpdate failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, nullptr, MsgLenEnc) <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal 1 failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    *EncMsg = (unsigned char *) calloc(*MsgLenEnc, sizeof(char));
    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal 2 failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    result = true;
    cleanup:
    if (m_RSASignCtx) {
        EVP_MD_CTX_free(m_RSASignCtx);
    }
    if (EncMsg && !result) {
        free(EncMsg);
    }
    return result;
}

bool sign(
        const unsigned char *p12Content,
        int p12Size,
        const char *password,
        const unsigned char *data,
        size_t dataSize,
        int algorithm,
        unsigned char **signatureResult,
        size_t *signatureSize
) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    bool result = false;
    BIO *bio = BIO_new_mem_buf(p12Content, p12Size);
    PKCS12 *p12 = d2i_PKCS12_bio(bio, nullptr);
    EVP_PKEY *pkey = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *ca = nullptr;

    const evp_md_st *algorithmType;
    if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    switch (algorithm) {
        case 0:
            algorithmType = EVP_sha1();
            break;
        case 1:
            algorithmType = EVP_sha256();
            break;
        case 2:
            algorithmType = EVP_sha512();
            break;
        default:
            fprintf(stderr, "Unsupported hash type\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
    }
    if (!RSASign(&pkey, data, dataSize, signatureResult, signatureSize, algorithmType)) {
        fprintf(stderr, "RSASign failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    result = true;
    cleanup:
    if (p12)
        PKCS12_free(p12);
    if (bio)
        BIO_free_all(bio);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (cert)
        X509_free(cert);
    if (ca)
        sk_X509_pop_free(ca, X509_free);
    /* http://wiki.openssl.org/index.php/Library_Initialization#Cleanup */
    ENGINE_cleanup();
    CONF_modules_unload(1);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return result;
}

// bool echoSignResult( const unsigned char **p12Content,
//                      int p12Size,
//                      const char *password,
//                      const unsigned char **data,
//                      size_t dataSize,
//                      int algorithm
// ) {
//     unsigned char *signature = nullptr;
//     size_t signatureSize = 0;
//     bool signResult = sign(*p12Content, p12Size, password, *data, dataSize, algorithm, &signature, &signatureSize);
//     /* Remember to free() memory allocated by slurp() */

//     if (signResult){
//         char *base64Text;
//         Base64Encode(signature, signatureSize, &base64Text);
//         fprintf(stdout, "%s", base64Text);
//         free(base64Text);
//     }
//     free(signature);
//     return signResult;
// }


#define FLUTTER_PKCS12_PLUGIN(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), flutter_pkcs12_plugin_get_type(), \
                              FlutterPkcs12Plugin))

struct _FlutterPkcs12Plugin {
  GObject parent_instance;
};

G_DEFINE_TYPE(FlutterPkcs12Plugin, flutter_pkcs12_plugin, g_object_get_type())

// Called when a method call is received from Flutter.
static void flutter_pkcs12_plugin_handle_method_call(
    FlutterPkcs12Plugin* self,
    FlMethodCall* method_call) {
  g_autoptr(FlMethodResponse) response = nullptr;

  const gchar* method = fl_method_call_get_name(method_call);

  if (strcmp(method, "getPlatformVersion") == 0) {
    struct utsname uname_data = {};
    uname(&uname_data);
    g_autofree gchar *version = g_strdup_printf("Linux %s", uname_data.version);
    g_autoptr(FlValue) result = fl_value_new_string(version);
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
  } else if (strcmp(method, "readPublicKey") == 0) {
    FlValue* args = fl_method_call_get_args(method_call);
    FlValue* p12BytesArg = fl_value_lookup_string(args, "p12Bytes");
    FlValue* passwordArg = fl_value_lookup_string(args, "password");

    const uint8_t * p12Bytes = fl_value_get_uint8_list(p12BytesArg);
    int p12Size = (int)fl_value_get_length(p12BytesArg);
    const char* password = fl_value_get_string(passwordArg);   
    g_autofree unsigned char *cert = nullptr;
    long certSize = 0;
    bool certResult = getPublicCert(p12Bytes, p12Size, password, &cert, &certSize);
    if (certResult){
      GBytes* g_certResult = g_bytes_new(cert,certSize);
      g_autoptr(FlValue) result = fl_value_new_uint8_list_from_bytes(g_certResult);
      response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
    } else {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new("CERTIFICATE_ERROR", "FAILURE", nullptr));
    }
  } else if (strcmp(method, "signDataWithP12") == 0) {
    FlValue* args = fl_method_call_get_args(method_call);
    FlValue* p12BytesArg = fl_value_lookup_string(args, "p12Bytes");
    FlValue* passwordArg = fl_value_lookup_string(args, "password");
    FlValue* dataArg = fl_value_lookup_string(args, "data");
    FlValue* signatureHashTypeArg = fl_value_lookup_string(args, "signatureHashType");
    const uint8_t * p12Bytes = fl_value_get_uint8_list(p12BytesArg);
    int p12Size = (int)fl_value_get_length(p12BytesArg);
    const char* password = fl_value_get_string(passwordArg);
    const uint8_t * data = fl_value_get_uint8_list(dataArg);
    int dataSize = (int)fl_value_get_length(dataArg);
    int64_t algorithm = fl_value_get_int(signatureHashTypeArg);
    g_autofree unsigned char *signature = nullptr;
    size_t signatureSize = 0;
    bool signResult = sign(p12Bytes, p12Size, password, data, dataSize, algorithm, &signature, &signatureSize);
    if (signResult){
      GBytes* g_signResult = g_bytes_new(signature,signatureSize);
      g_autoptr(FlValue) result = fl_value_new_uint8_list_from_bytes(g_signResult);
      response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
    } else {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new("CERTIFICATE_ERROR", "FAILURE", nullptr));
    }
  }
  else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }
  fl_method_call_respond(method_call, response, nullptr);
}

static void flutter_pkcs12_plugin_dispose(GObject* object) {
  G_OBJECT_CLASS(flutter_pkcs12_plugin_parent_class)->dispose(object);
}

static void flutter_pkcs12_plugin_class_init(FlutterPkcs12PluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = flutter_pkcs12_plugin_dispose;
}

static void flutter_pkcs12_plugin_init(FlutterPkcs12Plugin* self) {}

static void method_call_cb(FlMethodChannel* channel, FlMethodCall* method_call,
                           gpointer user_data) {
  FlutterPkcs12Plugin* plugin = FLUTTER_PKCS12_PLUGIN(user_data);
  flutter_pkcs12_plugin_handle_method_call(plugin, method_call);
}

void flutter_pkcs12_plugin_register_with_registrar(FlPluginRegistrar* registrar) {
  FlutterPkcs12Plugin* plugin = FLUTTER_PKCS12_PLUGIN(
      g_object_new(flutter_pkcs12_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) channel =
      fl_method_channel_new(fl_plugin_registrar_get_messenger(registrar),
                            "flutter_pkcs12",
                            FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(channel, method_call_cb,
                                            g_object_ref(plugin),
                                            g_object_unref);

  g_object_unref(plugin);
}