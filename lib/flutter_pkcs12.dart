import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/services.dart';

class CustomException implements Exception {
  CustomException(this.cause);
  String cause;
}

class NoCertificateException implements Exception {
  NoCertificateException(this.cause);
  String cause;
}

class BadPasswordP12Exception implements Exception {
  BadPasswordP12Exception(this.cause);
  String? cause;
}

class BadFormatP12Exception implements Exception {
  BadFormatP12Exception(this.cause);
  String? cause;
}

class UnknownP12Exception implements Exception {
  UnknownP12Exception(this.cause);
  String? cause;
}

class CertificateResult {
  CertificateResult({this.b64});
  String? b64;
}

class SignWithP12Result {
  SignWithP12Result({this.signature});
  String? signature;
}

class SignResult {
  SignResult({this.signature, this.certificate});

  String? signature;
  String? certificate;
}

enum SignatureHashType {
  PKCS_SHA1,
  PKCS_SHA256,
  PKCS_SHA512,
}

class FlutterPkcs12 {
  static const MethodChannel _channel = const MethodChannel('flutter_pkcs12');

  static Future<String?> get platformVersion async {
    final String? version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }

  Future<SignWithP12Result> signDataWithP12({
    required Uint8List p12Bytes,
    required String password,
    required Uint8List data,
    required SignatureHashType signatureHashType,
  }) async {
    try {
      final Uint8List signatureB64 =
          await (_channel.invokeMethod('signDataWithP12', {
        'p12Bytes': p12Bytes,
        'password': password,
        'data': data,
        'signatureHashType': signatureHashType.index,
      }));
      return SignWithP12Result(signature: base64Encode(signatureB64));
    } catch (e) {
      if (e is PlatformException) {
        switch (e.code) {
          case "BAD_PASSWORD":
            throw BadPasswordP12Exception(e.message);
          case "BAD_CERTIFICATE_FORMAT":
            throw BadFormatP12Exception(e.message);
          case "CERTIFICATE_ERROR":
            throw UnknownP12Exception(e.message);
          default:
            rethrow;
        }
      } else {
        rethrow;
      }
    }
  }

  Future<CertificateResult> readPublicKey({
    required Uint8List p12Bytes,
    required String password,
  }) async {
    try {
      final Uint8List crtB64 = await (_channel.invokeMethod(
          'readPublicKey', {'p12Bytes': p12Bytes, 'password': password}));
      return CertificateResult(b64: base64Encode(crtB64));
    } catch (e) {
      if (e is PlatformException) {
        switch (e.code) {
          case "BAD_PASSWORD":
            throw BadPasswordP12Exception(e.message);
          case "BAD_CERTIFICATE_FORMAT":
            throw BadFormatP12Exception(e.message);
          case "CERTIFICATE_ERROR":
            throw UnknownP12Exception(e.message);
          default:
            rethrow;
        }
      } else {
        rethrow;
      }
    }
  }
}
