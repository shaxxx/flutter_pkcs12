import Flutter
import UIKit
import Foundation
import Security
import CommonCrypto

public class SwiftFlutterPkcs12Plugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "flutter_pkcs12", binaryMessenger: registrar.messenger())
    let instance = SwiftFlutterPkcs12Plugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
      do {
            try executeFunc(call: call, result: result)
        }  catch {
            result(FlutterError(code: "UNKNOWN_ERROR", message: "Unknown exception occured.", details: error.localizedDescription ))
        }
  }

  private func executeFunc(call: FlutterMethodCall, result:FlutterResult) throws {
        let dic = call.arguments as! [String: Any]
        switch call.method {
        case "signDataWithP12":
            let p12Bytes = dic["p12Bytes"] as! FlutterStandardTypedData
            let data = dic["data"] as! FlutterStandardTypedData
            try self.signDataWithP12(p12Bytes.data as NSData, dic["password"] as! NSString, data.data as NSData, result)
        case "readPublicKey":
            let p12Bytes = dic["p12Bytes"] as! FlutterStandardTypedData
            try self.readPublicKey(p12Bytes.data as NSData, dic["password"] as! NSString, result)
        default:
            print("Method not found")
            result(FlutterMethodNotImplemented)
        }
    }

    private func signDataWithP12(_ p12Bytes: NSData, _ password: NSString, _ data: NSData, _ result: FlutterResult) throws {
        let privateKeyResponse = self.getPrivateKey(p12Bytes, password)
        guard privateKeyResponse.error == errSecSuccess else {
            let secError = privateKeyResponse.error
            if secError == errSecAuthFailed {
                result(FlutterError(code: "BAD_PASSWORD", message: "Invalid password", details: nil))
            } else {
                result(FlutterError(code: "FATAL_ERROR", message: "It was not possible to extract the certificate \(secError)", details: nil))
            }
            return
        }
        
        guard let privateKey = privateKeyResponse.privateKey else {
            result(FlutterError(code: "PRIVATE_KEY_ERROR", message: "It was not possible to extract the private key", details: nil))
            return
        }
        let resultSign : RSASigningResult = self.sign(data: data as Data, privateKey: privateKey)
        guard resultSign.error == nil else {
            result(FlutterError(code: "ERROR_SIGN", message: "It was not possible to sign using the private key \(resultSign.error!.description)", details: nil))
            return
        }
        result(resultSign.signedData)
    }

    private func readPublicKey(_ p12Bytes: NSData, _ password: NSString, _ result: FlutterResult) throws {
        let certificateResponse = self.getCertificate(p12Bytes, password)
        guard certificateResponse.error == errSecSuccess else {
            let secError = certificateResponse.error
            if secError == errSecAuthFailed {
                result(FlutterError(code: "BAD_PASSWORD", message: "Invalid password", details: nil))
            } else {
                result(FlutterError(code: "FATAL_ERROR", message: "It was not possible to extract the certificate \(secError)", details: nil))
            }
            return
        }
        guard let certificate = certificateResponse.certificate else {
            result(FlutterError(code: "CERTIFICATE_ERROR", message: "It was not possible to extract the certificate", details: nil))
            return
        }
        let data = SecCertificateCopyData(certificate) as Data
        //let string = (data as Data).base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0))
        result(data)
    }

    private typealias IdentityResult = (identity: SecIdentity?, error: OSStatus)
    private func getIdentity(_ p12Bytes: NSData, _ password: NSString) -> IdentityResult{
        let importPasswordOption:NSDictionary = [ kSecImportExportPassphrase : password]
        var items : CFArray?
        let secError : OSStatus = SecPKCS12Import(p12Bytes,importPasswordOption, &items)
        guard secError == errSecSuccess else {
            return IdentityResult( identity: nil, error: secError )
        }
        let identityDictionaries = items as! [[String: Any]]
        let identity = identityDictionaries[0][kSecImportItemIdentity as String]
            as! SecIdentity
        return IdentityResult(identity: identity, error: errSecSuccess )
    }
    
    private typealias PrivateKeyResult = (privateKey: SecKey?, error: OSStatus)
    private func getPrivateKey(_ p12Bytes:NSData, _ password: NSString ) -> PrivateKeyResult {
        let identityResult = getIdentity(p12Bytes, password)
        guard identityResult.error == errSecSuccess else {
            return PrivateKeyResult(privateKey: nil, error: identityResult.error)
        }
        
        guard let identity = identityResult.identity else {
            return PrivateKeyResult( privateKey: nil, error: errSecBadReq )
        }
        
        var optPrivateKey: SecKey?
        let secError = SecIdentityCopyPrivateKey(identity, &optPrivateKey)
        guard secError == errSecSuccess else {
            return PrivateKeyResult(privateKey: nil, error: secError )
        }
        guard let privateKey = optPrivateKey else {
            return PrivateKeyResult(privateKey: nil, error: errSecBadReq )
        }
        return PrivateKeyResult(privateKey: privateKey, error: errSecSuccess )
    }
    
    private typealias CertificateResult = (certificate: SecCertificate?, error: OSStatus)
    private func getCertificate(_ p12Bytes: NSData, _ password: NSString) -> CertificateResult {
        let identityResult = getIdentity(p12Bytes, password)
        guard identityResult.error == errSecSuccess else {
            return CertificateResult(certificate: nil, error: identityResult.error)
        }
        
        guard let identity = identityResult.identity else {
            return CertificateResult( certificate: nil, error: errSecBadReq )
        }
        
        var optCertificateRef : SecCertificate?
        let secError = SecIdentityCopyCertificate(identity, &optCertificateRef)
        guard secError == errSecSuccess else {
            return CertificateResult( certificate : nil, error: secError )
        }
        
        guard let certificate = optCertificateRef else {
            return CertificateResult( certificate : nil,  error: errSecBadReq )
        }
        
        return CertificateResult( certificate : certificate, error: errSecSuccess)
    }

    private typealias RSASigningResult = (signedData: Data?, error: NSError?)
    private func sign(data plainData: Data, privateKey: SecKey!) -> RSASigningResult {
        // Then sign it
        let dataToSign = [UInt8](plainData)
        var signatureLen = SecKeyGetBlockSize(privateKey)
        var signature = [UInt8](repeating: 0, count: SecKeyGetBlockSize(privateKey))
        var hash: [UInt8] = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(dataToSign, CC_LONG(plainData.count), &hash)
        let err: OSStatus = SecKeyRawSign(privateKey,
                                          SecPadding.PKCS1SHA1,
                                          hash,
                                          hash.count,
                                          &signature, &signatureLen)
        
        if err == errSecSuccess {
            return (signedData: Data(_: signature), error: nil)
        }
        
        return (signedData: nil, error: NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: nil))
        
    }
}
