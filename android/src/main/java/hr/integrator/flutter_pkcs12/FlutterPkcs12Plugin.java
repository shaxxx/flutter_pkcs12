package hr.integrator.flutter_pkcs12;

import androidx.annotation.NonNull;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * FlutterPkcs12Plugin
 */
public class FlutterPkcs12Plugin implements FlutterPlugin, MethodCallHandler {
    @Override
    public void onAttachedToEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {
        final MethodChannel channel = new MethodChannel(flutterPluginBinding.getFlutterEngine().getDartExecutor(), "flutter_pkcs12");
        channel.setMethodCallHandler(new FlutterPkcs12Plugin());
    }

    // This static function is optional and equivalent to onAttachedToEngine. It supports the old
    // pre-Flutter-1.12 Android projects. You are encouraged to continue supporting
    // plugin registration via this function while apps migrate to use the new Android APIs
    // post-flutter-1.12 via https://flutter.dev/go/android-project-migration.
    //
    // It is encouraged to share logic between onAttachedToEngine and registerWith to keep
    // them functionally equivalent. Only one of onAttachedToEngine or registerWith will be called
    // depending on the user's project. onAttachedToEngine or registerWith must both be defined
    // in the same class.
    public static void registerWith(Registrar registrar) {
        final MethodChannel channel = new MethodChannel(registrar.messenger(), "flutter_pkcs12");
        channel.setMethodCallHandler(new FlutterPkcs12Plugin());
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
        if (call.method.equals("getPlatformVersion")) {
            result.success("Android " + android.os.Build.VERSION.RELEASE);
        } else if (call.method.equals("signDataWithP12")) {
            byte[] p12Bytes = call.argument("p12Bytes");
            String password = call.argument("password");
            byte[] dataToSign = call.argument("data");
            java.lang.Integer signatureHashType = call.argument("signatureHashType");
            SignDataWithP12(result, p12Bytes, password, dataToSign, SignatureHashType.values()[signatureHashType]);
        } else if (call.method.equals("readPublicKey")) {
            try {
                byte[] p12Bytes = call.argument("p12Bytes");
                String password = call.argument("password");
                byte[] publicKey = ReadPublicKey(p12Bytes, password);
                result.success(publicKey);
            } catch (EOFException ex) {
                result.error("BAD_CERTIFICATE_FORMAT", ex.getMessage(), null);
            } catch (IOException ex) {
                result.error("BAD_PASSWORD", ex.getMessage(), null);
            } catch (java.lang.Exception ex) {
                result.error("CERTIFICATE_ERROR", ex.getMessage(), null);
            }
        } else {
            result.notImplemented();
        }
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
    }

    class NoCertificateException extends Exception {
        NoCertificateException(String message) {
            super(message);
        }
    }

    private void SignDataWithP12(MethodChannel.Result result, byte[] p12Bytes, String password,
                                 byte[] data, SignatureHashType signatureHashType) {
        try {
            KeyStore.PrivateKeyEntry pk = getPrivateKey(p12Bytes, password);
            result.success(SignWithPrivateKey(pk.getPrivateKey(), data, signatureHashType));
        } catch (EOFException ex) {
            result.error("BAD_CERTIFICATE_FORMAT", ex.getMessage(), null);
        } catch (IOException ex) {
            result.error("BAD_PASSWORD", ex.getMessage(), null);
        } catch (java.lang.Exception ex) {
            result.error("CERTIFICATE_ERROR", ex.getMessage(), null);
        }
    }

    private byte[] SignWithPrivateKey(PrivateKey pk, byte[] data, SignatureHashType signatureHashType) throws
            InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        Signature sig = null;
        switch (signatureHashType) {
            case PKCS_SHA1:
                sig = Signature.getInstance("SHA1WithRSA");
                break;
            case PKCS_SHA256:
                sig = Signature.getInstance("SHA256withRSA");
                break;
            case PKCS_SHA512:
                sig = Signature.getInstance("SHA512withRSA");
                break;
        }
        sig.initSign(pk);
        sig.update(data);
        return sig.sign();
    }

    byte[] ReadPublicKey(byte[] p12Bytes, String password) throws
            KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore p12 = getP12(p12Bytes, password);
        Enumeration<String> e = p12.aliases();
        String alias = e.nextElement();
        X509Certificate c = (X509Certificate) p12.getCertificate(alias);
        return c.getEncoded();
    }

    private KeyStore.PrivateKeyEntry getPrivateKey(byte[] p12Bytes, String password) throws
            KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        KeyStore p12 = getP12(p12Bytes, password);
        Enumeration<String> e = p12.aliases();
        String alias = e.nextElement();
        return (KeyStore.PrivateKeyEntry) p12.getEntry(alias, new KeyStore.PasswordProtection("".toCharArray()));
    }

    private KeyStore getP12(byte[] p12Bytes, String password) throws
            KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new ByteArrayInputStream(p12Bytes), password.toCharArray());
        return p12;
    }

    enum SignatureHashType {
        PKCS_SHA1,
        PKCS_SHA256,
        PKCS_SHA512,
    }
}