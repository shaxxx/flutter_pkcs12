#import "FlutterPkcs12Plugin.h"
#if __has_include(<flutter_pkcs12/flutter_pkcs12-Swift.h>)
#import <flutter_pkcs12/flutter_pkcs12-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "flutter_pkcs12-Swift.h"
#endif

@implementation FlutterPkcs12Plugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftFlutterPkcs12Plugin registerWithRegistrar:registrar];
}
@end
