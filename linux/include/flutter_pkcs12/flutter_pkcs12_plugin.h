#ifndef FLUTTER_PLUGIN_FLUTTER_PKCS12_PLUGIN_H_
#define FLUTTER_PLUGIN_FLUTTER_PKCS12_PLUGIN_H_

#include <flutter_linux/flutter_linux.h>

G_BEGIN_DECLS

#ifdef FLUTTER_PLUGIN_IMPL
#define FLUTTER_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#define FLUTTER_PLUGIN_EXPORT
#endif

typedef struct _FlutterPkcs12Plugin FlutterPkcs12Plugin;
typedef struct {
  GObjectClass parent_class;
} FlutterPkcs12PluginClass;

FLUTTER_PLUGIN_EXPORT GType flutter_pkcs12_plugin_get_type();

FLUTTER_PLUGIN_EXPORT void flutter_pkcs12_plugin_register_with_registrar(
    FlPluginRegistrar* registrar);

G_END_DECLS

#endif  // FLUTTER_PLUGIN_FLUTTER_PKCS12_PLUGIN_H_
