// lib/models/plugin_manifest.dart

class PluginManifest {
  final String name;
  final String version;
  final String description;
  final String author;
  final String entryPoint;
  final String? uiComponent;
  final List<String> dataTypes;
  final List<String> permissions;
  final Map<String, String> dependencies;

  PluginManifest({
    required this.name,
    required this.version,
    required this.description,
    required this.author,
    required this.entryPoint,
    this.uiComponent,
    required this.dataTypes,
    required this.permissions,
    required this.dependencies,
  });

  factory PluginManifest.fromJson(Map<String, dynamic> json) {
    return PluginManifest(
      name: json['name'] as String,
      version: json['version'] as String,
      description: json['description'] as String,
      author: json['author'] as String,
      entryPoint: json['entryPoint'] as String,
      uiComponent: json['uiComponent'] as String?,
      dataTypes: List<String>.from(json['dataTypes'] ?? []),
      permissions: List<String>.from(json['permissions'] ?? []),
      dependencies: Map<String, String>.from(json['dependencies'] ?? {}),
    );
  }
}