import 'dart:convert';
import 'package:flutter/services.dart';

class PluginManifest {
  final String name;
  final String version;
  final String description;
  final String author;
  final String entryPoint; // e.g., "main.js"
  final String? uiComponent; // e.g., "LedgerUI.js"
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
      dataTypes: List<String>.from(json['dataTypes'] as List),
      permissions: List<String>.from(json['permissions'] as List),
      dependencies: Map<String, String>.from(json['dependencies'] as Map),
    );
  }

  static Future<PluginManifest> fromIpfs(String pluginCid) async {
    // In a real app, this would fetch from IPFS
    // For now, simulate with asset bundle
    final manifestStr = await rootBundle.loadString('assets/mock_manifest.json');
    final json = jsonDecode(manifestStr) as Map<String, dynamic>;
    return PluginManifest.fromJson(json);
  }
}