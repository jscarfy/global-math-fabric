import 'dart:io';
import 'package:tray_manager/tray_manager.dart';
import 'package:flutter/material.dart';
import 'platform_runner.dart';

class GMFTray with TrayListener {
  static final GMFTray _i = GMFTray._();
  GMFTray._();

  static Future<void> init() async {
    TrayManager.instance.addListener(_i);
    // You should provide platform-specific tray icon files; placeholder name.
    // Put icons under assets/ and register in pubspec.yaml if needed.
    await TrayManager.instance.setIcon(Platform.isWindows ? 'assets/tray/icon.ico' : 'assets/tray/icon.png');
    await TrayManager.instance.setToolTip('Global Math Fabric');
    await TrayManager.instance.setContextMenu(Menu(items: [
      MenuItem(key: 'pause', label: 'Pause Background'),
      MenuItem(key: 'resume', label: 'Resume Background'),
      MenuItem.separator(),
      MenuItem(key: 'exit', label: 'Exit'),
    ]));
  }

  @override
  void onTrayMenuItemClick(MenuItem item) async {
    switch (item.key) {
      case 'pause':
        await PlatformRunner.stopBackground();
        break;
      case 'resume':
        await PlatformRunner.startBackground();
        break;
      case 'exit':
        // Best-effort: stop background then quit
        await PlatformRunner.stopBackground();
        // ignore: use_build_context_synchronously
        TrayManager.instance.destroy();
        break;
    }
  }
}

class GMFTrayStatus {
  static Future<void> set(String s) async {
    try {
      await TrayManager.instance.setToolTip('GMF: $s');
    } catch (_) {}
  }
}
