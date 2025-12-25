import 'dart:io';
import 'package:flutter_foreground_task/flutter_foreground_task.dart';

class AndroidNotificationPermission {
  static Future<void> ensure() async {
    if (!Platform.isAndroid) return;

    final p = await FlutterForegroundTask.checkNotificationPermission();
    if (p != NotificationPermission.granted) {
      await FlutterForegroundTask.requestNotificationPermission();
    }
  }
}
