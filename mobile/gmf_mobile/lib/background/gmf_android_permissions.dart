import 'dart:io';
import 'package:permission_handler/permission_handler.dart';

Future<void> gmfRequestAndroidNotificationPermission() async {
  if (!Platform.isAndroid) return;
  // Android 13+ 才需要 runtime notification permission；老版本會直接回傳 granted/denied-ish。
  final status = await Permission.notification.status;
  if (!status.isGranted) {
    await Permission.notification.request();
  }
}
