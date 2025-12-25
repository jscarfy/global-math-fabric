import 'dart:io';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

class StatusNotify {
  static final FlutterLocalNotificationsPlugin _p = FlutterLocalNotificationsPlugin();
  static bool _inited = false;

  static Future<void> init() async {
    if (_inited) return;
    _inited = true;

    // Desktop 通常不需要系统通知；Android/iOS 需要初始化
    if (!(Platform.isAndroid || Platform.isIOS)) return;

    const android = AndroidInitializationSettings('@mipmap/ic_launcher');
    const ios = DarwinInitializationSettings();
    const init = InitializationSettings(android: android, iOS: ios);
    await _p.initialize(init);
  }

  static Future<void> info(String title, String body) async {
    await init();
    if (!(Platform.isAndroid || Platform.isIOS)) return;

    const androidDetails = AndroidNotificationDetails(
      'gmf_status',
      'GMF Status',
      channelDescription: 'Global Math Fabric runtime status',
      importance: Importance.low,
      priority: Priority.low,
    );
    const iosDetails = DarwinNotificationDetails();
    const details = NotificationDetails(android: androidDetails, iOS: iosDetails);

    await _p.show(DateTime.now().millisecondsSinceEpoch ~/ 1000, title, body, details);
  }
}
