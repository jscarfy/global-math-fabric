import 'dart:io';
import 'package:battery_plus/battery_plus.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:thermal/thermal.dart';

class GmfCapabilities {
  static final Battery _battery = Battery();
  static final Connectivity _conn = Connectivity();

  static String _normalizeNetwork(List<ConnectivityResult> r) {
    // connectivity_plus (>=6) can return multiple results
    if (r.contains(ConnectivityResult.wifi) || r.contains(ConnectivityResult.ethernet)) return 'wifi';
    if (r.contains(ConnectivityResult.mobile)) return 'cellular';
    if (r.contains(ConnectivityResult.none)) return 'none';
    return r.isNotEmpty ? r.first.toString().split('.').last : 'unknown';
  }

  static String _normalizeThermal(ThermalState s) {
    // thermal plugin states (example): nominal, fair, serious, critical
    return s.toString().split('.').last;
  }

  static Future<Map<String, dynamic>> probe() async {
    final level = await _battery.batteryLevel; // 0..100
    final state = await _battery.batteryState; // charging/full/discharging/unknown
    final charging = (state == BatteryState.charging || state == BatteryState.full);

    final results = await _conn.checkConnectivity();
    final networkType = _normalizeNetwork(results);

    ThermalState thermalState;
    try {
      thermalState = await Thermal.getThermalState();
    } catch (_) {
      thermalState = ThermalState.nominal;
    }

    return <String, dynamic>{
      "platform": Platform.isIOS ? "ios" : (Platform.isAndroid ? "android" : "other"),
      "battery_pct": level,
      "charging": charging,
      "network_type": networkType,
      "thermal": _normalizeThermal(thermalState),
      "ts_unix": DateTime.now().millisecondsSinceEpoch ~/ 1000,
    };
  }
}
