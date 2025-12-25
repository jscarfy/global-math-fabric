import 'dart:io';
import 'package:battery_plus/battery_plus.dart';
import 'package:connectivity_plus/connectivity_plus.dart';

import 'consent_store.dart';
import 'account_store.dart';
import 'resource_limits_store.dart';

enum GuardBlockReason {
  noConsent,
  noToken,
  notCharging,
  meteredNetwork,
}

class GuardDecision {
  final bool ok;
  final GuardBlockReason? reason;
  final String message;
  GuardDecision.ok() : ok = true, reason = null, message = "ok";
  GuardDecision.block(this.reason, this.message) : ok = false;
}

class RuntimeGuard {
  static final Battery _battery = Battery();

  static Future<GuardDecision> canRunNow() async {
    // 1) consent
    final consent = await ConsentStore.hasConsent();
    if (!consent) {
      return GuardDecision.block(GuardBlockReason.noConsent, "Consent missing");
    }

    // 2) token/account must exist
    final token = await AccountStore.getToken();
    final acct = await AccountStore.getAccountId();
    if (token == null || token.isEmpty || acct == null || acct.isEmpty) {
      return GuardDecision.block(GuardBlockReason.noToken, "Account token missing");
    }

    // 3) limits
    final limits = await ResourceLimitsStore.get();

    // chargingOnly (best-effort: mobile/desktop)
    if (limits.chargingOnly) {
      try {
        final state = await _battery.batteryState;
        final charging = (state == BatteryState.charging) || (state == BatteryState.full);
        if (!charging) {
          return GuardDecision.block(GuardBlockReason.notCharging, "Not charging (charging-only enabled)");
        }
      } catch (_) {
        // if battery api fails, be conservative on mobile, permissive on desktop
        if (!Platform.isLinux && !Platform.isMacOS && !Platform.isWindows) {
          return GuardDecision.block(GuardBlockReason.notCharging, "Cannot determine charging state");
        }
      }
    }

    // unmeteredOnly (Wi-Fi only). connectivity_plus doesn't expose metered flag universally;
    // we treat Wi-Fi/Ethernet as unmetered.
    if (limits.unmeteredOnly) {
      try {
        final c = await Connectivity().checkConnectivity();
        final ok = (c == ConnectivityResult.wifi) || (c == ConnectivityResult.ethernet);
        if (!ok) {
          return GuardDecision.block(GuardBlockReason.meteredNetwork, "Not on Wi-Fi/Ethernet (unmetered-only enabled)");
        }
      } catch (_) {
        // conservative on mobile
        if (!Platform.isLinux && !Platform.isMacOS && !Platform.isWindows) {
          return GuardDecision.block(GuardBlockReason.meteredNetwork, "Cannot determine network");
        }
      }
    }

    return GuardDecision.ok();
  }
}
