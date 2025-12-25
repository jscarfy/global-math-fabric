class GmfIntervalPolicy {
  /// Return loop interval seconds based on capability payload.
  /// cap fields: battery_pct (0..100), charging (bool), network_type ("wifi"|"cellular"|"none"), thermal
  static int computeIntervalSec(Map<String, dynamic> cap) {
    final battery = (cap['battery_pct'] is num) ? (cap['battery_pct'] as num).toDouble() : 100.0;
    final charging = cap['charging'] == true;
    final net = (cap['network_type'] ?? 'wifi').toString().toLowerCase();
    final thermal = (cap['thermal'] ?? 'nominal').toString().toLowerCase();

    // Hard safety: too hot => slow down
    if (thermal == 'critical' || thermal == 'serious') return 30;

    // Very low battery and not charging => very slow
    if (!charging && battery < 15) return 60;

    // Cellular => slow (unless charging and battery high; still keep moderate)
    if (net != 'wifi' && net != 'ethernet') return charging ? 20 : 30;

    // Best case: charging + wifi + ok thermal => fast
    if (charging && (thermal == 'nominal' || thermal == 'fair')) return 3;

    // Wifi but not charging => moderate
    return 10;
  }
}
