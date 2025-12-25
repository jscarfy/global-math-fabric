class CpuThrottle {
  final int capPercent;
  CpuThrottle(this.capPercent);

  /// Call with workDurationMs = time spent doing actual compute (approx).
  /// If cap=25 => sleep ~ 3x work time.
  Duration sleepForWork(Duration work) {
    final cap = capPercent.clamp(1, 100);
    if (cap >= 100) return Duration.zero;
    final w = work.inMicroseconds;
    if (w <= 0) return const Duration(milliseconds: 50);
    final factor = (100 - cap) / cap; // e.g. 75/25 = 3
    final us = (w * factor).round();
    return Duration(microseconds: us);
  }
}
