import 'package:share_plus/share_plus.dart';
import 'build_config.dart';

class ShareInstall {
  static String landingUrl() => "${BuildConfig.pagesBase}/";

  static Future<void> shareLanding() async {
    await Share.share(
      "Install Global Math Fabric:\n${landingUrl()}\n\n(Windows auto-update via AppInstaller; first-time cert link is on the page.)",
      subject: "Global Math Fabric install link",
    );
  }
}
