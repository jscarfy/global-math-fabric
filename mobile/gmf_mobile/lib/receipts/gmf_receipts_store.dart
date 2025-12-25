import 'dart:io';
import 'package:path_provider/path_provider.dart';

class GmfReceiptsStore {
  static Future<File> _file() async {
    final dir = await getApplicationDocumentsDirectory();
    final f = File('${dir.path}/gmf_receipts.jsonl');
    if (!await f.exists()) {
      await f.create(recursive: true);
    }
    return f;
  }

  static Future<void> appendJsonLine(String json) async {
    final f = await _file();
    await f.writeAsString(json.trimRight() + "\n", mode: FileMode.append, flush: true);
  }
}
