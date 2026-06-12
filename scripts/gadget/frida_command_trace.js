/*
 * Low-noise Gadget trace for mapping Anker app UI actions to BLE commands.
 *
 * Use this when the goal is to identify which decompiled Dart ASM files to
 * inspect. It logs only Flutter method-channel command traffic and
 * final BLE writes, avoiding the broad crypto/helper tracing in
 * frida_ble_pipeline.js.
 */

var MAX_TEXT = 1800;
var lastFlutterBleMethod = null;

function timestamp() {
  var t = new Date();
  return (
    t.getHours().toString().padStart(2, "0") +
    ":" +
    t.getMinutes().toString().padStart(2, "0") +
    ":" +
    t.getSeconds().toString().padStart(2, "0") +
    "." +
    t.getMilliseconds().toString().padStart(3, "0")
  );
}

function log(line) {
  console.log("[" + timestamp() + "] " + line);
}

function trim(value) {
  var text = String(value);
  if (text.length <= MAX_TEXT) return text;
  return text.slice(0, MAX_TEXT) + "... <" + text.length + " chars>";
}

function toHex(bytes) {
  if (!bytes) return "null";
  try {
    var out = "";
    for (var i = 0; i < bytes.length; i++) {
      out += ("0" + (bytes[i] & 0xff).toString(16)).slice(-2);
    }
    return out;
  } catch (e) {
    return "<hex failed: " + e + ">";
  }
}

function classNameOf(value) {
  try {
    if (value && value.$className) return value.$className;
  } catch (_) {}
  try {
    if (value && value.getClass) return value.getClass().getName().toString();
  } catch (_) {}
  return "";
}

function isByteArray(value) {
  if (!value || typeof value.length !== "number") return false;
  var name = classNameOf(value);
  if (name === "[B" || name === "byte[]") return true;
  if (value.length === 0) return false;
  return typeof value[0] === "number";
}

function readJavaField(obj, name) {
  try {
    var field = obj.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(obj);
  } catch (_) {}
  return undefined;
}

function formatMap(value, depth) {
  var Map = Java.use("java.util.Map");
  var map = Java.cast(value, Map);
  var iterator = map.entrySet().iterator();
  var parts = [];
  while (iterator.hasNext() && parts.length < 20) {
    var entry = iterator.next();
    parts.push(
      formatValue(entry.getKey(), depth + 1) +
        "=" +
        formatValue(entry.getValue(), depth + 1),
    );
  }
  if (iterator.hasNext()) parts.push("...");
  return "{" + parts.join(", ") + "}";
}

function formatByteBuffer(value) {
  var ByteBuffer = Java.use("java.nio.ByteBuffer");
  var buffer = Java.cast(value, ByteBuffer).duplicate();
  var bytes = [];
  while (buffer.hasRemaining()) {
    bytes.push(buffer.get());
  }
  return "ByteBuffer(hex=" + toHex(bytes) + ")";
}

function formatMethodCall(value, depth) {
  var method = readJavaField(value, "method");
  var args = readJavaField(value, "arguments");
  if (method === undefined && args === undefined) return null;
  return (
    "MethodCall(method=" +
    method +
    ", arguments=" +
    formatValue(args, depth + 1) +
    ")"
  );
}

function formatValue(value, depth) {
  if (depth === undefined) depth = 0;
  if (value === null || value === undefined) return String(value);
  if (isByteArray(value)) return "hex=" + toHex(value);
  if (depth > 4) return trim(value);
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  )
    return trim(value);

  var name = classNameOf(value);
  try {
    if (name === "io.flutter.plugin.common.MethodCall") {
      var call = formatMethodCall(value, depth);
      if (call !== null) return trim(call);
    }
    if (
      name === "java.nio.HeapByteBuffer" ||
      name === "java.nio.DirectByteBuffer"
    ) {
      return formatByteBuffer(value);
    }
    if (
      name.indexOf("java.util.") === 0 ||
      name.indexOf("android.util.ArrayMap") === 0
    ) {
      return trim(name + formatMap(value, depth));
    }
  } catch (e) {
    return "<format failed " + name + ": " + e + ">";
  }

  try {
    return trim((name ? name + "=" : "") + value.toString());
  } catch (_) {
    return "<" + (name || typeof value) + ">";
  }
}

function duplicateByteBuffer(buffer) {
  var ByteBuffer = Java.use("java.nio.ByteBuffer");
  var copy = Java.cast(buffer, ByteBuffer).duplicate();
  try {
    copy.position(0);
  } catch (_) {}
  return copy;
}

function decodeFlutterMessage(buffer) {
  try {
    var StandardMethodCodec = Java.use(
      "io.flutter.plugin.common.StandardMethodCodec",
    );
    var standardCodec = StandardMethodCodec.INSTANCE.value;
    return formatValue(
      standardCodec.decodeMethodCall(duplicateByteBuffer(buffer)),
      0,
    );
  } catch (_) {}

  try {
    var JSONMethodCodec = Java.use("io.flutter.plugin.common.JSONMethodCodec");
    var jsonCodec = JSONMethodCodec.INSTANCE.value;
    return formatValue(
      jsonCodec.decodeMethodCall(duplicateByteBuffer(buffer)),
      0,
    );
  } catch (_) {}

  return formatByteBuffer(buffer);
}

function firstMatch(text, pattern) {
  var match = pattern.exec(text);
  return match ? match[1] : null;
}

function wordsFrom(text) {
  var ignored = {
    MethodCall: true,
    HashMap: true,
    java: true,
    util: true,
    param: true,
    data: true,
    type: true,
    hex: true,
    null: true,
  };
  var seen = {};
  var words = [];
  var matches = text.match(/[A-Za-z][A-Za-z0-9_]{3,}/g) || [];
  for (var i = 0; i < matches.length; i++) {
    var word = matches[i];
    if (ignored[word] || seen[word]) continue;
    seen[word] = true;
    words.push(word);
  }
  return words.slice(0, 16);
}

function commandFromBleHex(hex) {
  if (!hex || hex.length < 18 || hex.slice(0, 2) !== "ff") return "unknown";
  return hex.slice(14, 18);
}

function payloadPrefixFromBleHex(hex) {
  if (!hex || hex.length < 18) return "unknown";
  return hex.slice(0, 18);
}

function logAsmPointer(source, details) {
  var parts = [];
  parts.push("source=" + source);
  if (details.method) parts.push("method=" + details.method);
  if (details.identifier) parts.push("identifier=" + details.identifier);
  if (details.command) parts.push("command=" + details.command);
  if (details.packetPrefix) parts.push("packet_prefix=" + details.packetPrefix);
  if (details.dataHex) parts.push("data_hex=" + details.dataHex);
  if (details.searchTerms && details.searchTerms.length > 0) {
    parts.push("asm_search_terms=" + details.searchTerms.join(","));
  }
  log("[ASM POINTER] " + parts.join(" "));
}

function installAntiExitHook() {
  try {
    var System = Java.use("java.lang.System");
    var AndroidProcess = Java.use("android.os.Process");
    System.exit.overload("int").implementation = function (code) {
      log("[ANTI EXIT] blocked System.exit(" + code + ")");
    };
    AndroidProcess.killProcess.overload("int").implementation = function (pid) {
      log("[ANTI EXIT] blocked Process.killProcess(" + pid + ")");
    };
  } catch (e) {
    log("[TRACE] anti-exit hook failed: " + e);
  }
}

function installBleHook() {
  try {
    var BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
    BluetoothGatt.writeCharacteristic.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var characteristic = arguments[0];
        var data =
          arguments.length >= 2 ? arguments[1] : characteristic.getValue();
        var hex = toHex(data);
        var command = commandFromBleHex(hex);
        var packetPrefix = payloadPrefixFromBleHex(hex);
        log(
          "[BLE WRITE] uuid=" +
            characteristic.getUuid() +
            " command=" +
            command +
            " packet_prefix=" +
            packetPrefix +
            " data=" +
            hex,
        );
        if (lastFlutterBleMethod !== null) {
          log(
            "[BLE CONTEXT] previous_flutter_ble_method=" + lastFlutterBleMethod,
          );
        }
        logAsmPointer("ble_write", {
          command: command,
          packetPrefix: packetPrefix,
          dataHex: hex,
          searchTerms: lastFlutterBleMethod
            ? wordsFrom(lastFlutterBleMethod)
            : [],
        });
        return overload.apply(this, arguments);
      };
    });
    log("[TRACE] hooked BluetoothGatt.writeCharacteristic");
  } catch (e) {
    log("[TRACE] BLE hook failed: " + e);
  }
}

function installFlutterHook() {
  try {
    var Handler = Java.use(
      "io.flutter.plugin.common.MethodChannel$IncomingMethodCallHandler",
    );
    Handler.onMessage.overload(
      "java.nio.ByteBuffer",
      "io.flutter.plugin.common.BinaryMessenger$BinaryReply",
    ).implementation = function (message, reply) {
      var decoded = decodeFlutterMessage(message);
      if (
        decoded.indexOf("akiot.ble.") !== -1 ||
        decoded.indexOf("write_characteristic") !== -1
      ) {
        lastFlutterBleMethod = decoded;
        var method = firstMatch(decoded, /MethodCall\(method=([^,\)]+)/);
        var identifier = firstMatch(decoded, /identifier=([^,}\s]+)/);
        var dataHex =
          firstMatch(decoded, /data=hex=([0-9a-fA-F]+)/) ||
          firstMatch(decoded, /hex=([0-9a-fA-F]{8,})/);
        log("[FLUTTER BLE METHOD] " + decoded);
        logAsmPointer("flutter_method", {
          method: method,
          identifier: identifier,
          dataHex: dataHex,
          command: dataHex ? commandFromBleHex(dataHex) : null,
          packetPrefix: dataHex ? payloadPrefixFromBleHex(dataHex) : null,
          searchTerms: wordsFrom(decoded),
        });
      }
      return this.onMessage(message, reply);
    };
    log("[TRACE] hooked Flutter MethodChannel BLE messages");
    return true;
  } catch (e) {
    return false;
  }
}

setImmediate(function () {
  Java.perform(function () {
    installAntiExitHook();
    installBleHook();

    var attempts = 0;
    var timer = setInterval(function () {
      attempts++;
      Java.perform(function () {
        if (installFlutterHook() || attempts >= 120) {
          if (attempts >= 120)
            log("[TRACE] gave up waiting for Flutter MethodChannel");
          clearInterval(timer);
        }
      });
    }, 250);
  });
});
