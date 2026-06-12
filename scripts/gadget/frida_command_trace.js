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

function installAndroidLogHook() {
  try {
    var Log = Java.use("android.util.Log");
    var interesting = [
      "before payload",
      "发送蓝牙命令",
      "发送请求标识",
      "A1781发送命令",
      "A1771发送命令",
      "A1790发送命令",
    ];

    function shouldLog(tag, message) {
      var text = String(tag) + " " + String(message);
      for (var i = 0; i < interesting.length; i++) {
        if (text.indexOf(interesting[i]) !== -1) return true;
      }
      return false;
    }

    function hookLevel(level) {
      Log[level].overload("java.lang.String", "java.lang.String").implementation =
        function (tag, message) {
          if (shouldLog(tag, message)) {
            log("[ANDROID LOG " + level + "] tag=" + tag + " message=" + message);
          }
          return this[level](tag, message);
        };
    }

    ["d", "i", "v", "w", "e"].forEach(hookLevel);
    log("[TRACE] hooked android.util.Log plaintext command hints");
  } catch (e) {
    log("[TRACE] Android Log hook failed: " + e);
  }
}

function installCipherHook() {
  try {
    var Cipher = Java.use("javax.crypto.Cipher");
    var cipherStates = {};

    Cipher.init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var result = overload.apply(this, arguments);
        var opmode = arguments[0];
        var key = arguments.length > 1 ? arguments[1] : null;
        var iv = null;
        try {
          iv = this.getIV();
        } catch (_) {}
        cipherStates[this.hashCode()] = {
          mode: opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : String(opmode),
          algorithm: String(this.getAlgorithm()),
          keyHex: key && key.getEncoded ? toHex(key.getEncoded()) : "null",
          ivHex: iv && iv.length > 0 ? toHex(iv) : "null",
        };
        return result;
      };
    });

    Cipher.doFinal.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var input = arguments.length > 0 ? arguments[0] : null;
        var result = overload.apply(this, arguments);
        var state = cipherStates[this.hashCode()];
        if (!state || state.algorithm.indexOf("AES") === -1) return result;

        var inputHex = input ? toHex(input) : "";
        var resultHex = result ? toHex(result) : "";
        var smallBleShape =
          (inputHex.length > 0 && inputHex.length <= 96) ||
          (resultHex.length > 0 && resultHex.length <= 96);
        if (smallBleShape) {
          log(
            "[CIPHER doFinal] algorithm=" +
              state.algorithm +
              " mode=" +
              state.mode +
              " input=" +
              inputHex +
              " output=" +
              resultHex +
              " key=" +
              state.keyHex +
              " iv=" +
              state.ivHex,
          );
        }
        return result;
      };
    });

    log("[TRACE] hooked javax.crypto.Cipher small AES payloads");
  } catch (e) {
    log("[TRACE] Cipher hook failed: " + e);
  }
}

var dartHeapBase = null;
var dartLibappBase = null;
var dartHookLastError = null;

function initDartContext(context) {
  if (dartHeapBase === null) {
    dartHeapBase = context.x28.shl(32);
  }
}

function dartPointer(value) {
  if (!value) return value;
  if ((value.toInt32() & 1) === 0) return null;
  if (value.compare(ptr("0x100000000")) > 0) return value.sub(1);
  if (dartHeapBase === null) return null;
  return dartHeapBase.add(value.toInt32()).sub(1);
}

function dartCid(objectPtr) {
  return (objectPtr.readU32() >>> 12) & 0xfffff;
}

function dartSmi(value) {
  return value.toInt32() >> 1;
}

function dartString(objectPtr, twoByte) {
  var length = objectPtr.add(8).readU32() >> 1;
  return twoByte
    ? objectPtr.add(16).readUtf16String(length)
    : objectPtr.add(16).readUtf8String(length);
}

function dartUint8List(objectPtr) {
  var length = objectPtr.add(20).readU32() >> 1;
  var data = objectPtr.add(24).readByteArray(length);
  return {
    kind: "Uint8List",
    hex: toHex(new Uint8Array(data)),
    values: Array.prototype.slice.call(new Uint8Array(data)),
  };
}

function dartList(objectPtr, growable, depth) {
  var length = objectPtr.add(12).readU32() >> 1;
  var arrayPtr = objectPtr;
  if (growable) {
    arrayPtr = dartPointer(objectPtr.add(16).readPointer());
    if (arrayPtr === null) return { kind: "GrowableList", length: length };
  }
  var values = [];
  var hexBytes = [];
  for (var i = 0; i < length && i < 64; i++) {
    var item = arrayPtr.add(16 + i * 4).readPointer();
    var decoded = dartValue(item, depth - 1);
    values.push(decoded);
    if (typeof decoded === "number" && decoded >= 0 && decoded <= 255) {
      hexBytes.push(decoded);
    }
  }
  var out = { kind: growable ? "GrowableList" : "List", values: values };
  if (hexBytes.length === values.length) out.hex = toHex(hexBytes);
  return out;
}

function dartValue(value, depth) {
  if (depth === undefined) depth = 3;
  if (!value) return null;
  if ((value.toInt32() & 1) === 0) return dartSmi(value);
  if (depth <= 0) return "<depth>";

  var objectPtr = dartPointer(value);
  if (objectPtr === null) return "<ptr " + value + ">";
  try {
    var cid = dartCid(objectPtr);
    if (cid === 172) return null;
    if (cid === 59) return dartSmi(value);
    if (cid === 93) return dartString(objectPtr, false);
    if (cid === 94) return dartString(objectPtr, true);
    if (cid === 89) return dartList(objectPtr, false, depth);
    if (cid === 91) return dartList(objectPtr, true, depth);
    if (cid === 117) return dartUint8List(objectPtr);
    return { cid: cid, ptr: value.toString() };
  } catch (e) {
    return "<decode failed " + value + ": " + e + ">";
  }
}

function dartArg(context, index) {
  return context.x15.add(8 * index).readPointer();
}

function hookDartFunction(label, offset, argCount, logReturn) {
  try {
    Interceptor.attach(dartLibappBase.add(ptr(offset)), {
      onEnter: function (args) {
        initDartContext(this.context);
        var decoded = [];
        for (var i = 0; i < argCount; i++) {
          decoded.push(dartValue(dartArg(this.context, i), 3));
        }
        log("[DART ENTER " + label + "] args=" + trim(JSON.stringify(decoded)));
      },
      onLeave: function (retval) {
        if (!logReturn) return;
        log("[DART LEAVE " + label + "] ret=" + trim(JSON.stringify(dartValue(retval, 3))));
      },
    });
    log("[TRACE] hooked Dart " + label + " offset=" + offset);
  } catch (e) {
    log("[TRACE] Dart hook failed " + label + ": " + e);
  }
}

function installDartHooks() {
  try {
    try {
      dartLibappBase = Module.findBaseAddress("libapp.so");
    } catch (e) {
      var module = Process.findModuleByName("libapp.so");
      dartLibappBase = module ? module.base : null;
    }
    if (dartLibappBase === null) {
      log("[TRACE] libapp.so not loaded yet for Dart hooks");
      return false;
    }
    log("[TRACE] libapp.so base=" + dartLibappBase);

    hookDartFunction("ZXCommandTransformer.generateCommand", "0x1080f4c", 1, true);
    hookDartFunction("ZXCommandTransformer._getSettingCommand", "0x1080fa8", 1, true);
    hookDartFunction("ZXCommandTransformer._getNormalCommand", "0x1081d8c", 1, true);
    hookDartFunction("ZXCommandTransformer.formatCommand", "0x1083b68", 8, true);
    hookDartFunction("A1781DeviceController.sendCommandWithParam", "0x255679c", 6, false);
    return true;
  } catch (e) {
    var message = String(e);
    if (message !== dartHookLastError) {
      dartHookLastError = message;
      log("[TRACE] install Dart hooks failed: " + message);
    }
    return false;
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
    installAndroidLogHook();
    installCipherHook();
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

    var dartAttempts = 0;
    var dartTimer = setInterval(function () {
      dartAttempts++;
      if (installDartHooks() || dartAttempts >= 80) {
        if (dartAttempts >= 80) log("[TRACE] gave up waiting for libapp.so");
        clearInterval(dartTimer);
      }
    }, 250);
  });
});
