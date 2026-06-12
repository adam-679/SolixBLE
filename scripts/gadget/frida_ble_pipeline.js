/*
 * Gadget pipeline trace for Anker BLE command encoding.
 *
 * BLE write hooks only see encrypted packets in recent Anker builds. This
 * script hooks the Flutter encryption bridge and nearby obfuscated Java
 * helpers so setter payloads can be correlated before they reach
 * BluetoothGatt.writeCharacteristic().
 */

var MAX_TEXT = 1400;
var MAX_COLLECTION_ITEMS = 20;

function timestamp() {
    var t = new Date();
    return t.getHours().toString().padStart(2, "0") + ":" +
        t.getMinutes().toString().padStart(2, "0") + ":" +
        t.getSeconds().toString().padStart(2, "0") + "." +
        t.getMilliseconds().toString().padStart(3, "0");
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

function readField(obj, name) {
    try {
        if (!obj || obj[name] === undefined) return undefined;
        if (obj[name] && obj[name].value !== undefined) return obj[name].value;
        return obj[name];
    } catch (_) {
        return undefined;
    }
}

function readJavaField(obj, name) {
    try {
        var field = obj.getClass().getField(name);
        field.setAccessible(true);
        return field.get(obj);
    } catch (_) {}
    try {
        var declared = obj.getClass().getDeclaredField(name);
        declared.setAccessible(true);
        return declared.get(obj);
    } catch (_) {}
    return readField(obj, name);
}

function formatMap(value, depth) {
    var Map = Java.use("java.util.Map");
    var map = Java.cast(value, Map);
    var iterator = map.entrySet().iterator();
    var parts = [];
    var count = 0;
    while (iterator.hasNext() && count < MAX_COLLECTION_ITEMS) {
        var entry = iterator.next();
        parts.push(formatValue(entry.getKey(), depth + 1) + "=" + formatValue(entry.getValue(), depth + 1));
        count++;
    }
    if (iterator.hasNext()) parts.push("...");
    return "{" + parts.join(", ") + "}";
}

function formatCollection(value, depth) {
    var Collection = Java.use("java.util.Collection");
    var collection = Java.cast(value, Collection);
    var iterator = collection.iterator();
    var parts = [];
    var count = 0;
    while (iterator.hasNext() && count < MAX_COLLECTION_ITEMS) {
        parts.push(formatValue(iterator.next(), depth + 1));
        count++;
    }
    if (iterator.hasNext()) parts.push("...");
    return "[" + parts.join(", ") + "]";
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
    return "MethodCall(method=" + method + ", arguments=" + formatValue(args, depth + 1) + ")";
}

function formatValue(value, depth) {
    if (depth === undefined) depth = 0;
    if (value === null || value === undefined) return String(value);
    if (isByteArray(value)) return "hex=" + toHex(value);
    if (depth > 3) return trim(value);
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
        return trim(value);
    }

    var name = classNameOf(value);
    try {
        if (name === "io.flutter.plugin.common.MethodCall") {
            var call = formatMethodCall(value, depth);
            if (call !== null) return trim(call);
        }
        if (name === "java.nio.HeapByteBuffer" || name === "java.nio.DirectByteBuffer") {
            return formatByteBuffer(value);
        }
        if (name.indexOf("java.util.") === 0 || name.indexOf("android.util.ArrayMap") === 0) {
            try {
                return trim(name + formatMap(value, depth));
            } catch (_) {
                try {
                    return trim(name + formatCollection(value, depth));
                } catch (__) {}
            }
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

function formatArgs(args) {
    var parts = [];
    for (var i = 0; i < args.length; i++) {
        parts.push(formatValue(args[i], 0));
    }
    return "[" + parts.join(", ") + "]";
}

function hookOverloads(className, methodName, options) {
    options = options || {};
    try {
        var klass = Java.use(className);
        if (!klass[methodName]) {
            log("[pipeline] no method " + className + "." + methodName);
            return false;
        }
        klass[methodName].overloads.forEach(function (overload) {
            var signature = overload.argumentTypes.map(function (type) {
                return type.className;
            }).join(", ");
            overload.implementation = function () {
                var prefix = options.label || (className + "." + methodName);
                if (!options.afterOnly) {
                    log("[CALL " + prefix + "(" + signature + ")] args=" + formatArgs(arguments));
                }
                var result;
                try {
                    result = overload.apply(this, arguments);
                } catch (e) {
                    log("[THROW " + prefix + "] " + e);
                    throw e;
                }
                if (!options.beforeOnly) {
                    log("[RET  " + prefix + "] " + formatValue(result, 0));
                }
                return result;
            };
        });
        log("[pipeline] hooked " + className + "." + methodName + " overloads=" + klass[methodName].overloads.length);
        return true;
    } catch (e) {
        return false;
    }
}

function hookAllDeclared(className, label) {
    try {
        var klass = Java.use(className);
        var methods = klass.class.getDeclaredMethods();
        var names = {};
        for (var i = 0; i < methods.length; i++) {
            names[methods[i].getName().toString()] = true;
        }
        Object.keys(names).sort().forEach(function (name) {
            if (name === "$init" || name === "equals" || name === "hashCode" || name === "toString") return;
            hookOverloads(className, name, { label: label + "." + name });
        });
        return true;
    } catch (e) {
        return false;
    }
}

function retry(label, installer, delayMs, maxAttempts) {
    var attempts = 0;
    var timer = setInterval(function () {
        attempts++;
        Java.perform(function () {
            if (installer()) {
                log("[pipeline] ready " + label);
                clearInterval(timer);
            } else if (attempts >= maxAttempts) {
                log("[pipeline] gave up waiting for " + label);
                clearInterval(timer);
            }
        });
    }, delayMs);
}

function printStackTrace(name) {
    try {
        var Log = Java.use("android.util.Log");
        var Exception = Java.use("java.lang.Exception");
        log(Log.getStackTraceString(Exception.$new(name)));
    } catch (_) {}
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
        var StandardMethodCodec = Java.use("io.flutter.plugin.common.StandardMethodCodec");
        var standardCodec = StandardMethodCodec.INSTANCE.value;
        var standardCall = standardCodec.decodeMethodCall(duplicateByteBuffer(buffer));
        return formatValue(standardCall, 0);
    } catch (_) {}

    try {
        var JSONMethodCodec = Java.use("io.flutter.plugin.common.JSONMethodCodec");
        var jsonCodec = JSONMethodCodec.INSTANCE.value;
        var jsonCall = jsonCodec.decodeMethodCall(duplicateByteBuffer(buffer));
        return formatValue(jsonCall, 0);
    } catch (_) {}

    return formatByteBuffer(buffer);
}

function hookMethodChannelMessages() {
    try {
        var Handler = Java.use("io.flutter.plugin.common.MethodChannel$IncomingMethodCallHandler");
        Handler.onMessage.overload("java.nio.ByteBuffer", "io.flutter.plugin.common.BinaryMessenger$BinaryReply").implementation = function (message, reply) {
            log("[FLUTTER METHOD] " + decodeFlutterMessage(message));
            return this.onMessage(message, reply);
        };
        log("[pipeline] hooked MethodChannel incoming decode");
        return true;
    } catch (e) {
        return false;
    }
}

setImmediate(function () {
    Java.perform(function () {
        log("[pipeline] installing startup hooks");

        try {
            var System = Java.use("java.lang.System");
            var AndroidProcess = Java.use("android.os.Process");
            System.exit.overload("int").implementation = function (code) {
                log("[anti-exit] blocked System.exit(" + code + ")");
            };
            AndroidProcess.killProcess.overload("int").implementation = function (pid) {
                log("[anti-exit] blocked Process.killProcess(" + pid + ")");
            };
        } catch (e) {
            log("[pipeline] anti-exit hook failed: " + e);
        }

        try {
            var BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
            BluetoothGatt.writeCharacteristic.overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var characteristic = arguments[0];
                    var data = arguments.length >= 2 ? arguments[1] : characteristic.getValue();
                    log("[BLE WRITE] uuid=" + characteristic.getUuid() + " data=" + toHex(data));
                    return overload.apply(this, arguments);
                };
            });
            log("[pipeline] hooked BluetoothGatt.writeCharacteristic");
        } catch (e) {
            log("[pipeline] BLE hook failed: " + e);
        }
    });
});

retry("Flutter encryption plugin", function () {
    var ok = false;
    ok = hookOverloads("z1.a", "onMethodCall", { label: "EncryptionPlugin.onMethodCall" }) || ok;
    ok = hookAllDeclared("z1.b", "SafeUtils") || ok;
    ok = hookAllDeclared("k1.b", "ECDHUtil") || ok;
    ok = hookAllDeclared("o9.k", "BleWriter") || ok;
    return ok;
}, 250, 120);

retry("Flutter MethodChannel", function () {
    return hookMethodChannelMessages();
}, 250, 120);

retry("native library loads", function () {
    var ok = false;
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.load0.overloads.forEach(function (overload) {
            overload.implementation = function () {
                log("[NATIVE LOAD Runtime.load0] args=" + formatArgs(arguments));
                return overload.apply(this, arguments);
            };
        });
        Runtime.loadLibrary0.overloads.forEach(function (overload) {
            overload.implementation = function () {
                log("[NATIVE LOAD Runtime.loadLibrary0] args=" + formatArgs(arguments));
                return overload.apply(this, arguments);
            };
        });
        ok = true;
    } catch (_) {}
    return ok;
}, 250, 20);
