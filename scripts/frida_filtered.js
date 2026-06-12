/*
 * Filtered Anker Frida capture script.
 *
 * This is a quieter copy of frida.js for rooted timed-attach captures. It
 * keeps BLE, cipher, and selected preference logs while dropping catalog,
 * Firebase, Crashlytics, and other high-volume bootstrap preference noise.
 */

function timestamp() {
    return new Date().toISOString();
}

function log(line) {
    console.log("[" + timestamp() + "] " + line);
}

function toHex(byteArray) {
    if (!byteArray) return "null";
    var result = "";
    for (var i = 0; i < byteArray.length; i++) {
        result += ("0" + (byteArray[i] & 0xff).toString(16)).slice(-2);
    }
    return result;
}

var IGNORED_PREF_NAMES = [
    "com.google.android.gms.appid",
    "com.google.firebase.crashlytics",
    "com.google.firebase.messaging",
    "FirebaseHeartBeat",
    "__wx_opensdk_sp__",
    "pst",
    "pst_bdservice_v1",
    "push_client_self_info",
    "com.baidu.pushservice.BIND_CACHE",
];

var IGNORED_PREF_KEYS = [
    "flutter.productAccessories",
    "flutter.productCategories",
    "flutter.thirdPartyProductCategories",
    "flutter.hesProductsPnImage",
    "flutter.termsOfService",
    "flutter.generalPrivacyPolicy",
    "flutter.iotPrivacyPolicy",
    "flutter.appUpdateInfo",
    "flutter.currentTimezoneGMT",
    "flutter.hostUrlByRegion",
    "fire-",
    "firebase.",
    "firebase_",
    "crashlytics.",
    "last-used-date",
    "topic_operation_queue",
    "auto_init",
    "BD_OPPO_PROXY",
    "bd_push",
    "com.baidu.",
];

function startsWithAny(value, prefixes) {
    if (!value) return false;
    for (var i = 0; i < prefixes.length; i++) {
        if (value.indexOf(prefixes[i]) === 0) return true;
    }
    return false;
}

function shouldLogPrefName(name) {
    return !startsWithAny(name || "", IGNORED_PREF_NAMES);
}

function shouldLogPrefKey(key) {
    return !startsWithAny(key || "", IGNORED_PREF_KEYS);
}

function summarizeValue(value) {
    if (value === null || value === undefined) return String(value);
    var text = String(value);
    if (text.length <= 500) return text;
    return text.slice(0, 500) + "... <" + text.length + " chars>";
}

setImmediate(function () {
    Java.perform(function () {
        var System = Java.use("java.lang.System");
        var Process = Java.use("android.os.Process");

        System.exit.overload("int").implementation = function (code) {
            log("[anti-exit] blocked System.exit(" + code + ")");
        };

        Process.killProcess.overload("int").implementation = function (pid) {
            log("[anti-exit] blocked Process.killProcess(" + pid + ")");
        };
    });
});

setImmediate(function () {
    Java.perform(function () {
        var contextWrapper = Java.use("android.content.ContextWrapper");
        contextWrapper.getSharedPreferences.overload("java.lang.String", "int").implementation = function (name, mode) {
            if (shouldLogPrefName(name)) {
                log("[PREF OPEN] name=" + name + " mode=" + mode);
            }
            return this.getSharedPreferences(name, mode);
        };

        var sharedPreferencesEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

        function hookPut(methodName, label, signature) {
            var overload = sharedPreferencesEditor[methodName].overload("java.lang.String", signature);
            overload.implementation = function (key, value) {
                if (shouldLogPrefKey(key)) {
                    log("[PREF PUT " + label + "] " + key + " = " + summarizeValue(value));
                }
                return overload.call(this, key, value);
            };
        }

        hookPut("putString", "String", "java.lang.String");
        hookPut("putBoolean", "Boolean", "boolean");
        hookPut("putFloat", "Float", "float");
        hookPut("putInt", "Int", "int");
        hookPut("putLong", "Long", "long");
        hookPut("putStringSet", "StringSet", "java.util.Set");

        var sharedPreferences = Java.use("android.app.SharedPreferencesImpl");
        sharedPreferences.getString.overload("java.lang.String", "java.lang.String").implementation = function (key, fallback) {
            var value = this.getString(key, fallback);
            if (shouldLogPrefKey(key)) {
                log("[PREF GET String] " + key + " = " + summarizeValue(value));
            }
            return value;
        };
    });
});

Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.init.overloads.forEach(function (overload) {
        overload.implementation = function () {
            var opmode = arguments[0];
            var key = arguments[1];
            var modeName = opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : opmode;
            var result = overload.apply(this, arguments);
            var iv = this.getIV();

            log("[CIPHER INIT] mode=" + modeName + " algorithm=" + this.getAlgorithm());
            if (key && key.getEncoded()) {
                log("[CIPHER KEY] " + toHex(key.getEncoded()));
            }
            if (iv) {
                log("[CIPHER IV] " + toHex(iv));
            }
            return result;
        };
    });

    Cipher.doFinal.overloads.forEach(function (overload) {
        overload.implementation = function () {
            var input = arguments[0];
            var result = overload.apply(this, arguments);
            if (input && input.length > 0) {
                log("[CIPHER INPUT] " + toHex(input));
            }
            if (result && result.length > 0) {
                log("[CIPHER OUTPUT] " + toHex(result));
            }
            return result;
        };
    });
});

Java.perform(function () {
    var BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
    var BluetoothGattCharacteristic = Java.use("android.bluetooth.BluetoothGattCharacteristic");

    BluetoothGatt.writeCharacteristic.overloads.forEach(function (overload) {
        overload.implementation = function () {
            var characteristic = arguments[0];
            var data = arguments.length >= 2 ? arguments[1] : characteristic.getValue();

            log("[BLE WRITE] uuid=" + characteristic.getUuid() + " data=" + toHex(data));
            return overload.apply(this, arguments);
        };
    });

    BluetoothGattCharacteristic.setValue.overloads.forEach(function (overload) {
        overload.implementation = function () {
            var uuid = this.getUuid().toString();
            var value = arguments[0];

            log("[BLE NOTIFY] uuid=" + uuid + " data=" + toHex(value));
            return overload.apply(this, arguments);
        };
    });
});
