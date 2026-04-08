"""Configuration for apkanal — patterns, prompts, exclusions, schemas."""

# ---------------------------------------------------------------------------
# Library / generated code exclusion prefixes (Java package paths)
# ---------------------------------------------------------------------------
EXCLUDED_PACKAGES = [
    "android/", "androidx/", "com/google/android/", "com/google/protobuf/",
    "com/google/gson/", "com/google/firebase/", "com/google/flatbuffers/",
    "com/google/common/", "com/google/errorprone/", "com/google/thirdparty/",
    "kotlin/", "kotlinx/", "java/", "javax/",
    "org/apache/", "org/json/", "org/xml/", "org/w3c/",
    "org/checkerframework/", "org/codehaus/",
    "com/squareup/", "io/reactivex/", "io/realm/",
    "io/grpc/", "io/perfmark/",
    "com/facebook/react/", "org/chromium/",
    "okhttp3/", "okio/", "retrofit2/",
    "dagger/", "com/bumptech/glide/",
    "org/intellij/", "org/jetbrains/",
    "_COROUTINE/",
]

EXCLUDED_FILE_PATTERNS = [
    "R.java", "R$", "BuildConfig.java",
    "$$Lambda$", "_Factory.java", "_MembersInjector.java",
    "Binding.java", "BR.java", "_Impl.java",
    "Hilt_", "Dagger",
]

# ---------------------------------------------------------------------------
# Suspicion patterns: (regex, weight, description)
# ---------------------------------------------------------------------------
SUSPICION_PATTERNS = {
    "code_execution": [
        (r"Runtime\.getRuntime\(\)\.exec", 30, "Runtime command execution"),
        (r"ProcessBuilder", 25, "Process creation"),
    ],
    "dynamic_loading": [
        (r"DexClassLoader", 35, "Dynamic DEX loading"),
        (r"InMemoryDexClassLoader", 40, "In-memory DEX loading"),
        (r"PathClassLoader", 25, "Dynamic class path loading"),
        (r"Class\.forName", 15, "Reflective class lookup"),
        (r"System\.loadLibrary", 20, "Native library loading"),
        (r"System\.load\s*\(", 20, "Native library loading from path"),
    ],
    "reflection": [
        (r"getDeclaredMethod", 12, "Reflective method access"),
        (r"getDeclaredField", 10, "Reflective field access"),
        (r"setAccessible\s*\(\s*true", 20, "Accessibility bypass"),
        (r"Method\.invoke", 15, "Reflective method invocation"),
    ],
    "encoding_crypto": [
        (r"Base64\.(decode|encode|getDecoder|getEncoder)", 10, "Base64 encoding/decoding"),
        (r"Cipher\.getInstance", 10, "Cryptographic cipher usage"),
        (r"SecretKeySpec", 10, "Symmetric key construction"),
        (r"[^a-zA-Z](xor|XOR)\s*[\(\[]", 15, "Potential XOR obfuscation"),
    ],
    "network": [
        (r"ServerSocket|DatagramSocket", 15, "Raw socket server"),
        (r"WebSocket", 8, "WebSocket communication"),
        (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 20, "Hardcoded IP address"),
        (r"https?://[^\s\"']+", 5, "Hardcoded URL"),
    ],
    "sms_telephony": [
        (r"SmsManager", 25, "SMS operations"),
        (r"sendTextMessage|sendMultipartTextMessage", 30, "SMS sending"),
        (r"getDeviceId|getSubscriberId|getLine1Number|getImei", 20, "Device ID harvesting"),
    ],
    "data_access": [
        (r"ContactsContract", 15, "Contacts access"),
        (r"getLastKnownLocation|requestLocationUpdates", 15, "Location tracking"),
        (r"ClipboardManager", 10, "Clipboard access"),
        (r"android\.provider\.Telephony\.SMS", 15, "SMS content provider"),
    ],
    "obfuscation": [
        (r"new\s+String\s*\(\s*new\s+byte", 15, "String from byte array construction"),
        (r"\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}", 10, "Unicode escape sequences"),
        (r"\(char\)\s*\(?\s*\d+", 10, "Char from int casting (obfuscation)"),
    ],
    "persistence_stealth": [
        (r"BOOT_COMPLETED", 15, "Boot persistence"),
        (r"DeviceAdminReceiver", 25, "Device admin capability"),
        (r"AccessibilityService", 20, "Accessibility service abuse risk"),
        (r"BIND_NOTIFICATION_LISTENER", 20, "Notification listener"),
        (r"setComponentEnabledSetting", 15, "Component hiding/showing"),
        (r"PackageManager\.COMPONENT_ENABLED_STATE_DISABLED", 20, "Component disabling"),
    ],
    "root_su": [
        (r'"su"', 25, "Root (su) command reference"),
        (r"/system/app/Superuser", 20, "Superuser check"),
        (r"com\.noshufou\.android\.su", 20, "SuperUser app check"),
        (r"/system/xbin/su", 20, "su binary path"),
    ],
}

# ---------------------------------------------------------------------------
# LLM Prompts
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_ANALYSIS = """\
You are a senior Android security researcher specializing in malware analysis \
and backdoor detection. You are analyzing decompiled Android application source \
code for signs of malicious behavior, backdoors, data exfiltration, or suspicious \
functionality.

Your analysis should be thorough but practical. Not every use of Runtime.exec() \
or Base64 is malicious — consider the context. A legitimate app might use these \
for valid purposes. Focus on:

1. Combinations of suspicious patterns (e.g., Base64 decoding + DexClassLoader = likely dynamic payload loading)
2. Data being sent to external servers, especially PII or device identifiers
3. Hidden or obfuscated functionality that doesn't match the app's stated purpose
4. Command-and-control (C2) communication patterns
5. Privilege escalation attempts or root detection/exploitation
6. Code that activates under specific conditions (time bombs, geo-fencing, delayed triggers)
7. Cryptocurrency miners or ad fraud logic
8. Screen overlay / keylogging via AccessibilityService abuse

When reporting findings, include the exact file path and relevant code snippet. \
Rate your confidence 0.0-1.0 — use lower values when the pattern could be legitimate.

Do NOT include recommendations or remediation advice. Only report findings."""

SYSTEM_PROMPT_MANIFEST = """\
You are a senior Android security researcher. Analyze this AndroidManifest.xml \
for security concerns. Focus on:
1. Dangerous permissions (SEND_SMS, READ_CONTACTS, CAMERA, READ_CALL_LOG, etc.)
2. Exported components without proper permission protection
3. Custom permissions with weak (normal/dangerous) protection levels
4. android:allowBackup="true" (data theft risk)
5. android:debuggable="true" (should never be in production)
6. Unusual intent filter configurations
7. Receivers for BOOT_COMPLETED, PACKAGE_ADDED, etc.
8. Services with suspicious names or exported without protection
9. Content providers without proper permission guards

Do NOT include recommendations or remediation advice. Only report findings."""

SYSTEM_PROMPT_INTERACTIVE = """\
You are a senior Android security researcher. The user is interactively \
investigating decompiled Android application code for potential backdoors \
and malicious behavior. Answer their questions about the code precisely and \
concisely, with security implications highlighted. Reference specific files \
and line patterns when possible."""

# ---------------------------------------------------------------------------
# JSON Schema for structured output
# ---------------------------------------------------------------------------
FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "file_path": {"type": "string"},
                    "code_snippet": {"type": "string"},
                    "confidence": {"type": "number"},
                    "category": {"type": "string"},
                },
                "required": ["severity", "title", "description", "file_path"],
            },
        },
        "summary": {"type": "string"},
    },
    "required": ["findings"],
}

MANIFEST_SCHEMA = {
    "type": "object",
    "properties": {
        "permissions_analysis": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "permission": {"type": "string"},
                    "risk_level": {"type": "string"},
                    "explanation": {"type": "string"},
                },
                "required": ["permission", "risk_level"],
            },
        },
        "component_risks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "component": {"type": "string"},
                    "risk": {"type": "string"},
                    "explanation": {"type": "string"},
                },
                "required": ["component", "risk"],
            },
        },
        "overall_risk_level": {"type": "string"},
        "summary": {"type": "string"},
    },
    "required": ["overall_risk_level", "summary"],
}

# ---------------------------------------------------------------------------
# Chunk size
# ---------------------------------------------------------------------------
MAX_CHUNK_CHARS = 30_000  # ~8K tokens, smaller chunks for faster feedback
PARALLEL_CHUNKS = 8
STRIP_IMPORTS = True  # Remove import lines from source before sending to LLM
STRIP_METADATA = True  # Remove @Metadata(...) Kotlin compiler annotations
