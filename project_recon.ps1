<#
.SYNOPSIS
    Project reconnaissance for source-code security reviews.
    Run it in the ROOT of a project folder. Needs no Python, no installs and no admin rights;
    it uses cmdlets only, so it also works on locked-down machines (Constrained Language Mode).

.DESCRIPTION
    Walks the project and writes, into <Root>\recon-output (or -OutputDir):
      PASTE-ME.txt             compact summary + what to check manually  (paste this to the reviewer)
      README-ARCHITECTURE.md   how the project is structured: modules, layers, DI, data, network, security config
      review-targets.csv       every text file with a review score and the reasons
      inventory.csv            every file: path, type, size, lines, layers, flags

    The findings are HEURISTIC (file names and text patterns). They tell you where to look,
    not what is vulnerable. Secret-looking values are masked in every output file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\project_recon.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\project_recon.ps1 -Root C:\src\myapp -OutputDir C:\Reports\recon -TopN 80
#>
[CmdletBinding()]
param(
    [string]$Root = '.',
    [string]$OutputDir = '',
    [double]$MaxFileMB = 1.5,        # text files larger than this are listed but not read (bundles, minified code)
    [int]$TopN = 60,                 # review targets shown in PASTE-ME.txt
    [string[]]$ExtraExclude = @(),   # extra folder names to skip
    [switch]$NoContentScan           # inventory only
)

$ErrorActionPreference = 'Stop'
$started = Get-Date

# ======================================================================
# CONFIGURATION TABLES
# ======================================================================
$ExcludeNames = @('.git', '.svn', '.hg', 'node_modules', 'build', '.gradle', '.idea', '.vscode', 'Pods', 'DerivedData',
    '.dart_tool', '.pub-cache', 'dist', 'out', 'target', '__pycache__', '.next', '.nuxt', 'venv', '.venv', '.mvn',
    'recon-output', 'review-files', '.fvm', 'coverage', '.cxx', 'intermediates') + $ExtraExclude
$exclSet = @{}
foreach ($n in $ExcludeNames) { $exclSet[$n.ToLower()] = $true }

$srcExt = @{}; foreach ($e in '.kt .java .dart .swift .m .mm .h .c .cc .cpp .cs .js .jsx .ts .tsx .mjs .cjs .py .go .rs .php .rb .scala .vue .sql .sh .ps1 .bat .groovy .gradle .kts'.Split(' ')) { $srcExt[$e] = $true }
$cfgExt = @{}; foreach ($e in '.json .xml .plist .yaml .yml .toml .ini .cfg .conf .properties .env .pro .gradle .kts .entitlements .xcconfig .proto .graphql .gql'.Split(' ')) { $cfgExt[$e] = $true }
$docExt = @{}; foreach ($e in '.md .txt .rst .pdf .doc .docx .html .htm .csv'.Split(' ')) { $docExt[$e] = $true }
$binExt = @{}; foreach ($e in '.jar .aar .so .a .dll .exe .class .dex .apk .aab .ipa .zip .gz .tar .7z .keystore .jks .p12 .pfx .db .sqlite .sqlite3 .realm .bin .dylib .framework'.Split(' ')) { $binExt[$e] = $true }
$resExt = @{}; foreach ($e in '.png .jpg .jpeg .gif .webp .svg .ico .ttf .otf .woff .woff2 .mp3 .mp4 .wav .lottie .webm'.Split(' ')) { $resExt[$e] = $true }
# extensions whose content is read (text)
$TextExt = @{}
foreach ($t in @($srcExt, $cfgExt, @{ '.md' = 1; '.txt' = 1; '.html' = 1; '.htm' = 1; '.sh' = 1; '.pem' = 1; '.key' = 1; '.cer' = 1; '.crt' = 1; '.strings' = 1; '.storyboard' = 1; '.xib' = 1; '.pbxproj' = 1; '.lock' = 0 })) {
    foreach ($k in $t.Keys) { if ($t[$k] -ne 0) { $TextExt[$k] = $true } }
}
$TextNames = @{ 'dockerfile' = 1; 'jenkinsfile' = 1; 'podfile' = 1; 'gemfile' = 1; 'makefile' = 1; 'fastfile' = 1; 'proguard-rules.pro' = 1; 'cartfile' = 1 }

$ThirdPartyRx = '(^|/)(node_modules|pods|vendor|third[_-]?party|cordova_plugins|\.pub-cache|bower_components|carthage)(/|$)|/www/plugins/|/assets/public/plugins/|/assets/public/assets/lib/|/www/assets/lib/'
$BundleRx = '\.[0-9a-f]{8,}(\.chunk)?\.(js|css)$|(^|/)(chunk-vendors|vendor|vendors|runtime|polyfills|app|main)[\.-][0-9a-z\.\-]*\.js$'
$GeneratedRx = '\.g\.dart$|\.freezed\.dart$|\.pb\.dart$|\.pbgrpc\.dart$|\.mocks\.dart$|\.gr\.dart$|\.config\.dart$|\.min\.js$|\.bundle\.js$|/generated/|/r\.java$|/buildconfig\.java$|\.d\.ts$'
$TestRx = '(^|/)(test|tests|androidtest|__tests__|integration_test|spec|e2e|mocks?)(/|$)|_test\.(dart|js|ts|py)$|(^|/)test_[^/]*\.py$|test\.(kt|java|swift)$|\.spec\.(js|ts)$'

# --- security topics: matched against file CONTENT (one hit per file per topic) -------------
$SecPatterns = @(
    @{ Id = 'SECRET-LIT'; Topic = 'Hard-coded secrets / credentials'; W = 5; Rx = '(?i)(api[_-]?key|secret|passw(or)?d|pwd|auth[_-]?key|client[_-]?secret|private[_-]?key|access[_-]?key|token)["'']?\s*[:=]\s*["''][^"''\s]{8,}["'']'; Check = 'Real credential or placeholder? Anyone with the source or the APK can read it. Is it per-environment?' },
    @{ Id = 'KEY-GOOGLE'; Topic = 'Google API keys'; W = 3; Rx = 'AIza[0-9A-Za-z_\-]{35}'; Check = 'Check the key restrictions (package name, SHA-256, API list) in the Google Cloud console.' },
    @{ Id = 'KEY-AWS'; Topic = 'AWS access keys'; W = 7; Rx = 'AKIA[0-9A-Z]{16}'; Check = 'Treat as a leaked credential until proven otherwise.' },
    @{ Id = 'PRIVATE-KEY'; Topic = 'Private keys in the source'; W = 8; Rx = '-----BEGIN [A-Z ]*PRIVATE KEY-----'; Check = 'A private key should never be in the repository. What does it protect?' },
    @{ Id = 'JWT-LIT'; Topic = 'Hard-coded JWT / bearer tokens'; W = 5; Rx = 'eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{10,}'; Check = 'Is the token live? What does it grant?' },
    @{ Id = 'URL-CREDS'; Topic = 'Credentials inside URLs'; W = 6; Rx = '[a-z][a-z0-9+.-]*://[^/\s:@"'']+:[^/\s@"'']+@'; Check = 'user:password@host in a URL - real credentials?' },
    @{ Id = 'TLS-TRUST'; Topic = 'Certificate / hostname validation'; W = 5; Rx = '(?i)(TrustAllCerts|trustAllCerts|X509TrustManager|checkServerTrusted|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier|HostnameVerifier|badCertificateCallback|rejectUnauthorized\s*[:=]\s*false|verify\s*=\s*False|NSAllowsArbitraryLoads|setSslSocketFactory|SSLSocketFactory)'; Check = 'Is certificate or hostname validation disabled, or can it be switched off (debug flag, build property, remote config)?' },
    @{ Id = 'PINNING'; Topic = 'SSL pinning implementation'; W = 2; Rx = '(?i)(CertificatePinner|certificate_?pinning|ssl_?pinning|TrustKit|pin-set|sha256/|network_security_config|SecurityContext)'; Check = 'How is pinning done, is it enabled for every build, and is there a bypass switch?' },
    @{ Id = 'CLEARTEXT'; Topic = 'Clear-text (http) traffic'; W = 3; Rx = '(?i)(usesCleartextTraffic|cleartextTrafficPermitted\s*=\s*["'']?true|["'']http://(?!localhost|127\.|10\.0\.2\.2|0\.0\.0\.0|schemas\.|www\.w3\.org|xmlns|ns\.adobe|maven\.apache))'; Check = 'Which hosts are reached over plain http? Is it limited to debug builds?' },
    @{ Id = 'WEBVIEW'; Topic = 'WebView / embedded browser'; W = 4; Rx = '(?i)(setJavaScriptEnabled\s*\(\s*true|addJavascriptInterface|setAllowFileAccess\s*\(\s*true|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs|evaluateJavascript|InAppWebView|WebViewController|javascriptMode|WKWebView)'; Check = 'What URLs are loaded? Is JavaScript enabled, is file access allowed, are JS bridges exposed to untrusted content?' },
    @{ Id = 'WEAK-CRYPTO'; Topic = 'Weak crypto algorithms'; W = 4; Rx = '(?i)(MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"|Cipher\.getInstance\(\s*"(DES|DESede|RC4|AES)(/ECB[^"]*)?"\s*\)|AES/ECB|\bmd5\s*\(|\bsha1\s*\(|\bRC4\b)'; Check = 'What is protected with it? MD5/SHA-1/DES/ECB for passwords or integrity is a finding.' },
    @{ Id = 'STATIC-KEY'; Topic = 'Static IV / hard-coded key material'; W = 5; Rx = '(?i)(IvParameterSpec\s*\(\s*(new\s+byte\s*\[|"[^"]+"\.getBytes)|SecretKeySpec\s*\(\s*"[^"]+"\.getBytes|Key\.fromUtf8\(|IV\.fromUtf8\()'; Check = 'Is the key or IV a constant in the code?' },
    @{ Id = 'WEAK-RANDOM'; Topic = 'Non-cryptographic random'; W = 2; Rx = '(\bnew\s+Random\s*\(|Math\.random\s*\(|java\.util\.Random|\bRandom\(\))'; Check = 'Used for tokens, OTPs, IDs an attacker could guess? Or only for UI / map keys?' },
    @{ Id = 'SQL-RAW'; Topic = 'Raw SQL / injection'; W = 4; Rx = '(?i)(rawQuery\s*\(|execSQL\s*\(|"\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+|\.sql\(\s*f["'']|\.execute\(\s*f["'']|\.execute\([^)]*["'']\s*%\s|\.execute\([^)]*\.format\()'; Check = 'Is user input concatenated or formatted into the query (string concatenation, f-strings, % or .format)?' },
    @{ Id = 'STORE-PREFS'; Topic = 'Plain preferences / defaults storage'; W = 3; Rx = '(?i)(getSharedPreferences|SharedPreferences|MODE_WORLD_(READABLE|WRITEABLE)|NSUserDefaults|UserDefaults\.|shared_preferences|AsyncStorage|localStorage)'; Check = 'Are tokens, PINs or personal data stored here in clear text?' },
    @{ Id = 'STORE-SECURE'; Topic = 'Secure storage (how secrets are kept)'; W = 1; Rx = '(?i)(EncryptedSharedPreferences|flutter_secure_storage|FlutterSecureStorage|AndroidKeyStore|SecItemAdd|kSecAttr|MasterKey|SQLCipher)'; Check = 'Good sign - check what goes in, key handling, and fallbacks to plain storage.' },
    @{ Id = 'STORE-DB'; Topic = 'Local database'; W = 2; Rx = '(?i)(SQLiteDatabase|@Entity\b|@Dao\b|RoomDatabase|sqflite|openDatabase\s*\(|Hive\.|Isar\.|Realm\(|ObjectBox|package:drift)'; Check = 'What is stored, is the database encrypted, can it be backed up or read by other apps?' },
    @{ Id = 'STORE-FILE'; Topic = 'File / external storage'; W = 3; Rx = '(?i)(getExternalStorage|getExternalFilesDir|WRITE_EXTERNAL_STORAGE|openFileOutput|MODE_WORLD|path_provider|getApplicationDocumentsDirectory|getTemporaryDirectory|Environment\.DIRECTORY)'; Check = 'Are sensitive files written to shared or external storage?' },
    @{ Id = 'LOGGING'; Topic = 'Logging (sensitive data in logs?)'; W = 1; Rx = '(?i)(\bLog\.[dvie]\s*\(|printStackTrace\s*\(|debugPrint\s*\(|NSLog\s*\(|console\.log\s*\(|\bprint\s*\(|\bTimber\.)'; Check = 'Do log calls include tokens, PII, request or response bodies?' },
    @{ Id = 'LOG-NETWORK'; Topic = 'Network traffic logging'; W = 3; Rx = '(?i)(HttpLoggingInterceptor|LogInterceptor|Level\.BODY|requestBody\s*:\s*true|responseBody\s*:\s*true|logPrint)'; Check = 'Is body/header logging active in release builds?' },
    @{ Id = 'IPC'; Topic = 'IPC: intents, receivers, providers, channels'; W = 3; Rx = '(?i)(PendingIntent|registerReceiver|sendBroadcast|ContentProvider|FileProvider|getIntent\s*\(\)|onNewIntent|MethodChannel|EventChannel|BroadcastReceiver|startActivityForResult|Intent\.parseUri|android:exported\s*=\s*"true")'; Check = 'What data enters through intents / channels, and is it validated? Exported components without permission?' },
    @{ Id = 'DEEPLINK'; Topic = 'Deep links / URL schemes'; W = 3; Rx = '(?i)(android:scheme|app_links|uni_links|onGenerateRoute|handleDeepLink|getInitialLink|FirebaseDynamicLinks|dynamic_links|dynamiclinks|CFBundleURLSchemes|continue userActivity)'; Check = 'What can a crafted link trigger (navigation, login, payments, WebView URLs)?' },
    @{ Id = 'AUTH-TOKEN'; Topic = 'Authentication / session tokens'; W = 2; Rx = '(?i)(Authorization|Bearer\s|OAuth|refresh_?token|access_?token|id_?token|session_?id|\bjwt\b|X-Auth)'; Check = 'Where are tokens stored, refreshed, and invalidated on logout?' },
    @{ Id = 'BIOMETRIC-PIN'; Topic = 'Biometric / PIN / OTP'; W = 2; Rx = '(?i)(BiometricPrompt|local_auth|LAContext|FingerprintManager|authenticateWithBiometrics|passcode|\bPIN\b|\botp\b)'; Check = 'Is the check enforced server-side or only on the client? Can it be bypassed with a flag?' },
    @{ Id = 'TAMPER'; Topic = 'Root / tamper / screen protection'; W = 2; Rx = '(?i)(RootBeer|isRooted|jailbreak|jailbroken|SafetyNet|PlayIntegrity|IntegrityManager|isDeviceRooted|isDebuggerConnected|FLAG_SECURE|setSecure|freeRASP|talsec|dexguard)'; Check = 'Is detection present, enforced, and hard to bypass? Is FLAG_SECURE set on sensitive screens?' },
    @{ Id = 'DEBUG-FLAGS'; Topic = 'Debug flags and switches'; W = 3; Rx = '(?i)(android:debuggable|isDebuggable|BuildConfig\.DEBUG|kDebugMode|kReleaseMode|DEBUG\s*=\s*true|setWebContentsDebuggingEnabled|disableSSLPinning|SSL_PINNING)'; Check = 'What changes behind these flags and can a release build end up with them on?' },
    @{ Id = 'PERMISSIONS'; Topic = 'Sensitive Android permissions / backup'; W = 2; Rx = '(?i)(allowBackup|requestLegacyExternalStorage|READ_SMS|RECEIVE_SMS|READ_CONTACTS|READ_PHONE_STATE|ACCESS_FINE_LOCATION|RECORD_AUDIO|CALL_PHONE|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|MANAGE_EXTERNAL_STORAGE)'; Check = 'Is each permission justified? Is backup disabled?' },
    @{ Id = 'DYNAMIC-CODE'; Topic = 'Dynamic code / unsafe deserialization / XSS sinks'; W = 4; Rx = '(?i)(DexClassLoader|PathClassLoader|Class\.forName|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|System\.loadLibrary|\beval\s*\(|new\s+Function\s*\(|innerHTML|document\.write|dangerouslySetInnerHTML|ObjectInputStream|readObject\s*\()'; Check = 'Can attacker-controlled data reach these calls?' },
    @{ Id = 'CLIPBOARD'; Topic = 'Clipboard / screenshots'; W = 2; Rx = '(?i)(ClipboardManager|Clipboard\.setData|FlutterClipboard|setRecentsScreenshotEnabled|UIPasteboard)'; Check = 'Is sensitive data (OTP, account numbers, tokens) copied to the clipboard?' },
    @{ Id = 'THIRD-PARTY-SDK'; Topic = 'Analytics / third-party SDKs'; W = 2; Rx = '(?i)(FirebaseAnalytics|Crashlytics|Mixpanel|Sentry|Amplitude|AppsFlyer|CleverTap|MoEngage|WebEngage|facebook_app_events|Adjust\.|Branch\.)'; Check = 'What user or financial data is sent to these services?' },
    @{ Id = 'PII-FIN'; Topic = 'Personal / financial data handling'; W = 3; Rx = '(?i)(aadhaar|aadhar|\bpan[_ ]?(card|number|no)\b|\bifsc\b|account[_ ]?(number|no)\b|card[_ ]?number|\bcvv\b|\bkyc\b|date[_ ]?of[_ ]?birth|\bdob\b|mobile[_ ]?number)'; Check = 'How are these fields masked, stored, logged and transmitted?' },
    @{ Id = 'CRYPTO-USE'; Topic = 'Where crypto is implemented'; W = 2; Rx = '(?i)(Cipher\.getInstance|javax\.crypto|pointycastle|package:encrypt|CryptoKit|CommonCrypto|PBKDF2|bcrypt|argon2|\bHMAC\b)'; Check = 'Review algorithm, mode, key source, IV/nonce handling and error handling.' },
    @{ Id = 'HTTP-CLIENT'; Topic = 'HTTP client configuration'; W = 2; Rx = '(?i)(addInterceptor|OkHttpClient|Retrofit\.Builder|\bDio\s*\(|HttpClient\s*\(|URLSession|Alamofire|connectTimeout)'; Check = 'Interceptors, timeouts, certificate config, header handling, error handling.' },
    @{ Id = 'TODO-HACK'; Topic = 'TODO / hack / test-only code'; W = 1; Rx = '(?i)(\bTODO\b|\bFIXME\b|\bHACK\b|for testing|test only|remove before|temporary)'; Check = 'Shortcuts left in security-relevant code.' }
)

# --- architecture signals (what the project is built with) ------------------------------------
$ArchSignals = @(
    @{ G = 'Dependency injection'; L = 'Hilt'; Rx = '(@HiltAndroidApp|@AndroidEntryPoint|@InstallIn\b|@HiltViewModel)' },
    @{ G = 'Dependency injection'; L = 'Dagger'; Rx = '(@Component\b|@Module\b|@Provides\b|@Binds\b|DaggerAppComponent|dagger\.android)' },
    @{ G = 'Dependency injection'; L = 'Koin'; Rx = '(startKoin|koinViewModel|org\.koin|by\s+inject\s*\(|\bmodule\s*\{)' },
    @{ G = 'Dependency injection'; L = 'get_it (service locator)'; Rx = '(GetIt\.|package:get_it|getIt\.register|getIt<)' },
    @{ G = 'Dependency injection'; L = 'injectable'; Rx = '(@injectable|@lazySingleton|@singleton\b|configureDependencies)' },
    @{ G = 'Dependency injection'; L = 'Provider (Flutter)'; Rx = '(ChangeNotifierProvider|MultiProvider|Provider\.of|context\.read<|context\.watch<)' },
    @{ G = 'Dependency injection'; L = 'Riverpod'; Rx = '(flutter_riverpod|ProviderScope|StateNotifierProvider|ConsumerWidget|ref\.watch)' },
    @{ G = 'Dependency injection'; L = 'RepositoryProvider / BlocProvider'; Rx = '(RepositoryProvider|MultiBlocProvider|BlocProvider)' },
    @{ G = 'Dependency injection'; L = 'Spring annotations'; Rx = '(@Autowired|@RestController|@Service\b|@Repository\b|@Configuration\b|@Bean\b)' },
    @{ G = 'Dependency injection'; L = 'Swinject'; Rx = '(Swinject|Container\(\)\.register)' },
    @{ G = 'Dependency injection'; L = 'Hand-written locator / provider'; Rx = '(ServiceLocator|DependencyProvider|AppContainer|ServiceRegistry)' },
    @{ G = 'Persistence'; L = 'Room'; Rx = '(@Entity\b|@Dao\b|RoomDatabase|androidx\.room)' },
    @{ G = 'Persistence'; L = 'SQLDelight'; Rx = '(sqldelight|app\.cash\.sqldelight)' },
    @{ G = 'Persistence'; L = 'sqflite / drift'; Rx = '(package:sqflite|package:drift|openDatabase\s*\()' },
    @{ G = 'Persistence'; L = 'Hive / Isar / Realm / ObjectBox'; Rx = '(package:hive|Hive\.init|package:isar|Realm\(|io\.realm|ObjectBox)' },
    @{ G = 'Persistence'; L = 'SharedPreferences / UserDefaults'; Rx = '(SharedPreferences|getSharedPreferences|NSUserDefaults|UserDefaults\.|shared_preferences)' },
    @{ G = 'Persistence'; L = 'DataStore'; Rx = '(androidx\.datastore|DataStore<)' },
    @{ G = 'Persistence'; L = 'Encrypted / secure storage'; Rx = '(EncryptedSharedPreferences|flutter_secure_storage|FlutterSecureStorage|AndroidKeyStore|SecItemAdd|Keychain)' },
    @{ G = 'Networking'; L = 'Retrofit'; Rx = '(retrofit2|@GET\(|@POST\(|@PUT\(|@DELETE\()' },
    @{ G = 'Networking'; L = 'OkHttp'; Rx = '(okhttp3|OkHttpClient)' },
    @{ G = 'Networking'; L = 'Ktor'; Rx = '(io\.ktor)' },
    @{ G = 'Networking'; L = 'Dio'; Rx = '(package:dio/|\bDio\s*\()' },
    @{ G = 'Networking'; L = 'Dart http package'; Rx = '(package:http/)' },
    @{ G = 'Networking'; L = 'gRPC / protobuf'; Rx = '(io\.grpc|package:grpc|ManagedChannel|GrpcChannel|\.proto\b)' },
    @{ G = 'Networking'; L = 'GraphQL'; Rx = '(apollographql|graphql_flutter|package:gql)' },
    @{ G = 'Networking'; L = 'WebSocket'; Rx = '(WebSocketChannel|WebSocket\(|socket\.io|OkHttp.*WebSocket)' },
    @{ G = 'Networking'; L = 'URLSession / Alamofire'; Rx = '(URLSession|Alamofire)' },
    @{ G = 'Serialization'; L = 'Gson'; Rx = '(com\.google\.gson|\bGson\()' },
    @{ G = 'Serialization'; L = 'Moshi'; Rx = '(com\.squareup\.moshi)' },
    @{ G = 'Serialization'; L = 'kotlinx.serialization'; Rx = '(kotlinx\.serialization|@Serializable)' },
    @{ G = 'Serialization'; L = 'json_serializable / freezed'; Rx = '(json_serializable|@JsonSerializable|@freezed)' },
    @{ G = 'App architecture'; L = 'MVVM (ViewModel / LiveData / Flow)'; Rx = '(androidx\.lifecycle|LiveData|MutableStateFlow|StateFlow|@HiltViewModel|extends\s+ViewModel)' },
    @{ G = 'App architecture'; L = 'BLoC / Cubit'; Rx = '(flutter_bloc|extends\s+(Bloc|Cubit)<|BlocBuilder)' },
    @{ G = 'App architecture'; L = 'Jetpack Compose'; Rx = '(@Composable|setContent\s*\{)' },
    @{ G = 'App architecture'; L = 'Navigation / routing'; Rx = '(NavHost|NavController|GoRouter|Navigator\.push|onGenerateRoute|AutoRoute|findNavController)' },
    @{ G = 'App architecture'; L = 'Coroutines / Rx'; Rx = '(kotlinx\.coroutines|suspend\s+fun|io\.reactivex|package:rxdart)' },
    @{ G = 'Cross-platform bridges'; L = 'Capacitor'; Rx = '(@capacitor/|CapacitorPlugin|Capacitor\.Plugins|com\.getcapacitor)' },
    @{ G = 'Cross-platform bridges'; L = 'Cordova'; Rx = '(CordovaPlugin|cordova\.exec|org\.apache\.cordova)' },
    @{ G = 'Cross-platform bridges'; L = 'Flutter platform channels'; Rx = '(MethodChannel|EventChannel|FlutterPlugin)' },
    @{ G = 'Cross-platform bridges'; L = 'React Native'; Rx = '(react-native|NativeModules|ReactContextBaseJavaModule)' }
)

# --- folder-layer heuristics on the relative path (lower-case, "/" separators) ---------------
$LayerRules = @(
    @{ L = 'repository'; Rx = 'repositor|(^|/)repos?(/|$)|_repo\.|repo\.(dart|kt|java|swift|ts)$' },
    @{ L = 'data source / DAO / database'; Rx = 'datasource|data_source|(^|/)dao(s)?(/|$)|dao\.(kt|java)$|(^|/)(db|database|storage|persistence|local)(/|$)' },
    @{ L = 'remote API / network'; Rx = '(^|/)(api|apis|network|networking|remote|http|retrofit|grpc|rest)(/|$)|api_?(client|service)|interceptor' },
    @{ L = 'service'; Rx = '(^|/)services?(/|$)|[a-z_]service\.(dart|kt|java|swift|ts|js|py)$' },
    @{ L = 'model / DTO / domain'; Rx = '(^|/)(model|models|entity|entities|dto|dtos|domain|schema|schemas)(/|$)|_model\.|model\.(dart|kt|java)$' },
    @{ L = 'use case / interactor'; Rx = 'usecase|use_case|interactor' },
    @{ L = 'state / view model'; Rx = 'bloc|cubit|viewmodel|view_model|(^|/)(providers?|stores?|redux|mobx|state)(/|$)|notifier' },
    @{ L = 'UI / screens'; Rx = '(^|/)(ui|views?|screens?|pages?|widgets?|components?|presentation|activity|activities|fragments?|compose|layouts?)(/|$)' },
    @{ L = 'dependency injection'; Rx = '(^|/)(di|injection|inject|injector|service_locator|locator|dependencyprovider|container)(/|\.|_|$)|(^|/)modules?(/|$)|appmodule|servicelocator' },
    @{ L = 'auth / security / crypto'; Rx = 'auth|login|logout|token|session|crypto|encrypt|security|biometric|keystore|keychain|password|otp|credential|oauth|kyc' },
    @{ L = 'configuration / flavors'; Rx = '(^|/)(config|configs|configuration|env|flavors?|constants|settings)(/|\.|_|$)|\.env|build\.gradle|gradle\.properties|\.properties$|google-services|googleservice-info' },
    @{ L = 'navigation / deep links'; Rx = 'router|routes?(/|\.|_)|navigation|navigator|deeplink|deep_link' },
    @{ L = 'utilities / core'; Rx = '(^|/)(utils?|helpers?|common|core|shared|extensions?)(/|$)' },
    @{ L = 'native bridge / plugin'; Rx = 'method_?channel|platform_?channel|bridge|(^|/)plugins?(/|$)' }
)

# --- files that deserve a manual look whatever their score ------------------------------------
$SpecialFiles = @(
    @{ Rx = '(^|/)androidmanifest\.xml$'; Why = 'Permissions, exported components, backup / debuggable / cleartext flags, deep links.' },
    @{ Rx = '(^|/)(settings|build)\.gradle(\.kts)?$'; Why = 'Modules, flavors, signing, minify/obfuscation, build switches, dependencies.' },
    @{ Rx = '(^|/)(gradle|local)\.properties$'; Why = 'Credentials, tokens, repository passwords, SDK paths.' },
    @{ Rx = 'network_security_config.*\.xml$'; Why = 'Pinning, user CAs, clear-text policy.' },
    @{ Rx = '(^|/)google-services\.json$|googleservice-info\.plist$'; Why = 'Firebase / Google API keys and project IDs.' },
    @{ Rx = 'proguard.*\.pro$|dexguard.*\.(pro|cfg)$'; Why = 'Obfuscation and keep rules.' },
    @{ Rx = '(^|/)info\.plist$'; Why = 'ATS exceptions, URL schemes, usage descriptions.' },
    @{ Rx = '\.entitlements$'; Why = 'iOS capabilities.' },
    @{ Rx = '(^|/)(mainactivity|appdelegate|sceneDelegate)\.(kt|java|swift|m)$|[a-z]*application\.(kt|java)$'; Why = 'Entry points and app start-up / SDK initialisation.' },
    @{ Rx = '(^|/)main\.dart$|(^|/)index\.(js|ts|tsx)$|(^|/)app\.(tsx|jsx|js|ts)$'; Why = 'Application entry point.' },
    @{ Rx = '(^|/)(pubspec\.yaml|package\.json|podfile|pom\.xml|requirements\.txt|pyproject\.toml|go\.mod|composer\.json|cargo\.toml)$'; Why = 'Dependency list (outdated or risky libraries).' },
    @{ Rx = '(^|/)capacitor\.config\.(json|ts|js)$|(^|/)config\.xml$'; Why = 'Capacitor / Cordova configuration: allowed navigation, cleartext, plugins.' },
    @{ Rx = '(^|/)dockerfile$|(^|/)jenkinsfile$|\.github/workflows/|bitrise\.yml$|codemagic\.yaml$|\.gitlab-ci\.yml$|azure-pipelines\.yml$|fastfile$'; Why = 'CI/CD and release automation: secrets, signing, build switches.' },
    @{ Rx = '(^|/)\.env(\..*)?$'; Why = 'Environment variables and secrets.' }
)

$SensitiveRx = '(\.(jks|keystore|p12|pfx|pem|key|cer|crt|der|mobileprovision|p8|sqlite|sqlite3|db|bak|old|sql|apk|aab|ipa)$)|(^|/)(\.env(\..*)?|id_rsa|id_dsa|.*credentials.*|.*secrets?\..*|serviceaccount.*\.json|google-services\.json|googleservice-info\.plist|local\.properties|gradle\.properties|\.npmrc|\.netrc|\.htpasswd)$'

# validate every regex once so a typo fails loudly, not silently
foreach ($p in $SecPatterns) { try { [void][regex]::IsMatch('x', $p.Rx) } catch { throw "Bad regex in pattern $($p.Id): $($_.Exception.Message)" } }
foreach ($p in $ArchSignals) { try { [void][regex]::IsMatch('x', "(?i)$($p.Rx)") } catch { throw "Bad regex in signal $($p.L): $($_.Exception.Message)" } }

# ======================================================================
# HELPERS
# ======================================================================
# Topics whose matches may contain real secrets: every quoted value in their sample lines is masked.
$MaskIds = @('SECRET-LIT', 'KEY-GOOGLE', 'KEY-AWS', 'PRIVATE-KEY', 'JWT-LIT', 'URL-CREDS', 'STATIC-KEY')

# Token-shaped values (cloud keys, JWTs, user:password@) are masked everywhere.
function Hide-Tokens([string]$s) {
    if (-not $s) { return '' }
    $t = [regex]::Replace($s, '(AKIA[0-9A-Z]{2}|AIza[0-9A-Za-z_\-]{4}|eyJ[A-Za-z0-9_\-]{4})[A-Za-z0-9_\-\.]+', '$1***')
    $t = [regex]::Replace($t, '(?i)((password|passwd|pwd|secret|token|api[_-]?key|apikey|auth[a-z_]*)["'']?\s*[:=]\s*["''])([^"'']{0,3})[^"'']*', '$1$3***')
    return [regex]::Replace($t, '://[^/\s:@]+:[^/\s@]+@', '://***:***@')
}

# Secret-type topics additionally keep only the first 3 characters of each quoted value.
function Get-Sample([string]$line, [bool]$maskQuoted) {
    $t = Hide-Tokens $line.Trim()
    if ($maskQuoted) { $t = [regex]::Replace($t, '(["''])([^"'']{3})[^"'']{3,}(["''])', '$1$2***$3') }
    if ($t.Length -gt 110) { $t = $t.Substring(0, 110) + '...' }
    return $t
}

function Get-HitLines($lines, [string]$rx, [int]$max) {
    $out = @()
    for ($k = 0; $k -lt $lines.Count -and $out.Count -lt $max; $k++) {
        $ln = $lines[$k]
        if ([regex]::IsMatch($ln, $rx)) {
            # minified files have one huge line: keep only the text around the match
            if ($ln.Length -gt 300) {
                $mi = [regex]::Match($ln, $rx).Index - 50
                if ($mi -lt 0) { $mi = 0 }
                $take = $ln.Length - $mi
                if ($take -gt 200) { $take = 200 }
                $ln = $ln.Substring($mi, $take)
                # never start or end inside a token (it could be the tail or head of a key)
                $ln = '...' + [regex]::Replace([regex]::Replace($ln, '^[A-Za-z0-9_\-\.]+', ''), '[A-Za-z0-9_\-\.]+$', '') + '...'
            }
            $out += @{ N = ($k + 1); T = $ln }
        }
    }
    return $out
}

function Get-Kind([string]$name, [string]$ext, [string]$relLower) {
    if ($relLower -match '(^|/)androidmanifest\.xml$|network_security_config|(^|/)(settings|build)\.gradle|(^|/)(pubspec\.yaml|package\.json|podfile)$') { return 'Config/Build' }
    if ($srcExt.ContainsKey($ext)) { return 'Source' }
    if ($ext -eq '.xml' -and $relLower -match '/res/') { return 'Resource' }
    if ($cfgExt.ContainsKey($ext)) { return 'Config' }
    if ($docExt.ContainsKey($ext)) { return 'Doc' }
    if ($binExt.ContainsKey($ext)) { return 'Binary' }
    if ($resExt.ContainsKey($ext)) { return 'Resource' }
    return 'Other'
}

$script:ExcludedDirs = @{}
function Get-Tree([string]$dir) {
    $items = Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue
    foreach ($it in $items) {
        if ($it.PSIsContainer) {
            if ("$($it.Attributes)" -match 'ReparsePoint') { continue }
            if ($exclSet.ContainsKey($it.Name.ToLower())) { $script:ExcludedDirs[$it.FullName.Substring($rootLen)] = 1; continue }
            Get-Tree $it.FullName
        }
        else { $it }
    }
}

function Join-Examples($paths, [int]$n) {
    $list = @($paths | Select-Object -First $n)
    return ($list -join ', ')
}

# ======================================================================
# 1. WALK THE TREE
# ======================================================================
try {
    $rootPath = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
}
catch { Write-Host "[ERROR] Root folder not found: $Root" -ForegroundColor Red; exit 1 }
# Length of the folder prefix as Windows reports it in item paths. Measured from a real entry,
# because a root typed as a short (8.3) or differently-cased path can differ in length from FullName.
$probe = Get-ChildItem -LiteralPath $rootPath -Force -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $probe) { Write-Host '[!] The folder is empty.'; exit 0 }
$rootLen = $probe.FullName.Length - $probe.Name.Length
if (-not $OutputDir) { $OutputDir = Join-Path $rootPath 'recon-output' }
if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

Write-Host ''
Write-Host ('=' * 64)
Write-Host '  Project recon'
Write-Host "  Root   : $rootPath"
Write-Host "  Output : $OutputDir"
Write-Host ('=' * 64)
Write-Host '[*] Listing files ...'
$all = @(Get-Tree $rootPath)
$total = $all.Count
Write-Host "    -> $total files ($($script:ExcludedDirs.Count) folders skipped: build output, dependencies, VCS)"
if ($total -eq 0) { Write-Host '[!] Nothing to scan.'; exit 0 }

# ======================================================================
# 2. INVENTORY + CONTENT SCAN (each file is read once)
# ======================================================================
$MaxBytes = [int]($MaxFileMB * 1MB)
$hitMap = @{}          # rel path -> hits
$topicFiles = @{}      # pattern id -> list of @{Path;Lines;Sample;Third}
$sigFiles = @{}        # arch signal label -> list of paths
$manifests = @(); $gradleFiles = @(); $settingsFiles = @(); $pubspecs = @(); $pkgJsons = @()
$skippedLarge = 0; $scanned = 0; $n = 0
$webBundles = @(); $webMaps = @(); $bundleMapRefs = 0; $bundleHosts = @{}; $bundleFeat = @{}
$BundleFeatures = @(
    @{ L = 'localStorage / sessionStorage'; Rx = '(localStorage|sessionStorage)\.(setItem|getItem)' },
    @{ L = 'document.cookie'; Rx = 'document\.cookie' },
    @{ L = 'v-html / innerHTML (XSS sink)'; Rx = 'v-html|innerHTML|insertAdjacentHTML' },
    @{ L = 'eval / new Function'; Rx = '\beval\(|new Function\(' },
    @{ L = 'postMessage'; Rx = 'postMessage\(' },
    @{ L = 'Authorization header / Bearer'; Rx = 'Authorization|Bearer ' },
    @{ L = 'console.log left in'; Rx = 'console\.(log|debug)\(' },
    @{ L = 'window.open / location.href'; Rx = 'window\.open\(|location\.href\s*=' }
)

Write-Host '[*] Classifying files and scanning content ...'
$records = foreach ($f in $all) {
    $n++
    if (($n % 1000) -eq 0) { Write-Host ("    {0}/{1}" -f $n, $total) }
    $rel = $f.FullName.Substring($rootLen)
    $relLower = $rel.ToLower().Replace('\', '/')
    $ext = $f.Extension.ToLower()
    $nameLower = $f.Name.ToLower()
    $third = [regex]::IsMatch($relLower, $ThirdPartyRx)
    $isBundle = [regex]::IsMatch($relLower, $BundleRx)
    $gen = $isBundle -or [regex]::IsMatch($relLower, $GeneratedRx)
    if ($nameLower -match '\.(js|css)\.map$') { $webMaps += $rel }
    $isTest = [regex]::IsMatch($relLower, $TestRx)
    $kind = Get-Kind $f.Name $ext $relLower
    $isText = $TextExt.ContainsKey($ext) -or $TextNames.ContainsKey($nameLower)

    $layers = @()
    if ($kind -in 'Source', 'Config', 'Config/Build') {
        foreach ($lr in $LayerRules) { if ([regex]::IsMatch($relLower, $lr.Rx)) { $layers += $lr.L } }
    }

    $lineCount = 0
    $flags = @()
    $score = 0.0
    $note = ''
    $text = $null

    if ($isText -and -not $NoContentScan) {
        $limit = $MaxBytes
        if ($isBundle -and $ext -eq '.js') { $limit = 8MB }
        if ($f.Length -gt $limit) { $skippedLarge++; $note = 'large file not read' }
        elseif ($f.Length -gt 0 -and -not ($relLower -match 'recon-output')) {
            $text = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
        }
    }

    if ($text) {
        $scanned++
        $lineCount = ($text.Length - $text.Replace("`n", '').Length) + 1
        $lines = $null

        foreach ($p in $SecPatterns) {
            if ([regex]::IsMatch($text, $p.Rx)) {
                if ($null -eq $lines) { $lines = $text -split "`n" }
                $hl = @(Get-HitLines $lines $p.Rx 3)
                $lineNos = ($hl | ForEach-Object { $_.N }) -join ', '
                $sample = ''
                if ($hl.Count -gt 0) { $sample = Get-Sample $hl[0].T ($MaskIds -contains $p.Id) }
                $flags += $p.Id
                $score += $p.W
                $entry = @{ Path = $rel; Lines = $lineNos; Sample = $sample; Third = ($third -or $gen -or $isTest) }
                if (-not $topicFiles.ContainsKey($p.Id)) { $topicFiles[$p.Id] = @() }
                $topicFiles[$p.Id] += $entry
            }
        }
        foreach ($s in $ArchSignals) {
            if ([regex]::IsMatch($text, "(?i)$($s.Rx)")) {
                $key = "$($s.G)|$($s.L)"
                if (-not $sigFiles.ContainsKey($key)) { $sigFiles[$key] = @() }
                $sigFiles[$key] += $rel
            }
        }
        if ($isBundle -and $ext -eq '.js') {
            $webBundles += $rel
            if ([regex]::IsMatch($text, 'sourceMappingURL=')) { $bundleMapRefs++ }
            foreach ($bf in $BundleFeatures) {
                if ([regex]::IsMatch($text, $bf.Rx)) { $bundleFeat[$bf.L] = 1 + [int]$bundleFeat[$bf.L] }
            }
            foreach ($um in [regex]::Matches($text, 'https?://([A-Za-z0-9\.\-]{4,80})')) {
                $hn = $um.Groups[1].Value.ToLower()
                $bundleHosts[$hn] = 1 + [int]$bundleHosts[$hn]
            }
        }
        if ($nameLower -eq 'androidmanifest.xml') { $manifests += $rel }
        if ($nameLower -eq 'build.gradle' -or $nameLower -eq 'build.gradle.kts') { $gradleFiles += $rel }
        if ($nameLower -eq 'settings.gradle' -or $nameLower -eq 'settings.gradle.kts') { $settingsFiles += $rel }
        if ($nameLower -eq 'pubspec.yaml') { $pubspecs += $rel }
        if ($nameLower -eq 'package.json') { $pkgJsons += $rel }
    }

    # review score: topic weights, a bonus for security-relevant layers, discounts for noise
    if ($layers -contains 'auth / security / crypto') { $score += 2 }
    if ($layers -contains 'data source / DAO / database') { $score += 1 }
    if ($layers -contains 'remote API / network') { $score += 1 }
    if ($layers -contains 'configuration / flavors') { $score += 1 }
    if ($third) { $score = $score * 0.4 }
    if ($gen) { $score = $score * 0.2 }
    if ($isTest) { $score = $score * 0.3 }
    $score = ([int]($score * 10)) / 10

    New-Object PSObject -Property @{
        Path = $rel; Ext = $ext; SizeKB = ([int]($f.Length / 1KB)); Lines = $lineCount; Kind = $kind
        Layers = ($layers -join '; '); ThirdParty = $third; Generated = $gen; Test = $isTest
        Score = $score; Flags = ($flags -join ' '); Note = $note
    }
}
Write-Host "    -> content read for $scanned files; $skippedLarge large files skipped"

# ======================================================================
# 3. DERIVED FACTS
# ======================================================================
$byKind = @($records | Group-Object Kind | Sort-Object Count -Descending)
$byExt = @($records | Group-Object Ext | Sort-Object Count -Descending | Select-Object -First 12)
$totalMB = [int](($records | Measure-Object SizeKB -Sum).Sum / 1024)
$firstParty = @($records | Where-Object { -not $_.ThirdParty -and -not $_.Generated -and -not $_.Test })

# project types, by marker files
$markers = @(
    @{ Rx = '(^|/)pubspec\.yaml$'; T = 'Flutter / Dart' }, @{ Rx = '(^|/)build\.gradle(\.kts)?$'; T = 'Android (Gradle)' },
    @{ Rx = '(^|/)androidmanifest\.xml$'; T = 'Android app / library' }, @{ Rx = '\.xcodeproj/|(^|/)podfile$|(^|/)info\.plist$'; T = 'iOS (Xcode / CocoaPods)' },
    @{ Rx = '(^|/)package\.json$'; T = 'Node / JavaScript' }, @{ Rx = 'capacitor\.config\.'; T = 'Capacitor' },
    @{ Rx = '(^|/)config\.xml$|cordova_plugins|(^|/)plugins/'; T = 'Cordova plugins' }, @{ Rx = '(^|/)pom\.xml$'; T = 'Maven / Java' },
    @{ Rx = '(^|/)(requirements\.txt|pyproject\.toml|setup\.py)$'; T = 'Python' }, @{ Rx = '(^|/)go\.mod$'; T = 'Go' },
    @{ Rx = '(^|/)composer\.json$'; T = 'PHP' }, @{ Rx = '\.csproj$|\.sln$'; T = '.NET' }, @{ Rx = '(^|/)cargo\.toml$'; T = 'Rust' }
)
$types = @()
foreach ($m in $markers) {
    $hit = @($records | Where-Object { [regex]::IsMatch($_.Path.ToLower().Replace('\', '/'), $m.Rx) } | Select-Object -First 3)
    if ($hit.Count -gt 0) { $types += ('{0}  (e.g. {1})' -f $m.T, (($hit | ForEach-Object { $_.Path }) -join ', ')) }
}

# gradle modules (settings.gradle) and which of them live outside the scanned folder
$modules = @(); $externalMods = @(); $insideMods = 0
foreach ($sf in $settingsFiles) {
    $t = Get-Content -LiteralPath (Join-Path $rootPath $sf) -Raw -ErrorAction SilentlyContinue
    if (-not $t) { continue }
    foreach ($m in [regex]::Matches($t, '(?m)^\s*include\s*\(?\s*([^\r\n]+)')) {
        foreach ($q in [regex]::Matches($m.Groups[1].Value, '[''"]:?([^''"]+)[''"]')) { $modules += $q.Groups[1].Value }
    }
    # Where does each module's folder really point? Resolved relative to the settings file, then checked on disk.
    $sdir = Split-Path -Parent (Join-Path $rootPath $sf)
    foreach ($m in [regex]::Matches($t, 'project\(\s*[''"]:?([^''"]+)[''"]\s*\)\.projectDir\s*=\s*(?:new\s+File\([^,]+,\s*)?file\(\s*[''"]([^''"]+)[''"]')) {
        $rp = $m.Groups[2].Value
        $res = Resolve-Path -LiteralPath (Join-Path $sdir $rp.Replace('/', '\')) -ErrorAction SilentlyContinue
        if (-not $res) { $externalMods += ('{0} -> {1}   [NOT FOUND - this code is not in the folder]' -f $m.Groups[1].Value, $rp) }
        elseif (-not $res.Path.StartsWith($rootPath)) { $externalMods += ('{0} -> {1}   [outside this folder - not inventoried]' -f $m.Groups[1].Value, $rp) }
        else { $insideMods++ }
    }
}
$modules = @($modules | Select-Object -Unique)

# gradle facts
$gradleFacts = @()
foreach ($gf in $gradleFiles) {
    $t = Get-Content -LiteralPath (Join-Path $rootPath $gf) -Raw -ErrorAction SilentlyContinue
    if (-not $t) { continue }
    $facts = @()
    foreach ($m in [regex]::Matches($t, '(?i)applicationId\s*=?\s*[''"]([^''"]+)[''"]')) { $facts += "applicationId $($m.Groups[1].Value)" }
    foreach ($m in [regex]::Matches($t, '(?i)\b(minSdk(?:Version)?|targetSdk(?:Version)?|compileSdk(?:Version)?)\s*=?\s*([\w\.]+)')) { $facts += "$($m.Groups[1].Value) $($m.Groups[2].Value)" }
    foreach ($m in [regex]::Matches($t, '(?i)\b(minifyEnabled|isMinifyEnabled|shrinkResources|debuggable|isDebuggable)\s*=?\s*(true|false)')) { $facts += "$($m.Groups[1].Value) $($m.Groups[2].Value)" }
    foreach ($m in [regex]::Matches($t, '(?i)buildConfigField\s*\(?\s*[''"][^''"]+[''"]\s*,\s*[''"]([^''"]+)[''"]\s*,\s*(.{1,90})')) {
        $nm = $m.Groups[1].Value
        $val = $m.Groups[2].Value.Trim()
        if ($nm -match '(?i)key|secret|token|passw|salt|id$') { $val = '***' } else { $val = Hide-Tokens $val }
        $facts += "buildConfigField $nm = $val"
    }
    if ($t -match '(?i)signingConfigs?\s*\{') { $facts += 'signingConfigs block present' }
    if ($t -match '(?i)disableSSLPinning|SSL_PINNING') { $facts += 'SSL pinning switch present (see review topics)' }
    $facts = @($facts | Select-Object -Unique)
    if ($facts.Count -gt 0) { $gradleFacts += @{ File = $gf; Facts = $facts } }
}

# manifest facts
$manifestFacts = @()
foreach ($mf in $manifests) {
    $t = Get-Content -LiteralPath (Join-Path $rootPath $mf) -Raw -ErrorAction SilentlyContinue
    if (-not $t) { continue }
    $perms = @([regex]::Matches($t, '<uses-permission[^>]*android:name="([^"]+)"') | ForEach-Object { $_.Groups[1].Value.Replace('android.permission.', '') })
    $exported = @()
    foreach ($m in [regex]::Matches($t, '<(activity|activity-alias|service|receiver|provider)\b[^>]*>')) {
        $tag = $m.Value
        if ($tag -match 'android:exported="true"') {
            $nm = ''; if ($tag -match 'android:name="([^"]+)"') { $nm = $Matches[1] }
            $exported += "$($m.Groups[1].Value):$nm"
        }
    }
    $flagsM = @()
    foreach ($a in 'allowBackup', 'debuggable', 'usesCleartextTraffic', 'networkSecurityConfig', 'requestLegacyExternalStorage') {
        $mm = [regex]::Match($t, "android:$a=""([^""]+)""")
        if ($mm.Success) { $flagsM += "$a=$($mm.Groups[1].Value)" }
    }
    $schemes = @([regex]::Matches($t, '<data[^>]*android:scheme="([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $manifestFacts += @{ File = $mf; Perms = $perms; Exported = $exported; Flags = $flagsM; Schemes = $schemes }
}

# dependencies from pubspec / package.json
$deps = @()
$notableDart = 'flutter_secure_storage|shared_preferences|webview_flutter|flutter_inappwebview|local_auth|dio|http|sqflite|hive|isar|drift|get_it|injectable|provider|riverpod|flutter_bloc|firebase|mixpanel|sentry|encrypt|pointycastle|permission_handler|url_launcher|flutter_local_notifications|root|jailbreak|safe_device|freerasp|certificate|pinning'
foreach ($ps in $pubspecs) {
    $lines = @(Get-Content -LiteralPath (Join-Path $rootPath $ps) -ErrorAction SilentlyContinue)
    $inDeps = $false; $names = @()
    foreach ($ln in $lines) {
        if ($ln -match '^(dependencies|dev_dependencies):') { $inDeps = ($ln -match '^dependencies:'); continue }
        if ($ln -match '^\S') { $inDeps = $false }
        if ($inDeps -and $ln -match '^  ([A-Za-z0-9_]+):') { $names += $Matches[1] }
    }
    if ($names.Count -gt 0) {
        $notable = @($names | Where-Object { $_ -match $notableDart })
        $deps += @{ File = $ps; Count = $names.Count; Notable = $notable; All = $names }
    }
}
foreach ($pj in $pkgJsons) {
    if ($pj -match 'node_modules') { continue }
    $t = Get-Content -LiteralPath (Join-Path $rootPath $pj) -Raw -ErrorAction SilentlyContinue
    if (-not $t) { continue }
    $m = [regex]::Match($t, '"dependencies"\s*:\s*\{([^}]*)\}')
    if ($m.Success) {
        $names = @([regex]::Matches($m.Groups[1].Value, '"([^"]+)"\s*:') | ForEach-Object { $_.Groups[1].Value })
        if ($names.Count -gt 0) { $deps += @{ File = $pj; Count = $names.Count; Notable = @($names | Where-Object { $_ -match 'capacitor|cordova|firebase|crypto|jwt|axios|express|webview|storage|keychain|secure|auth' }); All = $names } }
    }
}

# layers: counts and examples (first-party only)
$layerStats = @()
foreach ($lr in $LayerRules) {
    $hits = @($firstParty | Where-Object { $_.Layers -like "*$($lr.L)*" })
    if ($hits.Count -gt 0) { $layerStats += @{ L = $lr.L; Count = $hits.Count; Examples = (Join-Examples ($hits | ForEach-Object { $_.Path }) 5) } }
}

# inferred layering: the layers that exist, in the order data normally flows
$flowOrder = @('UI / screens', 'state / view model', 'navigation / deep links', 'use case / interactor', 'repository', 'data source / DAO / database', 'remote API / network', 'service', 'model / DTO / domain')
$flowParts = @()
foreach ($fo in $flowOrder) {
    $ls = @($layerStats | Where-Object { $_.L -eq $fo })
    if ($ls.Count -gt 0) { $flowParts += ('{0} ({1})' -f $fo, $ls[0].Count) }
}
$flowLine = 'none of the usual layers were recognised by folder / file name'
if ($flowParts.Count -gt 0) { $flowLine = $flowParts -join '  ->  ' }
$diNames = @($sigFiles.Keys | Where-Object { $_ -like 'Dependency injection|*' } | ForEach-Object { $_.Split('|')[1] })
$diLine = 'no dependency-injection framework recognised'
if ($diNames.Count -gt 0) { $diLine = $diNames -join ', ' }

# class-name families (Repository, DataSource, Api, UseCase, ...)
$families = @()
$famRx = '(?i)^(.+?)[_]?(Repository|Repo|DataSource|Dao|Api|ApiService|Client|Service|UseCase|Interactor|ViewModel|Bloc|Cubit|Manager|Interceptor|Module|Provider|Store|Controller)\.(kt|java|dart|swift|ts|js|py)$'
$famMap = @{}
foreach ($r in $firstParty) {
    $nm = $r.Path.Substring($r.Path.LastIndexOf('\') + 1)
    $m = [regex]::Match($nm, $famRx)
    if ($m.Success) {
        $fam = $m.Groups[2].Value.ToLower()
        if (-not $famMap.ContainsKey($fam)) { $famMap[$fam] = @() }
        $famMap[$fam] += $r.Path
    }
}
foreach ($k in ($famMap.Keys | Sort-Object)) { $families += @{ Name = $k; Count = $famMap[$k].Count; Examples = (Join-Examples $famMap[$k] 6) } }

# sensitive / unexpected files, special files, entry points
$sensitive = @($records | Where-Object { [regex]::IsMatch($_.Path.ToLower().Replace('\', '/'), $SensitiveRx) -and $_.Path -notmatch 'recon-output' })
$special = @()
foreach ($r in $records) {
    $rl = $r.Path.ToLower().Replace('\', '/')
    if ($r.ThirdParty) { continue }
    foreach ($sp in $SpecialFiles) {
        if ([regex]::IsMatch($rl, $sp.Rx)) { $special += @{ Path = $r.Path; Why = $sp.Why }; break }
    }
}

# top-level folder tree (3 levels) with file counts
$dirCount = @{}
foreach ($r in $records) {
    $parts = $r.Path.Split('\')
    $max = $parts.Count - 1
    if ($max -gt 3) { $max = 3 }
    for ($d = 1; $d -le $max; $d++) { $dirCount[($parts[0..($d - 1)] -join '\')]++ }
}
$purpose = @{
    'android' = 'Android native project (Gradle)'; 'ios' = 'iOS native project (Xcode)'; 'lib' = 'Application source (Dart / Flutter)'; 'src' = 'Source code'
    'app' = 'Application module'; 'packages' = 'Internal / shared packages'; 'modules' = 'Feature modules'; 'libraries' = 'Shared libraries'
    'assets' = 'Static assets'; 'res' = 'Android resources'; 'test' = 'Tests'; 'tests' = 'Tests'; 'docs' = 'Documentation'; 'scripts' = 'Helper scripts'
    'config' = 'Configuration'; 'www' = 'Web assets (Cordova / Capacitor)'; 'public' = 'Web assets'; 'cordova_plugins' = 'Cordova plugin native code'
    'plugins' = 'Plugins'; 'main' = 'Main source set'; 'java' = 'JVM source'; 'kotlin' = 'Kotlin source'; 'runner' = 'iOS runner target'
    'data' = 'Data layer'; 'domain' = 'Domain / business layer'; 'presentation' = 'UI / presentation layer'; 'di' = 'Dependency injection'
    'core' = 'Core / shared code'; 'common' = 'Common code'; 'utils' = 'Utilities'; 'network' = 'Networking'; 'models' = 'Data models'
    'repositories' = 'Repositories'; 'services' = 'Services'; 'widgets' = 'UI widgets'; 'screens' = 'Screens'; 'bloc' = 'State management (BLoC)'
    'features' = 'Feature folders'; 'gradle' = 'Gradle wrapper / config'; 'fastlane' = 'Release automation'; '.github' = 'GitHub config / CI workflows'
    'prod' = 'Production flavor sources'; 'stage' = 'Stage flavor sources'; 'debug' = 'Debug build sources'; 'release' = 'Release build sources'
}

# review targets
$ranked = @($records | Where-Object { $_.Score -ge 3 -and -not $_.Generated } | Sort-Object Score -Descending)
$topics = @()
foreach ($p in ($SecPatterns | Sort-Object { -$_.W })) {
    if ($topicFiles.ContainsKey($p.Id)) {
        $files = @($topicFiles[$p.Id])
        $own = @($files | Where-Object { -not $_.Third })
        $topics += @{ P = $p; Total = $files.Count; Own = $own; Third = ($files.Count - $own.Count) }
    }
}

# ======================================================================
# 4. WRITE THE FILES
# ======================================================================
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm'
$records | Sort-Object Path | Select-Object Path, Kind, Ext, SizeKB, Lines, Layers, ThirdParty, Generated, Test, Score, Flags, Note |
    Export-Csv -LiteralPath (Join-Path $OutputDir 'inventory.csv') -NoTypeInformation -Encoding UTF8
$records | Where-Object { $_.Score -gt 0 } | Sort-Object Score -Descending | Select-Object Score, Path, Flags, Layers, ThirdParty, Test |
    Export-Csv -LiteralPath (Join-Path $OutputDir 'review-targets.csv') -NoTypeInformation -Encoding UTF8

# ---- PASTE-ME.txt -------------------------------------------------------------------------
$o = @()
$o += "PROJECT RECON  -  $stamp"
$o += "Root: $rootPath"
$o += "Files: $total   (read: $scanned, large files skipped: $skippedLarge, size: $totalMB MB, folders skipped: $($script:ExcludedDirs.Count))"
$o += "First-party code files (not third-party / generated / test): $($firstParty.Count)"
$o += ''
$o += '== PROJECT TYPE =='
if ($types.Count -eq 0) { $o += '  (no known marker files found)' }
foreach ($t in $types) { $o += "  - $t" }
if ($modules.Count -gt 0) {
    $o += ''
    $o += "== GRADLE MODULES ($($modules.Count)) =="
    $o += '  ' + ($modules -join ', ')
    if ($externalMods.Count -gt 0) {
        $o += "  Modules whose code is NOT in this folder ($($externalMods.Count) of $($modules.Count); $insideMods are inside): review them separately if they are in scope:"
        foreach ($e in ($externalMods | Select-Object -First 40)) { $o += "    - $e" }
    }
}
foreach ($g in $gradleFacts) {
    $o += ''
    $o += "== BUILD FACTS: $($g.File) =="
    foreach ($f in ($g.Facts | Select-Object -First 30)) { $o += "  - $f" }
}
foreach ($m in $manifestFacts) {
    $o += ''
    $o += "== MANIFEST: $($m.File) =="
    if ($m.Flags.Count -gt 0) { $o += '  flags: ' + ($m.Flags -join ', ') } else { $o += '  flags: (allowBackup / debuggable / cleartext not set here)' }
    if ($m.Perms.Count -gt 0) { $o += "  permissions ($($m.Perms.Count)): " + ($m.Perms -join ', ') }
    if ($m.Exported.Count -gt 0) { $o += "  exported components ($($m.Exported.Count)): " + ($m.Exported -join ', ') }
    if ($m.Schemes.Count -gt 0) { $o += '  URL schemes: ' + ($m.Schemes -join ', ') }
}
if ($webBundles.Count -gt 0 -or $webMaps.Count -gt 0) {
    $bundleDirs = @($webBundles | ForEach-Object { $_.Substring(0, $_.LastIndexOf('\')) } | Group-Object | Sort-Object Count -Descending | Select-Object -First 4)
    $o += ''
    $o += '== BUNDLED WEB APP (compiled / minified JavaScript shipped inside the project) =='
    $o += "  bundle files read: $($webBundles.Count)   with a sourceMappingURL comment: $bundleMapRefs   source map files (.map) present: $($webMaps.Count)"
    foreach ($bd in $bundleDirs) { $o += "  folder: $($bd.Name)  ($($bd.Count) files)" }
    if ($webMaps.Count -gt 0) {
        $o += '  SOURCE MAPS ARE SHIPPED - open one: if it has "sourcesContent" the original source code can be recovered by anyone who unpacks the app:'
        foreach ($mp in ($webMaps | Select-Object -First 5)) { $o += "    - $mp" }
    }
    elseif ($bundleMapRefs -gt 0) { $o += '  bundles reference .map files but none are in this folder (the maps may have been removed - check the built APK too).' }
    foreach ($k in ($bundleFeat.Keys | Sort-Object)) { $o += ('  {0}: found in {1} bundle files' -f $k, $bundleFeat[$k]) }
    $hostList = @($bundleHosts.Keys | Where-Object { $_ -notmatch '^(www\.)?(w3\.org|vuejs\.org|github\.com|reactjs\.org|developer\.mozilla\.org|localhost)$' } | Sort-Object)
    if ($hostList.Count -gt 0) { $o += "  hosts / URLs referenced in the bundles ($($hostList.Count)): " + (($hostList | Select-Object -First 40) -join ', ') }
    $hostLines = @($bundleHosts.Keys | Sort-Object | ForEach-Object { '{0}  ({1} refs)' -f $_, $bundleHosts[$_] })
    Set-Content -LiteralPath (Join-Path $OutputDir 'bundle-hosts.txt') -Value $hostLines -Encoding UTF8
    $o += "  full host list ($($hostLines.Count)) written to bundle-hosts.txt"
    $webSet = @{}
    foreach ($wb in $webBundles) { $webSet[$wb] = 1 }
    $bundleTopics = @()
    foreach ($p in ($SecPatterns | Sort-Object { -$_.W })) {
        if (-not $topicFiles.ContainsKey($p.Id)) { continue }
        $hitsB = @($topicFiles[$p.Id] | Where-Object { $webSet.ContainsKey($_.Path) })
        if ($hitsB.Count -gt 0) { $bundleTopics += @{ P = $p; Hits = $hitsB } }
    }
    if ($bundleTopics.Count -gt 0) {
        $o += '  Chunks worth opening (topic hits inside the bundles; shows the text around the first match):'
        foreach ($bt in ($bundleTopics | Select-Object -First 14)) {
            $o += ('    [{0}] {1}  -  {2} chunks' -f $bt.P.Id, $bt.P.Topic, $bt.Hits.Count)
            foreach ($e in ($bt.Hits | Select-Object -First 4)) {
                $smp = [regex]::Replace($e.Sample, '(["''])([^"'']{3})[^"'']{3,}(["''])', '$1$2***$3')
                $o += ('       {0}   {1}' -f (Split-Path $e.Path -Leaf), $smp)
            }
        }
    }
    $o += '  The application logic of the web app is in these files; review the source (or the .map) rather than the minified text. Topic hits from bundles are counted under third-party / generated.'
}
$o += ''
$o += '== ARCHITECTURE SIGNALS (what the code is built with) =='
$lastG = ''
foreach ($k in ($sigFiles.Keys | Sort-Object)) {
    $g, $l = $k.Split('|')
    if ($g -ne $lastG) { $o += "  [$g]"; $lastG = $g }
    $files = @($sigFiles[$k])
    $o += ('    {0}: {1} files   e.g. {2}' -f $l, $files.Count, (Join-Examples $files 3))
}
if ($sigFiles.Count -eq 0) { $o += '  (none detected)' }
$o += ''
$o += '== INFERRED LAYERING =='
$o += "  data flow: $flowLine"
$o += "  dependency injection: $diLine"
$o += ''
$o += '== LAYERS BY FOLDER / FILE NAME (first-party only) =='
foreach ($l in $layerStats) { $o += ('  {0}: {1} files   e.g. {2}' -f $l.L, $l.Count, $l.Examples) }
$o += ''
$o += '== CLASS FAMILIES =='
foreach ($f in $families) { $o += ('  {0}: {1}   e.g. {2}' -f $f.Name, $f.Count, $f.Examples) }
foreach ($d in $deps) {
    $o += ''
    $o += "== DEPENDENCIES: $($d.File) ($($d.Count)) =="
    $o += '  notable: ' + ($d.Notable -join ', ')
}
$o += ''
$o += '== SENSITIVE / UNEXPECTED FILES IN THE FOLDER =='
if ($sensitive.Count -eq 0) { $o += '  (none)' }
foreach ($s in ($sensitive | Select-Object -First 40)) { $o += "  - $($s.Path)  ($($s.SizeKB) KB)" }
$o += ''
$o += '== ALWAYS REVIEW: configuration, entry points, build and CI files =='
foreach ($s in ($special | Select-Object -First 60)) { $o += ('  {0}   <- {1}' -f $s.Path, $s.Why) }
$o += ''
$o += '== TOPICS TO CHECK MANUALLY (own code first; highest weight first) =='
foreach ($t in $topics) {
    $o += ''
    $o += ('[{0}] {1}  -  {2} files ({3} in third-party / generated / test code)' -f $t.P.Id, $t.P.Topic, $t.Total, $t.Third)
    $o += "   check: $($t.P.Check)"
    foreach ($e in ($t.Own | Select-Object -First 6)) { $o += ('   {0}:{1}   {2}' -f $e.Path, $e.Lines, $e.Sample) }
    if ($t.Own.Count -gt 6) { $o += "   ... and $($t.Own.Count - 6) more own-code files (see review-targets.csv)" }
}
$o += ''
$o += "== TOP $TopN REVIEW TARGETS (score = topic weights, boosted for auth/data/network/config, reduced for third-party/test/generated) =="
$rank = 0
foreach ($r in ($ranked | Select-Object -First $TopN)) {
    $rank++
    $o += ('{0,3}. [{1}] {2}   {3}' -f $rank, $r.Score, $r.Path, $r.Flags)
}
$o += ''
$o += '== FOLDERS SKIPPED =='
foreach ($d in ($script:ExcludedDirs.Keys | Sort-Object | Select-Object -First 40)) { $o += "  - $d" }
$o += ''
$o += 'NOTE: heuristic output. Values that look like secrets are masked. Next: run collect_review_files.ps1 and publish_results.ps1, then upload the UPLOAD folder.'
Set-Content -LiteralPath (Join-Path $OutputDir 'PASTE-ME.txt') -Value $o -Encoding UTF8

# ---- README-ARCHITECTURE.md ----------------------------------------------------------------
$md = @()
$md += '# Project architecture (generated)'
$md += ''
$md += "Generated $stamp from `"$rootPath`" by project_recon.ps1. This is inferred from folder names, file names and text patterns; confirm anything important by reading the code."
$md += ''
$md += '## 1. Overview'
$md += ''
$md += "- Files: $total ($totalMB MB); first-party code files: $($firstParty.Count); folders skipped: $($script:ExcludedDirs.Count)"
$md += '- Detected project types:'
foreach ($t in $types) { $md += "  - $t" }
$md += '- File kinds: ' + (($byKind | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', ')
$md += '- Most common extensions: ' + (($byExt | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', ')
$md += ''
$md += '## 2. Folder structure'
$md += ''
$md += 'Top levels with file counts (folders skipped as build output / dependencies are not counted):'
$md += ''
$md += '```'
foreach ($k in ($dirCount.Keys | Sort-Object)) {
    $depth = $k.Split('\').Count
    $leaf = $k.Substring($k.LastIndexOf('\') + 1)
    $why = ''; if ($purpose.ContainsKey($leaf.ToLower())) { $why = '  - ' + $purpose[$leaf.ToLower()] }
    $md += ('{0}{1}/  ({2} files){3}' -f ('  ' * ($depth - 1)), $leaf, $dirCount[$k], $why)
}
$md += '```'
if ($modules.Count -gt 0) {
    $md += ''
    $md += "## 3. Build modules ($($modules.Count) Gradle modules)"
    $md += ''
    $md += ($modules -join ', ')
    if ($externalMods.Count -gt 0) {
        $md += ''
        $md += "**$($externalMods.Count) of $($modules.Count) modules are not in this folder** ($insideMods are) - their code is not part of this inventory and needs a separate review if it is in scope:"
        $md += ''
        foreach ($e in $externalMods) { $md += "- $e" }
    }
}
$md += ''
$md += '## 4. Layers (by folder / file name)'
$md += ''
$md += "**Inferred layering (top to bottom):** $flowLine"
$md += ''
$md += "**Dependency injection:** $diLine"
$md += ''
$md += 'Where each kind of code appears to live (first-party code only):'
$md += ''
$md += '| Layer | Files | Examples |'
$md += '|---|---|---|'
foreach ($l in $layerStats) { $md += "| $($l.L) | $($l.Count) | $($l.Examples.Replace('|', '/')) |" }
$md += ''
$md += 'Class families by file-name suffix:'
$md += ''
foreach ($f in $families) { $md += "- **$($f.Name)** ($($f.Count)): $($f.Examples)" }
$md += ''
$md += '## 5. How dependencies, data and networking are handled'
$md += ''
foreach ($grp in 'Dependency injection', 'Persistence', 'Networking', 'Serialization', 'App architecture', 'Cross-platform bridges') {
    $md += "### $grp"
    $md += ''
    $any = $false
    foreach ($k in ($sigFiles.Keys | Sort-Object)) {
        $g, $l = $k.Split('|')
        if ($g -eq $grp) { $any = $true; $files = @($sigFiles[$k]); $md += "- **$l** - $($files.Count) files, e.g. $(Join-Examples $files 4)" }
    }
    if (-not $any) { $md += '- (nothing detected)' }
    $md += ''
}
$md += '## 6. Build and security configuration'
$md += ''
foreach ($g in $gradleFacts) {
    $md += "**$($g.File)**"
    $md += ''
    foreach ($f in ($g.Facts | Select-Object -First 40)) { $md += "- $f" }
    $md += ''
}
foreach ($m in $manifestFacts) {
    $md += "**$($m.File)**"
    $md += ''
    if ($m.Flags.Count -gt 0) { $md += '- flags: ' + ($m.Flags -join ', ') }
    if ($m.Perms.Count -gt 0) { $md += '- permissions: ' + ($m.Perms -join ', ') }
    if ($m.Exported.Count -gt 0) { $md += '- exported components: ' + ($m.Exported -join ', ') }
    if ($m.Schemes.Count -gt 0) { $md += '- URL schemes: ' + ($m.Schemes -join ', ') }
    $md += ''
}
if ($webBundles.Count -gt 0 -or $webMaps.Count -gt 0) {
    $md += '**Bundled web app**'
    $md += ''
    $md += "- $($webBundles.Count) compiled JavaScript bundles read; $bundleMapRefs reference a source map; $($webMaps.Count) .map files present"
    foreach ($k in ($bundleFeat.Keys | Sort-Object)) { $md += "- $k : $($bundleFeat[$k]) bundle files" }
    $md += ''
}
$md += '## 7. Third-party libraries'
$md += ''
foreach ($d in $deps) {
    $md += "- **$($d.File)** - $($d.Count) direct dependencies. Notable: $($d.Notable -join ', ')"
}
if ($deps.Count -eq 0) { $md += '- (no pubspec.yaml / package.json found)' }
$md += ''
$md += '## 8. Entry points, configuration and files that should not be here'
$md += ''
foreach ($s in ($special | Select-Object -First 80)) { $md += "- `"$($s.Path)`" - $($s.Why)" }
$md += ''
$md += 'Sensitive or unexpected files present in the folder:'
$md += ''
if ($sensitive.Count -eq 0) { $md += '- (none)' }
foreach ($s in ($sensitive | Select-Object -First 60)) { $md += "- `"$($s.Path)`"" }
$md += ''
$md += '## 9. What to review manually'
$md += ''
$md += 'See `PASTE-ME.txt` (section "TOPICS TO CHECK MANUALLY") and `review-targets.csv` for the ranked file list.'
Set-Content -LiteralPath (Join-Path $OutputDir 'README-ARCHITECTURE.md') -Value $md -Encoding UTF8

# ======================================================================
# 5. CONSOLE SUMMARY
# ======================================================================
$secs = [int]((Get-Date) - $started).TotalSeconds
Write-Host ''
Write-Host "[OK] Done in $secs s"
Write-Host "     $OutputDir\PASTE-ME.txt             <- send this to the reviewer"
Write-Host "     $OutputDir\README-ARCHITECTURE.md   <- how the project is structured"
Write-Host "     $OutputDir\review-targets.csv       <- every file with a score"
Write-Host "     $OutputDir\inventory.csv            <- full file list"
Write-Host ''
Write-Host "Top 10 files to review first:"
$rank = 0
foreach ($r in ($ranked | Select-Object -First 10)) { $rank++; Write-Host ('  {0,2}. [{1}] {2}   {3}' -f $rank, $r.Score, $r.Path, $r.Flags) }
Write-Host ''
