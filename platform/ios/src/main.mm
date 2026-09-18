#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <string>

#include "dynarmic_smoke.hpp"
#include "pvz2_apk_probe.hpp"

extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

namespace {

constexpr unsigned int kCsOpsStatus = 0;
constexpr uint32_t kCsDebugged = 0x10000000u;

bool IsDebugged() {
    uint32_t flags = 0;
    if (csops(getpid(), kCsOpsStatus, &flags, sizeof(flags)) != 0) {
        return false;
    }
    return (flags & kCsDebugged) != 0;
}

bool HasGetTaskAllow() {
    using CreateFn = void *(*)(CFAllocatorRef);
    using CopyFn = CFTypeRef (*)(void *, CFStringRef, CFErrorRef *);

    auto create =
        reinterpret_cast<CreateFn>(
            dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf"));

    auto copy =
        reinterpret_cast<CopyFn>(
            dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement"));

    if (create == nullptr || copy == nullptr) {
        return false;
    }

    void *task = create(kCFAllocatorDefault);
    if (task == nullptr) {
        return false;
    }

    CFTypeRef value =
        copy(
            task,
            CFSTR("get-task-allow"),
            nullptr);

    const bool result =
        value == kCFBooleanTrue;

    if (value != nullptr) {
        CFRelease(value);
    }

    CFRelease(
        reinterpret_cast<CFTypeRef>(task));

    return result;
}

NSString *LogFilePath() {
    NSArray<NSURL *> *urls =
        [[NSFileManager defaultManager]
            URLsForDirectory:NSDocumentDirectory
                   inDomains:NSUserDomainMask];

    NSURL *documents = urls.firstObject;

    return
        [[documents
            URLByAppendingPathComponent:
                @"pvz2forios-probe.log"]
            path];
}

void AppendPersistentLog(NSString *line) {
    NSString *timestamp =
        [[NSDate date]
            descriptionWithLocale:nil];

    NSString *entry =
        [NSString stringWithFormat:
            @"[%@] %@\n",
            timestamp,
            line];

    NSString *path =
        LogFilePath();

    if (![[NSFileManager defaultManager]
            fileExistsAtPath:path]) {

        [entry
            writeToFile:path
              atomically:YES
                encoding:NSUTF8StringEncoding
                   error:nil];
        return;
    }

    NSFileHandle *handle =
        [NSFileHandle
            fileHandleForWritingAtPath:path];

    [handle seekToEndOfFile];

    [handle
        writeData:
            [entry
                dataUsingEncoding:
                    NSUTF8StringEncoding]];

    [handle closeFile];
}

NSString *ReadPersistentLog() {
    NSError *error = nil;

    NSString *text =
        [NSString
            stringWithContentsOfFile:
                LogFilePath()
                         encoding:
                NSUTF8StringEncoding
                            error:
                &error];

    if (text == nil) {
        return @"";
    }

    if (text.length > 32000) {
        return
            [text
                substringFromIndex:
                    text.length - 32000];
    }

    return text;
}

NSString *NSStringFromStd(
    const std::string& value) {

    return
        [NSString
            stringWithUTF8String:
                value.c_str()]
        ?: @"(invalid UTF-8)";
}

} // namespace

@interface ProbeViewController :
    UIViewController
    <UIDocumentPickerDelegate>

@property(nonatomic, strong)
    UILabel *statusLabel;

@property(nonatomic, strong)
    UITextView *logView;

@property(nonatomic, strong)
    UIButton *dynarmicButton;

@property(nonatomic, strong)
    UIButton *jniButton;

@property(nonatomic, assign)
    BOOL dynarmicRunning;

@property(nonatomic, assign)
    BOOL jniRunning;

@property(nonatomic, assign)
    BOOL step1ReadyLogged;

@end

@implementation ProbeViewController

- (UIButton *)makeButton:
        (NSString *)title
    selector:
        (SEL)selector {

    UIButton *button =
        [UIButton
            buttonWithType:
                UIButtonTypeSystem];

    button.translatesAutoresizingMaskIntoConstraints =
        NO;

    [button
        setTitle:title
        forState:UIControlStateNormal];

    button.titleLabel.font =
        [UIFont
            boldSystemFontOfSize:
                17.0];

    button.titleLabel.numberOfLines =
        2;

    button.titleLabel.textAlignment =
        NSTextAlignmentCenter;

    [button
        addTarget:self
           action:selector
 forControlEvents:
        UIControlEventTouchUpInside];

    return button;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor =
        UIColor.systemBackgroundColor;

    self.title =
        @"PvZ2forIOS — Complete Import Probe v13";

    UILabel *title =
        [[UILabel alloc] init];

    title.translatesAutoresizingMaskIntoConstraints =
        NO;

    title.text =
        @"PvZ2forIOS — complete Android import baseline probe v13";

    title.font =
        [UIFont
            boldSystemFontOfSize:
                26.0];

    title.numberOfLines = 0;

    UILabel *explanation =
        [[UILabel alloc] init];

    explanation.translatesAutoresizingMaskIntoConstraints =
        NO;

    explanation.text =
        @"v11.2 proved the complete PvZ2 ARMv7 shared-library startup works on the A14. v12 entered the real Native_GameAppInitialize and reached deep enough to expose Java method registration before stopping on fwrite. "
         @"v13 removes the remaining one-import-at-a-time problem: all verified PvZ2 Android imports now have either a real bridge or a deterministic subsystem fallback. Stdio/POSIX, GLES probe calls, OpenSL availability, time/locale and remaining control-flow imports are classified up front, so the next blockers should be semantic runtime/JNI requirements rather than missing ELF imports.";

    explanation.numberOfLines = 0;

    explanation.font =
        [UIFont
            systemFontOfSize:
                15.0];

    self.statusLabel =
        [[UILabel alloc] init];

    self.statusLabel.translatesAutoresizingMaskIntoConstraints =
        NO;

    self.statusLabel.numberOfLines =
        0;

    self.statusLabel.font =
        [UIFont
            monospacedSystemFontOfSize:
                13.0
            weight:
                UIFontWeightRegular];

    UIButton *enableButton =
        [self
            makeButton:
                @"1. Enable JIT\nwith StikDebug"
            selector:
                @selector(enableJIT)];

    self.dynarmicButton =
        [self
            makeButton:
                @"2. Dynarmic\nARM32 → 42"
            selector:
                @selector(runDynarmic)];

    self.jniButton =
        [self
            makeButton:
                @"3. Run real\nJNI_OnLoad"
            selector:
                @selector(selectApkForJni)];

    UIStackView *mainButtons =
        [[UIStackView alloc]
            initWithArrangedSubviews:
                @[
                    enableButton,
                    self.dynarmicButton,
                    self.jniButton
                ]];

    mainButtons.translatesAutoresizingMaskIntoConstraints =
        NO;

    mainButtons.axis =
        UILayoutConstraintAxisHorizontal;

    mainButtons.spacing = 12.0;

    mainButtons.distribution =
        UIStackViewDistributionFillEqually;

    UIButton *refreshButton =
        [self
            makeButton:
                @"Refresh status"
            selector:
                @selector(refreshStatus)];

    self.logView =
        [[UITextView alloc] init];

    self.logView.translatesAutoresizingMaskIntoConstraints =
        NO;

    self.logView.editable =
        NO;

    self.logView.font =
        [UIFont
            monospacedSystemFontOfSize:
                11.5
            weight:
                UIFontWeightRegular];

    self.logView.layer.borderWidth =
        1.0;

    self.logView.layer.borderColor =
        UIColor.separatorColor.CGColor;

    self.logView.layer.cornerRadius =
        8.0;

    self.logView.text =
        ReadPersistentLog();

    UIStackView *stack =
        [[UIStackView alloc]
            initWithArrangedSubviews:
                @[
                    title,
                    explanation,
                    self.statusLabel,
                    mainButtons,
                    refreshButton,
                    self.logView
                ]];

    stack.translatesAutoresizingMaskIntoConstraints =
        NO;

    stack.axis =
        UILayoutConstraintAxisVertical;

    stack.spacing =
        12.0;

    [self.view addSubview:stack];

    UILayoutGuide *guide =
        self.view.safeAreaLayoutGuide;

    [NSLayoutConstraint
        activateConstraints:
            @[
                [stack.leadingAnchor
                    constraintEqualToAnchor:
                        guide.leadingAnchor
                    constant:
                        24.0],

                [stack.trailingAnchor
                    constraintEqualToAnchor:
                        guide.trailingAnchor
                    constant:
                        -24.0],

                [stack.topAnchor
                    constraintEqualToAnchor:
                        guide.topAnchor
                    constant:
                        16.0],

                [stack.bottomAnchor
                    constraintEqualToAnchor:
                        guide.bottomAnchor
                    constant:
                        -16.0],

                [mainButtons.heightAnchor
                    constraintEqualToConstant:
                        62.0],

                [refreshButton.heightAnchor
                    constraintEqualToConstant:
                        38.0],

                [self.logView.heightAnchor
                    constraintGreaterThanOrEqualToConstant:
                        290.0],
            ]];

    [[NSNotificationCenter defaultCenter]
        addObserver:self
           selector:@selector(refreshStatus)
               name:UIApplicationDidBecomeActiveNotification
             object:nil];

    [self
        appendUI:
            [NSString
                stringWithFormat:
                    @"=== PvZ2 complete-import probe v13 session started; PID=%d ===",
                    getpid()]];

    [self
        appendUI:
            @"Milestones carried forward: Non-TXM JIT ✅ | Dynarmic ARM32→42 ✅ | exact PvZ2 ELF mapping ✅ | real JNI_OnLoad returned JNI 1.4 ✅"];

    [self refreshStatus];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter]
        removeObserver:self];
}

- (void)appendUI:
        (NSString *)line {

    AppendPersistentLog(line);

    NSString *existing =
        self.logView.text ?: @"";

    self.logView.text =
        [existing
            stringByAppendingFormat:
                @"%@\n",
                line];

    if (self.logView.text.length > 0) {
        NSRange bottom =
            NSMakeRange(
                self.logView.text.length - 1,
                1);

        [self.logView
            scrollRangeToVisible:
                bottom];
    }
}

- (void)showResult:
        (NSString *)title
    message:
        (NSString *)message {

    UIAlertController *alert =
        [UIAlertController
            alertControllerWithTitle:
                title
            message:
                message
            preferredStyle:
                UIAlertControllerStyleAlert];

    [alert
        addAction:
            [UIAlertAction
                actionWithTitle:
                    @"OK"
                style:
                    UIAlertActionStyleDefault
                handler:
                    nil]];

    [self
        presentViewController:
            alert
        animated:
            YES
        completion:
            nil];
}

- (void)refreshStatus {
    const BOOL taskAllow =
        HasGetTaskAllow();

    const BOOL debugged =
        IsDebugged();

    NSString *bundle =
        NSBundle.mainBundle.bundleIdentifier
        ?: @"(unknown)";

    if (debugged &&
        !self.step1ReadyLogged) {

        self.step1ReadyLogged =
            YES;

        [self
            appendUI:
                @"STEP 1 READY: CS_DEBUGGED is YES. A14/Non-TXM JIT acquisition is complete."];
    }

    self.statusLabel.text =
        [NSString
            stringWithFormat:
                @"Device: arm64 | PID: %d | iPad 10th gen / A14 / Non-TXM\n"
                 @"Bundle ID: %@\n"
                 @"get-task-allow: %@ | CS_DEBUGGED: %@\n"
                 @"Dynarmic smoke: %@ | full PvZ2 load: %@",
                getpid(),
                bundle,
                taskAllow
                    ? @"YES"
                    : @"NO",
                debugged
                    ? @"YES"
                    : @"NO",
                self.dynarmicRunning
                    ? @"RUNNING…"
                    : @"ready",
                self.jniRunning
                    ? @"RUNNING…"
                    : @"ready"];

    self.dynarmicButton.enabled =
        !self.dynarmicRunning &&
        !self.jniRunning;

    self.jniButton.enabled =
        !self.dynarmicRunning &&
        !self.jniRunning;
}

- (void)enableJIT {
    if (!HasGetTaskAllow()) {
        [self
            appendUI:
                @"STEP 1 FAILED: get-task-allow is NO."];
        return;
    }

    NSString *bundleID =
        NSBundle.mainBundle.bundleIdentifier;

    if (bundleID.length == 0) {
        [self
            appendUI:
                @"STEP 1 FAILED: bundle identifier unavailable."];
        return;
    }

    NSURLComponents *components =
        [[NSURLComponents alloc] init];

    components.scheme =
        @"stikdebug";

    components.host =
        @"enable-jit";

    components.queryItems =
        @[
            [NSURLQueryItem
                queryItemWithName:
                    @"bundle-id"
                value:
                    bundleID],
        ];

    NSURL *url =
        components.URL;

    if (url == nil) {
        [self
            appendUI:
                @"STEP 1 FAILED: could not construct StikDebug URL."];
        return;
    }

    [self
        appendUI:
            @"STEP 1: asking StikDebug to launch the final app process by Bundle ID under the debugger. No PID is supplied and no JIT script is sent."];

    [[UIApplication sharedApplication]
        openURL:url
        options:@{}
        completionHandler:
            ^(BOOL success) {

                dispatch_async(
                    dispatch_get_main_queue(),
                    ^{

                        [self
                            appendUI:
                                success
                                    ? @"STEP 1: StikDebug opened. It will relaunch PvZ2forIOS itself; when the new instance shows CS_DEBUGGED=YES, that final PID is ready."
                                    : @"STEP 1 FAILED: iPadOS could not open StikDebug."];
                    });
            }];
}

- (void)runDynarmic {
    if (!IsDebugged()) {
        [self
            appendUI:
                @"STEP 2 BLOCKED: CS_DEBUGGED is NO. Run step 1 first."];
        return;
    }

    if (self.dynarmicRunning ||
        self.jniRunning) {
        return;
    }

    self.dynarmicRunning =
        YES;

    [self refreshStatus];

    [self
        appendUI:
            @"STEP 2A: running the validated Dynarmic ARMv7 return-42 smoke test."];

    __weak ProbeViewController *weakSelf =
        self;

    dispatch_async(
        dispatch_get_global_queue(
            QOS_CLASS_USER_INITIATED,
            0),
        ^{

            DynarmicSmokeResult result =
                RunDynarmicArm32Smoke();

            dispatch_async(
                dispatch_get_main_queue(),
                ^{

                    ProbeViewController *selfRef =
                        weakSelf;

                    if (!selfRef) {
                        return;
                    }

                    selfRef.dynarmicRunning =
                        NO;

                    [selfRef
                        appendUI:
                            [NSString
                                stringWithFormat:
                                    @"STEP 2B: ok=%@ R0=%u PC=0x%08x halt=0x%08x svc=%@ exception=%@",
                                    result.ok
                                        ? @"YES"
                                        : @"NO",
                                    result.r0,
                                    result.pc,
                                    result.halt_reason,
                                    result.svc_seen
                                        ? @"YES"
                                        : @"NO",
                                    result.exception_seen
                                        ? @"YES"
                                        : @"NO"]];

                    [selfRef
                        appendUI:
                            [NSString
                                stringWithFormat:
                                    @"STEP 2C: %@",
                                    NSStringFromStd(
                                        result.message)]];

                    if (result.ok) {
                        [selfRef
                            appendUI:
                                @"SUCCESS STEP 2: Dynarmic ARM32 guest code returned 42."];
                    } else {
                        [selfRef
                            showResult:
                                @"Dynarmic test failed"
                            message:
                                NSStringFromStd(
                                    result.message)];
                    }

                    [selfRef refreshStatus];
                });
        });
}

- (void)selectApkForJni {
    if (!IsDebugged()) {
        [self
            appendUI:
                @"STEP 3 BLOCKED: CS_DEBUGGED is NO. Run step 1 first."];
        return;
    }

    if (self.jniRunning ||
        self.dynarmicRunning) {
        return;
    }

    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc]
            initForOpeningContentTypes:
                @[UTTypeData]
            asCopy:
                YES];

    picker.delegate =
        self;

    picker.allowsMultipleSelection =
        NO;

    picker.modalPresentationStyle =
        UIModalPresentationFormSheet;

    [self
        appendUI:
            @"STEP 3: select the same original PvZ2 1.5.252752 APK. v13 will reproduce the validated full startup, enter Native_GameAppInitialize, and use the complete known-import baseline so missing ELF imports no longer require one IPA per symbol."];

    [self
        presentViewController:
            picker
        animated:
            YES
        completion:
            nil];
}

- (void)documentPickerWasCancelled:
        (UIDocumentPickerViewController *)controller {

    [self
        appendUI:
            @"STEP 3: APK selection cancelled."];
}

- (void)documentPicker:
        (UIDocumentPickerViewController *)controller
    didPickDocumentsAtURLs:
        (NSArray<NSURL *> *)urls {

    NSURL *url =
        urls.firstObject;

    if (url == nil) {
        [self
            appendUI:
                @"STEP 3 FAILED: document picker returned no file."];
        return;
    }

    self.jniRunning =
        YES;

    [self refreshStatus];

    [self
        appendUI:
            [NSString
                stringWithFormat:
                    @"STEP 3A: selected %@; preparing full PvZ2 startup + complete import baseline + Native_GameAppInitialize…",
                    url.lastPathComponent
                        ?: @"(unnamed file)"]];

    __weak ProbeViewController *weakSelf =
        self;

    dispatch_async(
        dispatch_get_global_queue(
            QOS_CLASS_USER_INITIATED,
            0),
        ^{

            BOOL scoped =
                [url
                    startAccessingSecurityScopedResource];

            NSError *readError =
                nil;

            NSData *data =
                [NSData
                    dataWithContentsOfURL:
                        url
                    options:
                        NSDataReadingMappedIfSafe
                    error:
                        &readError];

            if (scoped) {
                [url
                    stopAccessingSecurityScopedResource];
            }

            if (data == nil) {
                dispatch_async(
                    dispatch_get_main_queue(),
                    ^{

                        ProbeViewController *selfRef =
                            weakSelf;

                        if (!selfRef) {
                            return;
                        }

                        selfRef.jniRunning =
                            NO;

                        [selfRef
                            appendUI:
                                [NSString
                                    stringWithFormat:
                                        @"STEP 3 FAILED: could not read APK: %@",
                                        readError.localizedDescription
                                            ?: @"unknown read error"]];

                        [selfRef refreshStatus];
                    });

                return;
            }

            PvZ2JniProbeResult result =
                RunPvZ2FullLoadProbe(
                    static_cast<const std::uint8_t*>(
                        data.bytes),
                    data.length,
                    [](const std::string& line) {
                        @autoreleasepool {
                            NSString *nsLine =
                                NSStringFromStd(line);
                            AppendPersistentLog(
                                [NSString stringWithFormat:
                                    @"[FULLLOAD] %@",
                                    nsLine]);
                        }
                    });

            dispatch_async(
                dispatch_get_main_queue(),
                ^{

                    ProbeViewController *selfRef =
                        weakSelf;

                    if (!selfRef) {
                        return;
                    }

                    selfRef.jniRunning =
                        NO;

                    [selfRef
                        appendUI:
                            [NSString
                                stringWithFormat:
                                    @"STEP 3B: init slots=%u | constructors=%u | completed=%u | __cxa_atexit=%u | imports patched=%u",
                                    result.init_array_slots,
                                    result.constructors_total,
                                    result.constructors_completed,
                                    result.cxa_atexit_calls,
                                    result.imports_patched]];

                    [selfRef
                        appendUI:
                            [NSString
                                stringWithFormat:
                                    @"STEP 3C: JNI_OnLoad reached=%@ returned=%@ return=0x%08x | GameAppInitialize=0x%08x reached=%@ returned=%@ result=%u",
                                    result.reached_jni_onload ? @"YES" : @"NO",
                                    result.returned_from_jni_onload ? @"YES" : @"NO",
                                    result.return_value,
                                    result.game_app_initialize_address,
                                    result.reached_game_app_initialize ? @"YES" : @"NO",
                                    result.returned_game_app_initialize ? @"YES" : @"NO",
                                    result.game_app_initialize_return & 0xffu]];

                    if (!result.trace.empty()) {
                        [selfRef
                            appendUI:
                                @"----- FULL LOAD TRACE -----"];

                        [selfRef
                            appendUI:
                                NSStringFromStd(
                                    result.trace)];

                        [selfRef
                            appendUI:
                                @"----- END FULL LOAD TRACE -----"];
                    }

                    [selfRef
                        appendUI:
                            [NSString
                                stringWithFormat:
                                    @"STEP 3D: %@",
                                    NSStringFromStd(
                                        result.message)]];

                    if (!result.first_unsupported_import.empty()) {
                        [selfRef
                            appendUI:
                                [NSString
                                    stringWithFormat:
                                        @"STEP 3E: first unsupported import = %@",
                                        NSStringFromStd(
                                            result.first_unsupported_import)]];
                    }

                    if (result.unsupported_jni_slot != 0xffffffffu) {
                        [selfRef
                            appendUI:
                                [NSString
                                    stringWithFormat:
                                        @"STEP 3F: first unsupported JNIEnv slot = %u (offset 0x%08x)",
                                        result.unsupported_jni_slot,
                                        result.unsupported_jni_slot * 4u]];
                    }

                    if (result.ok) {
                        [selfRef
                            appendUI:
                                @"SUCCESS STEP 3: real Native_GameAppInitialize returned under Dynarmic."];

                        [selfRef
                            showResult:
                                @"Native_GameAppInitialize returned"
                            message:
                                [NSString
                                    stringWithFormat:
                                        @"The real PvZ2 Native_GameAppInitialize executed to its return point on the A14.\n\nAddress: 0x%08x\nJNI signature: %@\nReturn jboolean: %u\nConstructors completed: %u/%u\nJNI_OnLoad: 0x%08x\n\nNext milestone: replace synthetic Android/Java objects with functional surface/filesystem/input bridges and continue toward first game frame.",
                                        result.game_app_initialize_address,
                                        NSStringFromStd(result.game_app_initialize_signature),
                                        result.game_app_initialize_return & 0xffu,
                                        result.constructors_completed,
                                        result.constructors_total,
                                        result.return_value]];
                    } else {
                        NSString *message =
                            NSStringFromStd(
                                result.message);

                        [selfRef
                            showResult:
                                result.constructor_failure_index != 0xffffffffu
                                    ? @"Constructor stopped safely"
                                    : (result.reached_game_app_initialize
                                        ? @"GameAppInitialize stopped safely"
                                        : (result.reached_jni_onload
                                            ? @"JNI_OnLoad stopped safely"
                                            : @"Full-load probe failed"))
                            message:
                                message];
                    }

                    [selfRef refreshStatus];
                });
        });
}

@end

@interface ProbeAppDelegate :
    UIResponder
    <UIApplicationDelegate>

@property(nonatomic, strong)
    UIWindow *window;

@end

@implementation ProbeAppDelegate

- (BOOL)application:
        (UIApplication *)application
    didFinishLaunchingWithOptions:
        (NSDictionary *)launchOptions {

    self.window =
        [[UIWindow alloc]
            initWithFrame:
                UIScreen.mainScreen.bounds];

    ProbeViewController *controller =
        [[ProbeViewController alloc] init];

    UINavigationController *nav =
        [[UINavigationController alloc]
            initWithRootViewController:
                controller];

    self.window.rootViewController =
        nav;

    [self.window
        makeKeyAndVisible];

    return YES;
}

@end

int main(
    int argc,
    char *argv[]) {

    @autoreleasepool {
        setenv(
            "DYNARMIC_DUAL_MAPPED",
            "1",
            1);

        return
            UIApplicationMain(
                argc,
                argv,
                nil,
                NSStringFromClass(
                    [ProbeAppDelegate class]));
    }
}
