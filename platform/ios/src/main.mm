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

// v52: the old logger opened, sought and closed an NSFileHandle for every
// diagnostic line. A full-load run emits thousands of lines, so the diagnostic
// logger itself became a major part of the wall-clock runtime. Keep one handle
// open for the run instead. Writes still reach the file immediately, preserving
// useful crash diagnostics without paying open/close cost per line.
NSLock *PersistentLogLock() {
    static NSLock *lock =
        [[NSLock alloc] init];
    return lock;
}

NSFileHandle *gPersistentLogHandle = nil;

void EnsurePersistentLogHandleLocked() {
    if (gPersistentLogHandle != nil) {
        return;
    }

    NSString *path =
        LogFilePath();

    if (![[NSFileManager defaultManager]
            fileExistsAtPath:path]) {
        [[NSFileManager defaultManager]
            createFileAtPath:path
                    contents:[NSData data]
                  attributes:nil];
    }

    gPersistentLogHandle =
        [NSFileHandle
            fileHandleForWritingAtPath:path];

    [gPersistentLogHandle
        seekToEndOfFile];
}

void FlushPersistentLog() {
    NSLock *lock =
        PersistentLogLock();

    [lock lock];

    EnsurePersistentLogHandleLocked();

    if (gPersistentLogHandle != nil) {
        [gPersistentLogHandle
            synchronizeFile];
    }

    [lock unlock];
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

    NSData *data =
        [entry
            dataUsingEncoding:
                NSUTF8StringEncoding];

    NSLock *lock =
        PersistentLogLock();

    [lock lock];

    EnsurePersistentLogHandleLocked();

    if (gPersistentLogHandle != nil &&
        data != nil) {
        [gPersistentLogHandle
            writeData:data];
    }

    [lock unlock];
}

NSString *ReadPersistentLogFull() {
    FlushPersistentLog();

    NSError *error = nil;

    NSString *text =
        [NSString
            stringWithContentsOfFile:
                LogFilePath()
                         encoding:
                NSUTF8StringEncoding
                            error:
                &error];

    return text ?: @"";
}

NSString *ReadPersistentLog() {
    NSString *text =
        ReadPersistentLogFull();

    if (text.length > 32000) {
        return
            [text
                substringFromIndex:
                    text.length - 32000];
    }

    return text;
}

void ResetPersistentLog() {
    NSLock *lock =
        PersistentLogLock();

    [lock lock];

    if (gPersistentLogHandle != nil) {
        [gPersistentLogHandle
            synchronizeFile];
        [gPersistentLogHandle
            closeFile];
        gPersistentLogHandle = nil;
    }

    [[NSFileManager defaultManager]
        removeItemAtPath:
            LogFilePath()
                   error:
            nil];

    [[NSFileManager defaultManager]
        createFileAtPath:
            LogFilePath()
                contents:[NSData data]
              attributes:nil];

    EnsurePersistentLogHandleLocked();

    [lock unlock];
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
        @"PvZ2forIOS — Startup Diagnostic Cockpit v52";

    UILabel *title =
        [[UILabel alloc] init];

    title.translatesAutoresizingMaskIntoConstraints =
        NO;

    title.text =
        @"PvZ2forIOS — startup diagnostic cockpit v52";

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
        @"v51 proved that Android player-profile persistence is now real: snapshot2.dat is created and Config values persist, but the game still fades from the EA splash into a genuinely black framebuffer without requesting MainMenu_Background or UI_MainMenu. "
         @"v52 changes strategy from one-hypothesis-per-build to a reusable diagnostic cockpit. It snapshots the real AndroidAppDriver/GameApp object graph around the EA transition, reports small enum/boolean-like field changes, captures post-EA JNI caller PCs and stack code candidates, summarizes every deferred worker, and keeps all existing resource/cloud/network/VFS/GLES probes. The frame soak is now adaptive: 600 is only a safety ceiling and a stable black post-EA state stops early. The persistent logger also keeps one file handle open instead of reopening the log for every line, removing a major diagnostic-time overhead. The displayed PNG is now the FINAL framebuffer, not the visually richest EA frame.";

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
                @"3. Run PvZ2\nAPK + OBB"
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

    UIButton *copyLogButton =
        [self
            makeButton:
                @"Copy full log"
            selector:
                @selector(copyFullLog)];

    UIStackView *utilityButtons =
        [[UIStackView alloc]
            initWithArrangedSubviews:
                @[
                    refreshButton,
                    copyLogButton
                ]];

    utilityButtons.translatesAutoresizingMaskIntoConstraints =
        NO;

    utilityButtons.axis =
        UILayoutConstraintAxisHorizontal;

    utilityButtons.spacing = 12.0;

    utilityButtons.distribution =
        UIStackViewDistributionFillEqually;

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
                    utilityButtons,
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

                [utilityButtons.heightAnchor
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
                    @"=== PvZ2 host-GLES v31 session started; PID=%d ===",
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

- (void)dismissCapturedFrame {
    [self.presentedViewController
        dismissViewControllerAnimated:YES
        completion:nil];
}

- (void)showCapturedFrameAtPath:
        (NSString *)path {

    UIImage *image =
        [UIImage
            imageWithContentsOfFile:path];

    if (image == nil) {
        [self
            showResult:
                @"Host GLES capture unavailable"
            message:
                [NSString
                    stringWithFormat:
                        @"v31 returned a capture path but UIKit could not decode the PNG:\n%@",
                        path ?: @"(null)"]];
        return;
    }

    UIViewController *frameController =
        [[UIViewController alloc] init];

    frameController.modalPresentationStyle =
        UIModalPresentationFullScreen;

    frameController.view.backgroundColor =
        UIColor.blackColor;

    UIImageView *imageView =
        [[UIImageView alloc]
            initWithImage:image];

    imageView.translatesAutoresizingMaskIntoConstraints =
        NO;
    imageView.contentMode =
        UIViewContentModeScaleAspectFit;

    UILabel *caption =
        [[UILabel alloc] init];

    caption.translatesAutoresizingMaskIntoConstraints =
        NO;
    caption.textColor =
        UIColor.whiteColor;
    caption.textAlignment =
        NSTextAlignmentCenter;
    caption.numberOfLines =
        0;
    caption.font =
        [UIFont
            monospacedSystemFontOfSize:13.0
            weight:UIFontWeightRegular];
    caption.text =
        @"v52 — FINAL framebuffer (not the richest splash frame)\nTap Close to inspect the state-graph / callsite diagnostic log.";

    UIButton *closeButton =
        [UIButton
            buttonWithType:UIButtonTypeSystem];

    closeButton.translatesAutoresizingMaskIntoConstraints =
        NO;
    [closeButton
        setTitle:@"Close"
        forState:UIControlStateNormal];
    closeButton.titleLabel.font =
        [UIFont
            boldSystemFontOfSize:18.0];
    [closeButton
        addTarget:self
        action:@selector(dismissCapturedFrame)
        forControlEvents:UIControlEventTouchUpInside];

    [frameController.view
        addSubview:imageView];
    [frameController.view
        addSubview:caption];
    [frameController.view
        addSubview:closeButton];

    UILayoutGuide *guide =
        frameController.view.safeAreaLayoutGuide;

    [NSLayoutConstraint
        activateConstraints:@[
            [caption.topAnchor
                constraintEqualToAnchor:guide.topAnchor
                constant:12.0],
            [caption.leadingAnchor
                constraintEqualToAnchor:guide.leadingAnchor
                constant:20.0],
            [caption.trailingAnchor
                constraintEqualToAnchor:guide.trailingAnchor
                constant:-20.0],

            [imageView.topAnchor
                constraintEqualToAnchor:caption.bottomAnchor
                constant:10.0],
            [imageView.leadingAnchor
                constraintEqualToAnchor:guide.leadingAnchor
                constant:8.0],
            [imageView.trailingAnchor
                constraintEqualToAnchor:guide.trailingAnchor
                constant:-8.0],

            [closeButton.topAnchor
                constraintEqualToAnchor:imageView.bottomAnchor
                constant:10.0],
            [closeButton.bottomAnchor
                constraintEqualToAnchor:guide.bottomAnchor
                constant:-12.0],
            [closeButton.centerXAnchor
                constraintEqualToAnchor:guide.centerXAnchor],
            [closeButton.heightAnchor
                constraintEqualToConstant:44.0],
        ]];

    [self
        presentViewController:frameController
        animated:YES
        completion:nil];
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

- (void)copyFullLog {
    NSString *fullLog =
        ReadPersistentLogFull();

    if (fullLog.length == 0) {
        fullLog =
            self.logView.text ?: @"";
    }

    UIPasteboard.generalPasteboard.string =
        fullLog;

    [self
        showResult:
            @"Full persistent log copied"
        message:
            [NSString
                stringWithFormat:
                    @"Copied %lu characters from the persistent probe log. Unlike v26, this is not limited to the 32k-character UI tail, so the early RSB lines survive an app restart.",
                    (unsigned long)fullLog.length]];
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
        YES;

    picker.modalPresentationStyle =
        UIModalPresentationFormSheet;

    [self
        appendUI:
            @"STEP 3: select BOTH files at once: the original PvZ2 1.5.252752 APK and main.7.com.ea.game.pvz2_row.obb. v52 runs one high-information startup diagnosis instead of another single-gate probe. Key outputs are V52 OBJECT ROOT / STATE-LIKE CHANGE / STATE CANDIDATE, V52 POST-EA JNI CALLSITE / STACK CODE, V52 WORKER FINAL, resource/menu milestones, and the adaptive-stop decision. The image shown at the end is the actual FINAL framebuffer."];

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
            @"STEP 3: APK/OBB selection cancelled."];
}

- (void)documentPicker:
        (UIDocumentPickerViewController *)controller
    didPickDocumentsAtURLs:
        (NSArray<NSURL *> *)urls {

    NSURL *apkURL = nil;
    NSURL *obbURL = nil;

    for (NSURL *candidate in urls) {
        NSString *extension =
            candidate.pathExtension.lowercaseString;

        if ([extension isEqualToString:@"apk"]) {
            apkURL = candidate;
        } else if ([extension isEqualToString:@"obb"]) {
            obbURL = candidate;
        }
    }

    if (apkURL == nil ||
        obbURL == nil) {

        [self
            appendUI:
                @"STEP 3 FAILED: v19 needs exactly the PvZ2 APK plus its matching .obb expansion file selected together."];

        [self
            showResult:
                @"APK + OBB required"
            message:
                @"Select both files in the document picker: the original PvZ2 1.5.252752 .apk and main.7.com.ea.game.pvz2_row.obb."];

        return;
    }

    ResetPersistentLog();
    self.logView.text = @"";

    [self
        appendUI:
            [NSString
                stringWithFormat:
                    @"=== PvZ2 v52 diagnostic run started; PID=%d ===",
                    getpid()]];

    self.jniRunning =
        YES;

    [self refreshStatus];

    [self
        appendUI:
            [NSString
                stringWithFormat:
                    @"STEP 3A: APK=%@ | OBB=%@; preparing full startup with real in-memory expansion-file I/O…",
                    apkURL.lastPathComponent
                        ?: @"(APK)",
                    obbURL.lastPathComponent
                        ?: @"(OBB)"]];

    __weak ProbeViewController *weakSelf =
        self;

    dispatch_async(
        dispatch_get_global_queue(
            QOS_CLASS_USER_INITIATED,
            0),
        ^{

            auto readScoped =
                ^NSData *(NSURL *url,
                           NSError **error) {

                    BOOL scoped =
                        [url
                            startAccessingSecurityScopedResource];

                    NSData *data =
                        [NSData
                            dataWithContentsOfURL:
                                url
                            options:
                                NSDataReadingMappedIfSafe
                            error:
                                error];

                    if (scoped) {
                        [url
                            stopAccessingSecurityScopedResource];
                    }

                    return data;
                };

            NSError *apkError = nil;
            NSError *obbError = nil;

            NSData *apkData =
                readScoped(
                    apkURL,
                    &apkError);

            NSData *obbData =
                readScoped(
                    obbURL,
                    &obbError);

            if (apkData == nil ||
                obbData == nil) {

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
                                        @"STEP 3 FAILED: APK read=%@ | OBB read=%@",
                                        apkData
                                            ? @"OK"
                                            : (apkError.localizedDescription
                                                ?: @"failed"),
                                        obbData
                                            ? @"OK"
                                            : (obbError.localizedDescription
                                                ?: @"failed")]];

                        [selfRef refreshStatus];
                    });

                return;
            }

            PvZ2JniProbeResult result =
                RunPvZ2FullLoadProbe(
                    static_cast<const std::uint8_t*>(
                        apkData.bytes),
                    apkData.length,
                    static_cast<const std::uint8_t*>(
                        obbData.bytes),
                    obbData.length,
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
                                    @"STEP 3C: JNI_OnLoad=%@ | GameAppInit returned=%@ result=%u | lifecycle=%u | firstDraw reached=%@ returned=%@ | frames=%u | adaptiveStop=%@ | hostGLES=%@ | richestFrame=%u nonBlack=%llu | lastNonBlack=%u pixels=%llu",
                                    result.returned_from_jni_onload ? @"YES" : @"NO",
                                    result.returned_game_app_initialize ? @"YES" : @"NO",
                                    result.game_app_initialize_return & 0xffu,
                                    result.lifecycle_calls_completed,
                                    result.reached_first_draw_frame ? @"YES" : @"NO",
                                    result.returned_first_draw_frame ? @"YES" : @"NO",
                                    result.draw_frames_completed,
                                    result.adaptive_frame_stop ? @"YES" : @"NO",
                                    result.host_gles_active ? @"YES" : @"NO",
                                    result.best_frame_number,
                                    (unsigned long long)result.best_frame_nonblack,
                                    result.last_nonblack_frame_number,
                                    (unsigned long long)result.last_nonblack_pixels]];

                    if (!result.diagnostic_summary.empty()) {
                        [selfRef
                            appendUI:
                                [NSString
                                    stringWithFormat:
                                        @"STEP 3C3: %@",
                                        NSStringFromStd(
                                            result.diagnostic_summary)]];
                    }

                    [selfRef
                        appendUI:
                            [NSString
                                stringWithFormat:
                                    @"STEP 3C2: RSB manifest=%@ | indexed files=%u | registry lookups=%u direct=%u pathFallback=%u misses=%u pathKeys=%u | malloc=%llu free=%llu realloc=%llu | heap high-water=%u live=%u in %u allocations",
                                    result.rsb_manifest_resolved ? @"RESOLVED" : @"NOT OBSERVED",
                                    result.rsb_resolved_files,
                                    result.resource_registry_lookup_calls,
                                    result.resource_registry_direct_hits,
                                    result.resource_registry_path_fallback_hits,
                                    result.resource_registry_misses,
                                    result.resource_path_index_entries,
                                    (unsigned long long)result.malloc_calls,
                                    (unsigned long long)result.free_calls,
                                    (unsigned long long)result.realloc_calls,
                                    result.heap_high_water,
                                    result.heap_live_bytes,
                                    result.heap_live_allocations]];

                    // v52: every trace line was already persisted by the
                    // progress callback. Do not append result.trace again;
                    // older probes doubled the exported log and made analysis
                    // unnecessarily expensive.

                    [selfRef
                        appendUI:
                            [NSString
                                stringWithFormat:
                                    @"STEP 3D: %@",
                                    NSStringFromStd(
                                        result.message)]];

                    if (!result.sweep_summary.empty()) {
                        [selfRef
                            appendUI:
                                @"----- V24 BULK SWEEP SUMMARY -----"];

                        [selfRef
                            appendUI:
                                NSStringFromStd(
                                    result.sweep_summary)];

                        [selfRef
                            appendUI:
                                [NSString
                                    stringWithFormat:
                                        @"Sweep counters: unique=%u recoveries=%u speculative=%@",
                                        result.sweep_issue_count,
                                        result.sweep_recovery_count,
                                        result.sweep_speculative
                                            ? @"YES"
                                            : @"NO"]];

                        [selfRef
                            appendUI:
                                @"----- END V24 BULK SWEEP SUMMARY -----"];
                    }

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
                                @"SUCCESS STEP 3: PvZ2 completed lifecycle + host GLES + v52 state/callsite diagnostics + adaptive frame soak."];

                        if (!result.final_frame_png_path.empty()) {
                            [selfRef
                                appendUI:
                                    [NSString
                                        stringWithFormat:
                                            @"STEP 3G: FINAL GLES framebuffer PNG = %@",
                                            NSStringFromStd(
                                                result.final_frame_png_path)]];

                            if (!result.best_frame_png_path.empty()) {
                                [selfRef
                                    appendUI:
                                        [NSString
                                            stringWithFormat:
                                                @"STEP 3G2: richest sampled framebuffer (diagnostic only) = %@",
                                                NSStringFromStd(
                                                    result.best_frame_png_path)]];
                            }

                            [selfRef
                                showCapturedFrameAtPath:
                                    NSStringFromStd(
                                        result.final_frame_png_path)];
                        } else {
                            [selfRef
                                showResult:
                                    @"PvZ2 v52 diagnostic returned"
                                message:
                                    [NSString
                                        stringWithFormat:
                                            @"PvZ2 completed its native startup and v52 adaptive diagnostic.\n\nGameAppInitialize: %u\nLifecycle calls completed: %u\nFrames returned: %u\nHost GLES active: %@\nRichest sampled frame: %u (%llu non-black pixels)\nConstructors: %u/%u\nJNI_OnLoad: 0x%08x\n\nNo final PNG capture was produced; inspect V52 STATE CANDIDATE / POST-EA JNI / WORKER FINAL plus the V47 framebuffer lines in the full log.",
                                            result.game_app_initialize_return & 0xffu,
                                            result.lifecycle_calls_completed,
                                            result.draw_frames_completed,
                                            result.host_gles_active ? @"YES" : @"NO",
                                            result.best_frame_number,
                                            (unsigned long long)result.best_frame_nonblack,
                                            result.constructors_completed,
                                            result.constructors_total,
                                            result.return_value]];
                        }
                    } else {
                        NSString *message =
                            NSStringFromStd(
                                result.message);

                        [selfRef
                            showResult:
                                !result.lifecycle_failure_name.empty()
                                    ? @"Lifecycle/first-frame call stopped"
                                    : (result.constructor_failure_index != 0xffffffffu
                                        ? @"Constructor stopped safely"
                                        : (result.reached_game_app_initialize
                                            ? @"GameAppInitialize stopped safely"
                                            : (result.reached_jni_onload
                                                ? @"JNI_OnLoad stopped safely"
                                                : @"Full-load probe failed")))
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
