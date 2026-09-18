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

    auto create = reinterpret_cast<CreateFn>(dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf"));
    auto copy = reinterpret_cast<CopyFn>(dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement"));
    if (create == nullptr || copy == nullptr) {
        return false;
    }

    void *task = create(kCFAllocatorDefault);
    if (task == nullptr) {
        return false;
    }

    CFTypeRef value = copy(task, CFSTR("get-task-allow"), nullptr);
    const bool result = value == kCFBooleanTrue;

    if (value != nullptr) {
        CFRelease(value);
    }
    CFRelease(reinterpret_cast<CFTypeRef>(task));
    return result;
}

NSString *LogFilePath() {
    NSArray<NSURL *> *urls =
        [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory
                                               inDomains:NSUserDomainMask];
    NSURL *documents = urls.firstObject;
    return [[documents URLByAppendingPathComponent:@"pvz2forios-probe.log"] path];
}

void AppendPersistentLog(NSString *line) {
    NSString *timestamp = [[NSDate date] descriptionWithLocale:nil];
    NSString *entry = [NSString stringWithFormat:@"[%@] %@\n", timestamp, line];
    NSString *path = LogFilePath();

    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [entry writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        return;
    }

    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
    [handle seekToEndOfFile];
    [handle writeData:[entry dataUsingEncoding:NSUTF8StringEncoding]];
    [handle closeFile];
}

NSString *ReadPersistentLog() {
    NSError *error = nil;
    NSString *text = [NSString stringWithContentsOfFile:LogFilePath()
                                              encoding:NSUTF8StringEncoding
                                                 error:&error];
    if (text == nil) {
        return @"";
    }
    if (text.length > 24000) {
        return [text substringFromIndex:text.length - 24000];
    }
    return text;
}

NSString *NSStringFromStd(const std::string& value) {
    return [NSString stringWithUTF8String:value.c_str()] ?: @"(invalid UTF-8)";
}

} // namespace

@interface ProbeViewController : UIViewController <UIDocumentPickerDelegate>
@property(nonatomic, strong) UILabel *statusLabel;
@property(nonatomic, strong) UITextView *logView;
@property(nonatomic, strong) UIButton *dynarmicButton;
@property(nonatomic, strong) UIButton *apkButton;
@property(nonatomic, assign) BOOL dynarmicRunning;
@property(nonatomic, assign) BOOL apkRunning;
@property(nonatomic, assign) BOOL step1ReadyLogged;
@end

@implementation ProbeViewController

- (UIButton *)makeButton:(NSString *)title selector:(SEL)selector {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.translatesAutoresizingMaskIntoConstraints = NO;
    [button setTitle:title forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:17.0];
    button.titleLabel.numberOfLines = 2;
    button.titleLabel.textAlignment = NSTextAlignmentCenter;
    [button addTarget:self action:selector forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.title = @"PvZ2forIOS — Loader Probe v8";

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"PvZ2forIOS — Dynarmic + real PvZ2 ELF loader probe v8";
    title.font = [UIFont boldSystemFontOfSize:25.0];
    title.numberOfLines = 0;

    UILabel *explanation = [[UILabel alloc] init];
    explanation.translatesAutoresizingMaskIntoConstraints = NO;
    explanation.text =
        @"v7 proved real ARMv7 guest code can run through Dynarmic on this A14. "
         @"v8 keeps that test and adds the next layer: choose your legally owned PvZ2 APK. "
         @"The app extracts libPVZ2.so itself, validates its ARM ELF32 layout, maps its PT_LOAD "
         @"segments into a guest address space, applies R_ARM_RELATIVE relocations, enumerates "
         @"Android imports and locates JNI_OnLoad. The game binary is never bundled into this IPA.";
    explanation.numberOfLines = 0;
    explanation.font = [UIFont systemFontOfSize:15.0];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:13.0
                                                       weight:UIFontWeightRegular];

    UIButton *enableButton =
        [self makeButton:@"1. Enable JIT\nwith StikDebug" selector:@selector(enableJIT)];

    self.dynarmicButton =
        [self makeButton:@"2. Dynarmic\nARM32 → 42" selector:@selector(runDynarmic)];

    self.apkButton =
        [self makeButton:@"3. Inspect + map\nPvZ2 APK" selector:@selector(selectApk)];

    UIStackView *mainButtons = [[UIStackView alloc]
        initWithArrangedSubviews:@[enableButton, self.dynarmicButton, self.apkButton]];
    mainButtons.translatesAutoresizingMaskIntoConstraints = NO;
    mainButtons.axis = UILayoutConstraintAxisHorizontal;
    mainButtons.spacing = 12.0;
    mainButtons.distribution = UIStackViewDistributionFillEqually;

    UIButton *refreshButton =
        [self makeButton:@"Refresh status" selector:@selector(refreshStatus)];

    self.logView = [[UITextView alloc] init];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:12.0
                                                    weight:UIFontWeightRegular];
    self.logView.layer.borderWidth = 1.0;
    self.logView.layer.borderColor = UIColor.separatorColor.CGColor;
    self.logView.layer.cornerRadius = 8.0;
    self.logView.text = ReadPersistentLog();

    UIStackView *stack = [[UIStackView alloc]
        initWithArrangedSubviews:@[
            title, explanation, self.statusLabel, mainButtons, refreshButton, self.logView
        ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12.0;

    [self.view addSubview:stack];

    UILayoutGuide *guide = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:guide.leadingAnchor constant:24.0],
        [stack.trailingAnchor constraintEqualToAnchor:guide.trailingAnchor constant:-24.0],
        [stack.topAnchor constraintEqualToAnchor:guide.topAnchor constant:16.0],
        [stack.bottomAnchor constraintEqualToAnchor:guide.bottomAnchor constant:-16.0],
        [mainButtons.heightAnchor constraintEqualToConstant:62.0],
        [refreshButton.heightAnchor constraintEqualToConstant:38.0],
        [self.logView.heightAnchor constraintGreaterThanOrEqualToConstant:280.0],
    ]];

    [[NSNotificationCenter defaultCenter]
        addObserver:self
           selector:@selector(refreshStatus)
               name:UIApplicationDidBecomeActiveNotification
             object:nil];

    [self appendUI:[NSString stringWithFormat:
        @"=== Loader probe v8 session started; PID=%d ===", getpid()]];
    [self appendUI:
        @"v7 milestone carried forward: ARM32 → Dynarmic → ARM64 returned R0=42 on the target A14."];
    [self refreshStatus];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)appendUI:(NSString *)line {
    AppendPersistentLog(line);

    NSString *existing = self.logView.text ?: @"";
    self.logView.text = [existing stringByAppendingFormat:@"%@\n", line];

    if (self.logView.text.length > 0) {
        NSRange bottom = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:bottom];
    }
}

- (void)showResult:(NSString *)title message:(NSString *)message {
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:title
                                            message:message
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                             style:UIAlertActionStyleDefault
                                           handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)refreshStatus {
    const BOOL taskAllow = HasGetTaskAllow();
    const BOOL debugged = IsDebugged();
    NSString *bundle = NSBundle.mainBundle.bundleIdentifier ?: @"(unknown)";

    if (debugged && !self.step1ReadyLogged) {
        self.step1ReadyLogged = YES;
        [self appendUI:
            @"STEP 1 READY: CS_DEBUGGED is YES. This A14/Non-TXM device needs no JIT script."];
    }

    self.statusLabel.text = [NSString stringWithFormat:
        @"Device: arm64 | PID: %d | iPad 10th gen / A14 / Non-TXM\n"
         @"Bundle ID: %@\n"
         @"get-task-allow: %@ | CS_DEBUGGED: %@\n"
         @"Dynarmic: %@ | APK/ELF probe: %@",
         getpid(),
         bundle,
         taskAllow ? @"YES" : @"NO",
         debugged ? @"YES" : @"NO",
         self.dynarmicRunning ? @"RUNNING…" : @"ready",
         self.apkRunning ? @"RUNNING…" : @"ready"];

    self.dynarmicButton.enabled = !self.dynarmicRunning;
    self.apkButton.enabled = !self.apkRunning;
}

- (void)enableJIT {
    if (!HasGetTaskAllow()) {
        [self appendUI:@"STEP 1 FAILED: get-task-allow is NO."];
        return;
    }

    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier;
    if (bundleID.length == 0) {
        [self appendUI:@"STEP 1 FAILED: bundle identifier unavailable."];
        return;
    }

    NSURLComponents *components = [[NSURLComponents alloc] init];
    components.scheme = @"stikdebug";
    components.host = @"enable-jit";
    components.queryItems = @[
        [NSURLQueryItem queryItemWithName:@"bundle-id" value:bundleID],
        [NSURLQueryItem queryItemWithName:@"pid"
                                    value:[NSString stringWithFormat:@"%d", getpid()]],
    ];

    NSURL *url = components.URL;
    if (url == nil) {
        [self appendUI:@"STEP 1 FAILED: could not construct StikDebug URL."];
        return;
    }

    [self appendUI:
        @"STEP 1: requesting Non-TXM debugger attach/detach. No JIT script is sent."];

    [[UIApplication sharedApplication]
        openURL:url
        options:@{}
        completionHandler:^(BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self appendUI:
                    success
                        ? @"STEP 1: StikDebug request opened. Return here; CS_DEBUGGED=YES means ready."
                        : @"STEP 1 FAILED: iPadOS could not open StikDebug."];
            });
        }];
}

- (void)runDynarmic {
    if (!IsDebugged()) {
        [self appendUI:@"STEP 2 BLOCKED: CS_DEBUGGED is NO. Run step 1 first."];
        return;
    }

    if (self.dynarmicRunning) {
        return;
    }

    self.dynarmicRunning = YES;
    [self refreshStatus];
    [self appendUI:
        @"STEP 2A: constructing Dynarmic A32 JIT and executing MOV 40 / ADD 2 / SVC."];

    __weak ProbeViewController *weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        DynarmicSmokeResult result = RunDynarmicArm32Smoke();

        dispatch_async(dispatch_get_main_queue(), ^{
            ProbeViewController *selfRef = weakSelf;
            if (!selfRef) {
                return;
            }

            selfRef.dynarmicRunning = NO;

            [selfRef appendUI:[NSString stringWithFormat:
                @"STEP 2B: ok=%@ R0=%u PC=0x%08x halt=0x%08x svc=%@ exception=%@",
                result.ok ? @"YES" : @"NO",
                result.r0,
                result.pc,
                result.halt_reason,
                result.svc_seen ? @"YES" : @"NO",
                result.exception_seen ? @"YES" : @"NO"]];

            NSString *message = NSStringFromStd(result.message);
            [selfRef appendUI:[NSString stringWithFormat:@"STEP 2C: %@", message]];

            if (result.ok) {
                [selfRef appendUI:
                    @"SUCCESS STEP 2: Dynarmic executed ARM32 guest code and returned R0=42."];
            } else {
                [selfRef showResult:@"Dynarmic test failed" message:message];
            }

            [selfRef refreshStatus];
        });
    });
}

- (void)selectApk {
    if (self.apkRunning) {
        return;
    }

    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc]
            initForOpeningContentTypes:@[UTTypeData]
                                asCopy:YES];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    picker.modalPresentationStyle = UIModalPresentationFormSheet;

    [self appendUI:
        @"STEP 3: choose the original PvZ2 1.5.252752 APK in Files. No game data is uploaded or bundled."];
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    [self appendUI:@"STEP 3: APK selection cancelled."];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller
    didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {

    NSURL *url = urls.firstObject;
    if (url == nil) {
        [self appendUI:@"STEP 3 FAILED: document picker returned no file."];
        return;
    }

    self.apkRunning = YES;
    [self refreshStatus];

    [self appendUI:[NSString stringWithFormat:
        @"STEP 3A: selected %@; reading APK…", url.lastPathComponent ?: @"(unnamed file)"]];

    __weak ProbeViewController *weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL scoped = [url startAccessingSecurityScopedResource];

        NSError *readError = nil;
        NSData *data = [NSData dataWithContentsOfURL:url
                                            options:NSDataReadingMappedIfSafe
                                              error:&readError];

        if (scoped) {
            [url stopAccessingSecurityScopedResource];
        }

        if (data == nil) {
            dispatch_async(dispatch_get_main_queue(), ^{
                ProbeViewController *selfRef = weakSelf;
                if (!selfRef) {
                    return;
                }
                selfRef.apkRunning = NO;
                [selfRef appendUI:[NSString stringWithFormat:
                    @"STEP 3 FAILED: could not read APK: %@",
                    readError.localizedDescription ?: @"unknown read error"]];
                [selfRef refreshStatus];
            });
            return;
        }

        PvZ2ApkProbeResult result = InspectAndMapPvZ2Apk(
            static_cast<const std::uint8_t*>(data.bytes),
            data.length);

        dispatch_async(dispatch_get_main_queue(), ^{
            ProbeViewController *selfRef = weakSelf;
            if (!selfRef) {
                return;
            }

            selfRef.apkRunning = NO;

            [selfRef appendUI:[NSString stringWithFormat:
                @"STEP 3B: APK=%llu bytes | libPVZ2.so compressed=%llu | ELF=%llu bytes",
                static_cast<unsigned long long>(result.apk_size),
                static_cast<unsigned long long>(result.elf_compressed_size),
                static_cast<unsigned long long>(result.elf_size)]];

            if (result.ok) {
                [selfRef appendUI:[NSString stringWithFormat:
                    @"STEP 3C: PT_LOAD=%u | guest base=0x%08x | image size=0x%08x",
                    result.load_segments,
                    result.guest_base,
                    result.image_size]];

                [selfRef appendUI:[NSString stringWithFormat:
                    @"STEP 3D: relocations RELATIVE=%u/%u applied | GLOB_DAT=%u | JUMP_SLOT=%u | other=%u",
                    result.relative_applied,
                    result.relative_relocations,
                    result.glob_dat_relocations,
                    result.jump_slot_relocations,
                    result.unsupported_relocations]];

                [selfRef appendUI:[NSString stringWithFormat:
                    @"STEP 3E: dynsym=%u | undefined imports=%u | DT_NEEDED=%u | init_array=%u",
                    result.dynsym_count,
                    result.undefined_symbol_count,
                    result.needed_library_count,
                    result.init_array_count]];

                [selfRef appendUI:[NSString stringWithFormat:
                    @"STEP 3F: SONAME=%@ | JNI_OnLoad ELF=0x%08x → guest=0x%08x",
                    NSStringFromStd(result.soname),
                    result.jni_onload_value,
                    result.jni_onload_guest]];

                [selfRef appendUI:[NSString stringWithFormat:
                    @"STEP 3G: needed: %@",
                    NSStringFromStd(result.needed_libraries)]];

                [selfRef appendUI:[NSString stringWithFormat:
                    @"STEP 3H: exact 1.5.252752 profile=%@",
                    result.exact_15252752_profile ? @"YES" : @"NO"]];

                [selfRef appendUI:[NSString stringWithFormat:
                    @"SUCCESS STEP 3: %@",
                    NSStringFromStd(result.message)]];

                NSString *alertMessage = result.exact_15252752_profile
                    ? @"The exact PvZ2 1.5.252752 ARMv7 ELF profile matched. PT_LOAD mapping and all 48,754 R_ARM_RELATIVE relocations succeeded. The next target is Android/JNI import trampolines and entering JNI_OnLoad."
                    : NSStringFromStd(result.message);

                [selfRef showResult:@"Real PvZ2 ELF mapped" message:alertMessage];
            } else {
                NSString *message = NSStringFromStd(result.message);
                [selfRef appendUI:[NSString stringWithFormat:@"STEP 3 FAILED: %@", message]];
                [selfRef showResult:@"APK / ELF probe failed" message:message];
            }

            [selfRef refreshStatus];
        });
    });
}

@end

@interface ProbeAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation ProbeAppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    ProbeViewController *controller = [[ProbeViewController alloc] init];
    UINavigationController *nav =
        [[UINavigationController alloc] initWithRootViewController:controller];
    self.window.rootViewController = nav;
    [self.window makeKeyAndVisible];
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        setenv("DYNARMIC_DUAL_MAPPED", "1", 1);
        return UIApplicationMain(
            argc,
            argv,
            nil,
            NSStringFromClass([ProbeAppDelegate class]));
    }
}
