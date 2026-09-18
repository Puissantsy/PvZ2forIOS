#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "dynarmic_smoke.hpp"

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
    return [[documents URLByAppendingPathComponent:@"pvz2forios-dynarmic.log"] path];
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
    if (text.length > 18000) {
        return [text substringFromIndex:text.length - 18000];
    }
    return text;
}

} // namespace

@interface ProbeViewController : UIViewController
@property(nonatomic, strong) UILabel *statusLabel;
@property(nonatomic, strong) UITextView *logView;
@property(nonatomic, strong) UIButton *dynarmicButton;
@property(nonatomic, assign) BOOL dynarmicRunning;
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
    self.title = @"PvZ2forIOS — Dynarmic Probe v7";

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"PvZ2forIOS — ARM32 → ARM64 Dynarmic probe v7";
    title.font = [UIFont boldSystemFontOfSize:26.0];
    title.numberOfLines = 0;

    UILabel *explanation = [[UILabel alloc] init];
    explanation.translatesAutoresizingMaskIntoConstraints = NO;
    explanation.text =
        @"The raw iPadOS JIT path is already validated. This build performs the next milestone: "
         @"Dynarmic receives a tiny ARMv7 program (MOV 40, ADD 2, SVC), translates it to native "
         @"ARM64 in its own iOS dual-mapped code cache, executes it, and must return R0 = 42.";
    explanation.numberOfLines = 0;
    explanation.font = [UIFont systemFontOfSize:16.0];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:14.0
                                                       weight:UIFontWeightRegular];

    UIButton *enableButton =
        [self makeButton:@"1. Enable JIT\nwith StikDebug" selector:@selector(enableJIT)];

    self.dynarmicButton =
        [self makeButton:@"2. Run Dynarmic\nARM32 → 42" selector:@selector(runDynarmic)];

    UIButton *refreshButton =
        [self makeButton:@"Refresh\nstatus" selector:@selector(refreshStatus)];

    UIStackView *buttons = [[UIStackView alloc]
        initWithArrangedSubviews:@[enableButton, self.dynarmicButton, refreshButton]];
    buttons.translatesAutoresizingMaskIntoConstraints = NO;
    buttons.axis = UILayoutConstraintAxisHorizontal;
    buttons.spacing = 12.0;
    buttons.distribution = UIStackViewDistributionFillEqually;

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
            title, explanation, self.statusLabel, buttons, self.logView
        ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 14.0;

    [self.view addSubview:stack];

    UILayoutGuide *guide = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:guide.leadingAnchor constant:24.0],
        [stack.trailingAnchor constraintEqualToAnchor:guide.trailingAnchor constant:-24.0],
        [stack.topAnchor constraintEqualToAnchor:guide.topAnchor constant:18.0],
        [stack.bottomAnchor constraintEqualToAnchor:guide.bottomAnchor constant:-18.0],
        [buttons.heightAnchor constraintEqualToConstant:64.0],
        [self.logView.heightAnchor constraintGreaterThanOrEqualToConstant:300.0],
    ]];

    [[NSNotificationCenter defaultCenter]
        addObserver:self
           selector:@selector(refreshStatus)
               name:UIApplicationDidBecomeActiveNotification
             object:nil];

    [self appendUI:[NSString stringWithFormat:
        @"=== Dynarmic probe v7 session started; PID=%d ===", getpid()]];
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
        @"Device: arm64 | PID: %d | iPad 10th gen / Non-TXM\n"
         @"Bundle ID: %@\n"
         @"get-task-allow: %@ | CS_DEBUGGED: %@\n"
         @"Dynarmic test: %@",
         getpid(),
         bundle,
         taskAllow ? @"YES" : @"NO",
         debugged ? @"YES" : @"NO",
         self.dynarmicRunning ? @"RUNNING…" : @"ready to run"];

    self.dynarmicButton.enabled = !self.dynarmicRunning;
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
        @"STEP 1: requesting Non-TXM debugger attach/detach. No script is sent."];

    [[UIApplication sharedApplication]
        openURL:url
        options:@{}
        completionHandler:^(BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self appendUI:
                    success
                        ? @"STEP 1: StikDebug request opened. Return here; CS_DEBUGGED=YES means it is ready."
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
        @"STEP 2A: constructing Dynarmic A32 JIT with an 8 MiB iOS dual-mapped code cache."];

    __weak ProbeViewController *weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        DynarmicSmokeResult result = RunDynarmicArm32Smoke();

        dispatch_async(dispatch_get_main_queue(), ^{
            ProbeViewController *selfRef = weakSelf;
            if (!selfRef) {
                return;
            }

            selfRef.dynarmicRunning = NO;

            NSString *line = [NSString stringWithFormat:
                @"STEP 2B: ok=%@ R0=%u PC=0x%08x halt=0x%08x svc=%@ exception=%@",
                result.ok ? @"YES" : @"NO",
                result.r0,
                result.pc,
                result.halt_reason,
                result.svc_seen ? @"YES" : @"NO",
                result.exception_seen ? @"YES" : @"NO"];
            [selfRef appendUI:line];

            NSString *message =
                [NSString stringWithUTF8String:result.message.c_str()] ?: @"(no message)";
            [selfRef appendUI:[NSString stringWithFormat:@"STEP 2C: %@", message]];

            if (result.ok) {
                [selfRef appendUI:
                    @"SUCCESS: Dynarmic executed ARM32 guest code on the A14 and returned R0=42."];
                [selfRef showResult:@"Dynarmic works"
                            message:@"ARM32 → Dynarmic → generated ARM64 → A14 succeeded. Guest R0 returned 42."];
            } else {
                [selfRef appendUI:@"FAILED: Dynarmic ARM32 smoke test did not complete successfully."];
                [selfRef showResult:@"Dynarmic test failed" message:message];
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
        // LiveContainer's Dynarmic fork auto-detects iOS 26 dual mapping, but
        // explicitly opting in documents the required policy for this target.
        setenv("DYNARMIC_DUAL_MAPPED", "1", 1);
        return UIApplicationMain(
            argc,
            argv,
            nil,
            NSStringFromClass([ProbeAppDelegate class]));
    }
}
