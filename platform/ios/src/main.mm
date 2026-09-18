#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libkern/OSCacheControl.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>

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

#if defined(__arm64__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR

__attribute__((noinline, optnone, naked))
void JIT26Detach() {
    __asm__(
        "mov x16, #0\n"
        "brk #0xf00d\n"
        "ret\n"
    );
}

__attribute__((noinline, optnone, naked))
void *JIT26PrepareRegion(void *address, size_t length) {
    __asm__(
        "mov x16, #1\n"
        "brk #0xf00d\n"
        "ret\n"
    );
}

struct JitProbeResult {
    bool ok;
    NSString *message;
};

JitProbeResult RunJitProbe() {
    if (!IsDebugged()) {
        return {false,
            @"CS_DEBUGGED is not set. Enable JIT with StikDebug first, return to this app, then run the probe."};
    }

    const mach_vm_size_t size = static_cast<mach_vm_size_t>(vm_page_size);
    void *rx = JIT26PrepareRegion(nullptr, static_cast<size_t>(size));
    if (rx == nullptr) {
        return {false, @"JIT26PrepareRegion returned NULL."};
    }

    mach_vm_address_t writable = 0;
    vm_prot_t currentProtection = VM_PROT_NONE;
    vm_prot_t maximumProtection = VM_PROT_NONE;

    kern_return_t kr = mach_vm_remap(
        mach_task_self(),
        &writable,
        size,
        0,
        VM_FLAGS_ANYWHERE,
        mach_task_self(),
        reinterpret_cast<mach_vm_address_t>(rx),
        false,
        &currentProtection,
        &maximumProtection,
        VM_INHERIT_NONE);

    if (kr != KERN_SUCCESS) {
        return {false,
            [NSString stringWithFormat:@"mach_vm_remap failed: %d", kr]};
    }

    kr = mach_vm_protect(
        mach_task_self(),
        writable,
        size,
        false,
        VM_PROT_READ | VM_PROT_WRITE);

    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(mach_task_self(), writable, size);
        return {false,
            [NSString stringWithFormat:@"mach_vm_protect(RW alias) failed: %d", kr]};
    }

    // arm64:
    //   mov w0, #42
    //   ret
    const uint32_t code[] = {0x52800540u, 0xD65F03C0u};
    std::memcpy(reinterpret_cast<void *>(writable), code, sizeof(code));
    sys_icache_invalidate(rx, sizeof(code));

    // The universal StikJIT script prepares the initial RX region while attached.
    // Detach only after every executable region required by the probe exists.
    JIT26Detach();

    using ProbeFn = int (*)();
    auto fn = reinterpret_cast<ProbeFn>(rx);
    const int value = fn();

    mach_vm_deallocate(mach_task_self(), writable, size);
    mach_vm_deallocate(
        mach_task_self(),
        reinterpret_cast<mach_vm_address_t>(rx),
        size);

    if (value != 42) {
        return {false,
            [NSString stringWithFormat:@"JIT code executed but returned %d instead of 42.", value]};
    }

    return {true, @"SUCCESS: generated ARM64 code executed and returned 42. iPadOS 26 JIT is working."};
}

#else

JitProbeResult RunJitProbe() {
    return {false, @"This probe must run on a physical arm64 iPhone/iPad."};
}

#endif

NSString *LogFilePath() {
    NSArray<NSURL *> *urls =
        [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory
                                               inDomains:NSUserDomainMask];
    NSURL *documents = urls.firstObject;
    return [[documents URLByAppendingPathComponent:@"pvz2forios-jit.log"] path];
}

void AppendLogLine(NSString *line) {
    NSString *timestamp = [[NSDate date] descriptionWithLocale:nil];
    NSString *entry = [NSString stringWithFormat:@"[%@] %@\n", timestamp, line];

    NSString *path = LogFilePath();
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) {
        [entry writeToFile:path
                atomically:YES
                  encoding:NSUTF8StringEncoding
                     error:nil];
        return;
    }

    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
    [handle seekToEndOfFile];
    NSData *data = [entry dataUsingEncoding:NSUTF8StringEncoding];
    [handle writeData:data];
    [handle closeFile];
}

}  // namespace

@interface ProbeViewController : UIViewController
@property(nonatomic, strong) UILabel *statusLabel;
@property(nonatomic, strong) UITextView *logView;
@end

@implementation ProbeViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.title = @"PvZ2forIOS — JIT Probe";

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"PvZ2forIOS — iPadOS 26 JIT probe";
    title.font = [UIFont boldSystemFontOfSize:28.0];
    title.numberOfLines = 0;

    UILabel *explanation = [[UILabel alloc] init];
    explanation.translatesAutoresizingMaskIntoConstraints = NO;
    explanation.text =
        @"This first build does not contain Plants vs. Zombies 2. "
         "It only verifies that a sideloaded arm64 app can create and execute "
         "Dynarmic-style JIT memory on this iPad.";
    explanation.numberOfLines = 0;
    explanation.font = [UIFont systemFontOfSize:17.0];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:15.0
                                                       weight:UIFontWeightRegular];

    UIButton *enableButton = [UIButton buttonWithType:UIButtonTypeSystem];
    enableButton.translatesAutoresizingMaskIntoConstraints = NO;
    [enableButton setTitle:@"1. Enable JIT with StikDebug"
                  forState:UIControlStateNormal];
    enableButton.titleLabel.font = [UIFont boldSystemFontOfSize:18.0];
    [enableButton addTarget:self
                     action:@selector(openStikDebug)
           forControlEvents:UIControlEventTouchUpInside];

    UIButton *probeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    probeButton.translatesAutoresizingMaskIntoConstraints = NO;
    [probeButton setTitle:@"2. Run JIT probe"
                 forState:UIControlStateNormal];
    probeButton.titleLabel.font = [UIFont boldSystemFontOfSize:18.0];
    [probeButton addTarget:self
                    action:@selector(runProbe)
          forControlEvents:UIControlEventTouchUpInside];

    UIButton *refreshButton = [UIButton buttonWithType:UIButtonTypeSystem];
    refreshButton.translatesAutoresizingMaskIntoConstraints = NO;
    [refreshButton setTitle:@"Refresh status"
                   forState:UIControlStateNormal];
    [refreshButton addTarget:self
                      action:@selector(refreshStatus)
            forControlEvents:UIControlEventTouchUpInside];

    self.logView = [[UITextView alloc] init];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:13.0
                                                    weight:UIFontWeightRegular];
    self.logView.layer.borderWidth = 1.0;
    self.logView.layer.borderColor = UIColor.separatorColor.CGColor;
    self.logView.layer.cornerRadius = 8.0;

    UIStackView *buttons = [[UIStackView alloc]
        initWithArrangedSubviews:@[enableButton, probeButton, refreshButton]];
    buttons.translatesAutoresizingMaskIntoConstraints = NO;
    buttons.axis = UILayoutConstraintAxisHorizontal;
    buttons.spacing = 18.0;
    buttons.distribution = UIStackViewDistributionFillEqually;

    UIStackView *stack = [[UIStackView alloc]
        initWithArrangedSubviews:@[
            title, explanation, self.statusLabel, buttons, self.logView
        ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 18.0;

    [self.view addSubview:stack];

    UILayoutGuide *guide = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:guide.leadingAnchor constant:24.0],
        [stack.trailingAnchor constraintEqualToAnchor:guide.trailingAnchor constant:-24.0],
        [stack.topAnchor constraintEqualToAnchor:guide.topAnchor constant:24.0],
        [stack.bottomAnchor constraintEqualToAnchor:guide.bottomAnchor constant:-24.0],
        [self.logView.heightAnchor constraintGreaterThanOrEqualToConstant:180.0],
        [buttons.heightAnchor constraintEqualToConstant:52.0],
    ]];

    [[NSNotificationCenter defaultCenter]
        addObserver:self
           selector:@selector(refreshStatus)
               name:UIApplicationDidBecomeActiveNotification
             object:nil];

    [self refreshStatus];
    [self appendUI:@"Probe application started."];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)appendUI:(NSString *)line {
    AppendLogLine(line);

    NSString *existing = self.logView.text ?: @"";
    self.logView.text =
        [existing stringByAppendingFormat:@"%@\n", line];

    if (self.logView.text.length > 0) {
        NSRange bottom = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:bottom];
    }
}

- (void)refreshStatus {
    BOOL debugged = IsDebugged();
    BOOL taskAllow = HasGetTaskAllow();
    NSString *bundle = NSBundle.mainBundle.bundleIdentifier ?: @"(unknown)";

    self.statusLabel.text = [NSString stringWithFormat:
        @"Device architecture: arm64\n"
         "PID: %d\n"
         "Bundle ID: %@\n"
         "get-task-allow: %@\n"
         "CS_DEBUGGED: %@\n"
         "Log: Documents/pvz2forios-jit.log",
         getpid(),
         bundle,
         taskAllow ? @"YES" : @"NO",
         debugged ? @"YES" : @"NO"];
}

- (void)openStikDebug {
    if (!HasGetTaskAllow()) {
        [self appendUI:
            @"WARNING: get-task-allow is not present. The current signing method may not permit JIT."];
    }

    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier;
    if (bundleID.length == 0) {
        [self appendUI:@"ERROR: bundle identifier is unavailable."];
        return;
    }

    NSURLComponents *components = [[NSURLComponents alloc] init];
    components.scheme = @"stikdebug";
    components.host = @"enable-jit";

    // This project targets iPadOS 26 and implements StikJIT's universal
    // breakpoint protocol, so the script is developer-defined and fixed.
    components.queryItems = @[
        [NSURLQueryItem queryItemWithName:@"bundle-id" value:bundleID],
        [NSURLQueryItem queryItemWithName:@"pid"
                                    value:[NSString stringWithFormat:@"%d", getpid()]],
        [NSURLQueryItem queryItemWithName:@"script-name" value:@"universal.js"],
    ];

    NSURL *url = components.URL;
    if (url == nil) {
        [self appendUI:@"ERROR: failed to construct StikDebug URL."];
        return;
    }

    [self appendUI:
        [NSString stringWithFormat:@"Requesting JIT from StikDebug for PID %d.", getpid()]];

    [[UIApplication sharedApplication]
        openURL:url
        options:@{}
        completionHandler:^(BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self appendUI:
                    success
                        ? @"StikDebug request opened. Return here after it attaches."
                        : @"ERROR: iPadOS could not open StikDebug. Install/configure StikDebug first."];
            });
        }];
}

- (void)runProbe {
    [self refreshStatus];

    if (!IsDebugged()) {
        [self appendUI:
            @"Probe not started: CS_DEBUGGED is still NO. Use the StikDebug button first."];
        return;
    }

    [self appendUI:
        @"CS_DEBUGGED is set. Calling the iOS 26 universal prepare-region breakpoint..."];

    JitProbeResult result = RunJitProbe();
    [self appendUI:result.message];
    [self refreshStatus];

    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:(result.ok ? @"JIT works" : @"JIT probe failed")
                                            message:result.message
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                             style:UIAlertActionStyleDefault
                                           handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
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
        return UIApplicationMain(
            argc,
            argv,
            nil,
            NSStringFromClass([ProbeAppDelegate class]));
    }
}
