#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

#include <dlfcn.h>
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <cstdint>
#include <cstring>

extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

namespace {

constexpr unsigned int kCsOpsStatus = 0;
constexpr uint32_t kCsDebugged = 0x10000000u;

struct ProbeState {
    void *rx = nullptr;
    vm_address_t rw = 0;
    vm_size_t size = 0;
    bool mapped = false;
    bool codeWritten = false;
    bool executed = false;
    int result = -1;
    bool step1ReadyLogged = false;
};

ProbeState gProbe;

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

    if (value != nullptr) CFRelease(value);
    CFRelease(reinterpret_cast<CFTypeRef>(task));
    return result;
}

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
    if (text == nil) return @"";
    if (text.length > 16000) return [text substringFromIndex:text.length - 16000];
    return text;
}

NSString *StageName() {
    if (gProbe.executed) return @"executed";
    if (gProbe.codeWritten) return @"code-written";
    if (gProbe.mapped) return @"dual-map-ready";
    if (IsDebugged()) return @"jit-enabled";
    return @"idle";
}

void CleanupProbe() {
    if (gProbe.rw != 0 && gProbe.size != 0) {
        vm_deallocate(mach_task_self(), gProbe.rw, gProbe.size);
    }
    if (gProbe.rx != nullptr && gProbe.size != 0) {
        munmap(gProbe.rx, gProbe.size);
    }
    gProbe = {};
}

} // namespace

@interface ProbeViewController : UIViewController
@property(nonatomic, strong) UILabel *statusLabel;
@property(nonatomic, strong) UITextView *logView;
@end

@implementation ProbeViewController

- (UIButton *)makeButton:(NSString *)title selector:(SEL)selector {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.translatesAutoresizingMaskIntoConstraints = NO;
    [button setTitle:title forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:16.0];
    button.titleLabel.numberOfLines = 2;
    button.titleLabel.textAlignment = NSTextAlignmentCenter;
    [button addTarget:self action:selector forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.title = @"PvZ2forIOS — JIT Probe v6";

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"PvZ2forIOS — iPadOS 26 Non-TXM JIT probe v6";
    title.font = [UIFont boldSystemFontOfSize:26.0];
    title.numberOfLines = 0;

    UILabel *explanation = [[UILabel alloc] init];
    explanation.translatesAutoresizingMaskIntoConstraints = NO;
    explanation.text =
        @"iPad 10th generation / A14 is Non-TXM. This build uses the documented "
         @"non-TXM path: debugger attach only, then an RX mapping with a separate RW mirror. "
         @"There are no JIT breakpoint scripts in this build.";
    explanation.numberOfLines = 0;
    explanation.font = [UIFont systemFontOfSize:16.0];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:14.0 weight:UIFontWeightRegular];

    UIButton *enableButton =
        [self makeButton:@"1. Enable JIT\nNon-TXM" selector:@selector(enableJIT)];
    UIButton *mapButton =
        [self makeButton:@"2. Allocate\nRX + RW mirror" selector:@selector(allocateDualMap)];
    UIButton *writeButton =
        [self makeButton:@"3. Write\nreturn 42" selector:@selector(writeCode)];
    UIButton *executeButton =
        [self makeButton:@"4. Execute\nreturn 42" selector:@selector(executeCode)];
    UIButton *cleanupButton =
        [self makeButton:@"Cleanup\nmapping" selector:@selector(cleanupMapping)];
    UIButton *refreshButton =
        [self makeButton:@"Refresh\nstatus" selector:@selector(refreshStatus)];

    UIStackView *row1 = [[UIStackView alloc]
        initWithArrangedSubviews:@[enableButton, mapButton, writeButton]];
    row1.translatesAutoresizingMaskIntoConstraints = NO;
    row1.axis = UILayoutConstraintAxisHorizontal;
    row1.spacing = 12.0;
    row1.distribution = UIStackViewDistributionFillEqually;

    UIStackView *row2 = [[UIStackView alloc]
        initWithArrangedSubviews:@[executeButton, cleanupButton, refreshButton]];
    row2.translatesAutoresizingMaskIntoConstraints = NO;
    row2.axis = UILayoutConstraintAxisHorizontal;
    row2.spacing = 12.0;
    row2.distribution = UIStackViewDistributionFillEqually;

    self.logView = [[UITextView alloc] init];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:12.0 weight:UIFontWeightRegular];
    self.logView.layer.borderWidth = 1.0;
    self.logView.layer.borderColor = UIColor.separatorColor.CGColor;
    self.logView.layer.cornerRadius = 8.0;
    self.logView.text = ReadPersistentLog();

    UIStackView *stack = [[UIStackView alloc]
        initWithArrangedSubviews:@[
            title, explanation, self.statusLabel, row1, row2, self.logView
        ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12.0;

    [self.view addSubview:stack];

    UILayoutGuide *guide = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:guide.leadingAnchor constant:24.0],
        [stack.trailingAnchor constraintEqualToAnchor:guide.trailingAnchor constant:-24.0],
        [stack.topAnchor constraintEqualToAnchor:guide.topAnchor constant:18.0],
        [stack.bottomAnchor constraintEqualToAnchor:guide.bottomAnchor constant:-18.0],
        [row1.heightAnchor constraintEqualToConstant:56.0],
        [row2.heightAnchor constraintEqualToConstant:56.0],
        [self.logView.heightAnchor constraintGreaterThanOrEqualToConstant:190.0],
    ]];

    [[NSNotificationCenter defaultCenter]
        addObserver:self
           selector:@selector(refreshStatus)
               name:UIApplicationDidBecomeActiveNotification
             object:nil];

    [self refreshStatus];
    [self appendUI:[NSString stringWithFormat:
        @"=== Probe v6 Non-TXM session started; PID=%d ===", getpid()]];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    CleanupProbe();
}

- (void)appendUI:(NSString *)line {
    AppendLogLine(line);
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
    BOOL debugged = IsDebugged();
    BOOL taskAllow = HasGetTaskAllow();
    NSString *bundle = NSBundle.mainBundle.bundleIdentifier ?: @"(unknown)";

    if (debugged && !gProbe.step1ReadyLogged) {
        gProbe.step1ReadyLogged = true;
        [self appendUI:
            @"STEP 1 READY: CS_DEBUGGED is YES. Non-TXM JIT acquisition is complete; no breakpoint script is required."];
    }

    self.statusLabel.text = [NSString stringWithFormat:
        @"Device: arm64 | PID: %d | mode: Non-TXM | stage: %@\n"
         @"Bundle ID: %@\n"
         @"get-task-allow: %@ | CS_DEBUGGED: %@\n"
         @"RX: %p | RW: 0x%llx | page: %llu bytes",
         getpid(),
         StageName(),
         bundle,
         taskAllow ? @"YES" : @"NO",
         debugged ? @"YES" : @"NO",
         gProbe.rx,
         (unsigned long long)gProbe.rw,
         (unsigned long long)gProbe.size];
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
        @"STEP 1: requesting classic Non-TXM debugger attach. No script is being sent to StikDebug."];

    [[UIApplication sharedApplication]
        openURL:url
        options:@{}
        completionHandler:^(BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self appendUI:
                    success
                        ? @"STEP 1: StikDebug request opened. Return here after StikDebug finishes the attach/detach."
                        : @"STEP 1 FAILED: iPadOS could not open StikDebug."];
            });
        }];
}

- (void)allocateDualMap {
#if defined(__arm64__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    [self refreshStatus];

    if (!IsDebugged()) {
        [self appendUI:@"STEP 2 BLOCKED: CS_DEBUGGED is NO. Complete step 1 first."];
        return;
    }
    if (gProbe.mapped) {
        [self appendUI:@"STEP 2 SKIPPED: dual mapping already exists."];
        return;
    }

    gProbe.size = static_cast<vm_size_t>(vm_page_size);
    [self appendUI:[NSString stringWithFormat:
        @"STEP 2A: mmap RX page (%llu bytes).", (unsigned long long)gProbe.size]];

    errno = 0;
    void *rx = mmap(nullptr,
                    gProbe.size,
                    PROT_READ | PROT_EXEC,
                    MAP_ANON | MAP_PRIVATE,
                    -1,
                    0);

    if (rx == MAP_FAILED) {
        int e = errno;
        gProbe.rx = nullptr;
        [self appendUI:[NSString stringWithFormat:
            @"STEP 2 FAILED: mmap(RX) errno=%d (%s).", e, strerror(e)]];
        return;
    }

    gProbe.rx = rx;
    [self appendUI:[NSString stringWithFormat:
        @"STEP 2B: RX mapping created at %p.", gProbe.rx]];

    vm_address_t rw = 0;
    vm_prot_t currentProtection = VM_PROT_NONE;
    vm_prot_t maximumProtection = VM_PROT_NONE;

    kern_return_t kr = vm_remap(
        mach_task_self(),
        &rw,
        gProbe.size,
        0,
        VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR,
        mach_task_self(),
        reinterpret_cast<vm_address_t>(gProbe.rx),
        false,
        &currentProtection,
        &maximumProtection,
        VM_INHERIT_DEFAULT);

    [self appendUI:[NSString stringWithFormat:
        @"STEP 2C: vm_remap returned %d; RW candidate=0x%llx.",
        kr, (unsigned long long)rw]];

    if (kr != KERN_SUCCESS || rw == 0) {
        munmap(gProbe.rx, gProbe.size);
        gProbe.rx = nullptr;
        [self appendUI:@"STEP 2 FAILED: could not create RW mirror."];
        return;
    }

    kr = vm_protect(
        mach_task_self(),
        rw,
        gProbe.size,
        false,
        VM_PROT_READ | VM_PROT_WRITE);

    [self appendUI:[NSString stringWithFormat:
        @"STEP 2D: vm_protect(RW mirror) returned %d.", kr]];

    if (kr != KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), rw, gProbe.size);
        munmap(gProbe.rx, gProbe.size);
        gProbe.rx = nullptr;
        [self appendUI:@"STEP 2 FAILED: RW mirror protection failed."];
        return;
    }

    gProbe.rw = rw;
    gProbe.mapped = true;
    [self appendUI:@"STEP 2 SUCCESS: Non-TXM RX/RW dual mapping is ready."];
    [self refreshStatus];
#else
    [self appendUI:@"STEP 2 FAILED: physical arm64 iOS device required."];
#endif
}

- (void)writeCode {
#if defined(__arm64__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    if (!gProbe.mapped || gProbe.rx == nullptr || gProbe.rw == 0) {
        [self appendUI:@"STEP 3 BLOCKED: allocate RX/RW mapping first."];
        return;
    }
    if (gProbe.codeWritten) {
        [self appendUI:@"STEP 3 SKIPPED: code already written."];
        return;
    }

    const uint32_t code[] = {
        0x52800540u,
        0xD65F03C0u,
    };

    [self appendUI:@"STEP 3A: writing generated ARM64 return-42 code through RW mirror."];
    std::memcpy(reinterpret_cast<void *>(gProbe.rw), code, sizeof(code));
    sys_icache_invalidate(gProbe.rx, sizeof(code));

    gProbe.codeWritten = true;
    [self appendUI:@"STEP 3 SUCCESS: code written; instruction cache invalidated."];
    [self refreshStatus];
#else
    [self appendUI:@"STEP 3 FAILED: physical arm64 iOS device required."];
#endif
}

- (void)executeCode {
#if defined(__arm64__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    if (!gProbe.codeWritten || gProbe.rx == nullptr) {
        [self appendUI:@"STEP 4 BLOCKED: write code first."];
        return;
    }

    [self appendUI:[NSString stringWithFormat:
        @"STEP 4A: executing generated code from RX address %p.", gProbe.rx]];

    using ProbeFn = int (*)();
    auto fn = reinterpret_cast<ProbeFn>(gProbe.rx);
    int value = fn();

    gProbe.executed = true;
    gProbe.result = value;

    [self appendUI:[NSString stringWithFormat:
        @"STEP 4B: generated code returned %d.", value]];

    if (value == 42) {
        [self appendUI:
            @"SUCCESS: classic Non-TXM JIT works on this iPad. Generated ARM64 code returned 42."];
        [self showResult:@"JIT works"
                 message:@"Non-TXM JIT succeeded. Generated ARM64 code returned 42."];
    } else {
        [self appendUI:@"STEP 4 FAILED: wrong return value."];
        [self showResult:@"Unexpected result"
                 message:[NSString stringWithFormat:@"Returned %d instead of 42.", value]];
    }
    [self refreshStatus];
#else
    [self appendUI:@"STEP 4 FAILED: physical arm64 iOS device required."];
#endif
}

- (void)cleanupMapping {
    CleanupProbe();
    [self appendUI:@"Mappings cleaned up."];
    [self refreshStatus];
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
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([ProbeAppDelegate class]));
    }
}
