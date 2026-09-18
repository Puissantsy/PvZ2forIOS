#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

#include <dlfcn.h>
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>

extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

namespace {

constexpr unsigned int kCsOpsStatus = 0;
constexpr uint32_t kCsDebugged = 0x10000000u;

struct ProbeState {
    void *rx = nullptr;
    vm_address_t writable = 0;
    vm_size_t size = 0;
    bool prepared = false;
    bool aliasReady = false;
    bool codeWritten = false;
    bool detached = false;
    bool executed = false;
    int result = -1;
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

NSString *ReadPersistentLog() {
    NSString *path = LogFilePath();
    NSError *error = nil;
    NSString *text = [NSString stringWithContentsOfFile:path
                                              encoding:NSUTF8StringEncoding
                                                 error:&error];
    if (text == nil) {
        return @"";
    }
    if (text.length > 16000) {
        return [text substringFromIndex:text.length - 16000];
    }
    return text;
}

NSString *StageName() {
    if (gProbe.executed) return @"executed";
    if (gProbe.detached) return @"detached";
    if (gProbe.codeWritten) return @"code-written";
    if (gProbe.aliasReady) return @"rw-alias-ready";
    if (gProbe.prepared) return @"rx-prepared";
    return @"idle";
}

}  // namespace

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
    self.title = @"PvZ2forIOS — JIT Probe v3";

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"PvZ2forIOS — iPadOS 26 JIT probe v3";
    title.font = [UIFont boldSystemFontOfSize:26.0];
    title.numberOfLines = 0;

    UILabel *explanation = [[UILabel alloc] init];
    explanation.translatesAutoresizingMaskIntoConstraints = NO;
    explanation.text =
        @"Diagnostic build v3: the JIT stages are split up and StikDebug receives a custom resilient script that handles both PC-at-BRK and PC-after-BRK debugger semantics.";
    explanation.numberOfLines = 0;
    explanation.font = [UIFont systemFontOfSize:16.0];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:14.0
                                                       weight:UIFontWeightRegular];

    UIButton *enableButton =
        [self makeButton:@"1. Enable JIT\nwith StikDebug" selector:@selector(openStikDebug)];
    UIButton *prepareButton =
        [self makeButton:@"2. Prepare\nRX region" selector:@selector(prepareRegion)];
    UIButton *aliasButton =
        [self makeButton:@"3. Create RW alias\n+ write code" selector:@selector(createAliasAndWrite)];
    UIButton *detachButton =
        [self makeButton:@"4. Detach\nJIT server" selector:@selector(detachJIT)];
    UIButton *executeButton =
        [self makeButton:@"5. Execute\n(return 42)" selector:@selector(executeCode)];
    UIButton *refreshButton =
        [self makeButton:@"Refresh\nstatus" selector:@selector(refreshStatus)];

    UIStackView *row1 = [[UIStackView alloc]
        initWithArrangedSubviews:@[enableButton, prepareButton, aliasButton]];
    row1.translatesAutoresizingMaskIntoConstraints = NO;
    row1.axis = UILayoutConstraintAxisHorizontal;
    row1.spacing = 12.0;
    row1.distribution = UIStackViewDistributionFillEqually;

    UIStackView *row2 = [[UIStackView alloc]
        initWithArrangedSubviews:@[detachButton, executeButton, refreshButton]];
    row2.translatesAutoresizingMaskIntoConstraints = NO;
    row2.axis = UILayoutConstraintAxisHorizontal;
    row2.spacing = 12.0;
    row2.distribution = UIStackViewDistributionFillEqually;

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
        @"=== Probe v3 session started; PID=%d; stage=%@ ===",
        getpid(), StageName()]];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
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

    self.statusLabel.text = [NSString stringWithFormat:
        @"Device: arm64 | PID: %d | stage: %@\n"
         @"Bundle ID: %@\n"
         @"get-task-allow: %@ | CS_DEBUGGED: %@\n"
         @"RX: %p | RW: 0x%llx | page: %llu bytes",
         getpid(),
         StageName(),
         bundle,
         taskAllow ? @"YES" : @"NO",
         debugged ? @"YES" : @"NO",
         gProbe.rx,
         (unsigned long long)gProbe.writable,
         (unsigned long long)gProbe.size];
}

- (void)openStikDebug {
    if (!HasGetTaskAllow()) {
        [self appendUI:
            @"ERROR: get-task-allow is NO. Reinstall using a compatible development-style signing method."];
        return;
    }

    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier;
    if (bundleID.length == 0) {
        [self appendUI:@"ERROR: bundle identifier is unavailable."];
        return;
    }

    NSString *script =
        @"function le64(h){let b=[];for(let i=0;i<h.length;i+=2)b.push(parseInt(h.substr(i,2),16));let n=0n;for(let i=b.length-1;i>=0;i--)n=(n<<8n)|BigInt(b[i]);return n;}\n"
         @"function le32(h){return parseInt(h.match(/../g).reverse().join(''),16)>>>0;}\n"
         @"function toLE64(n){let a=[];for(let i=0;i<8;i++){a.push(Number(n&255n));n>>=8n;}return a.map(x=>x.toString(16).padStart(2,'0')).join('');}\n"
         @"function brkImm(v){return (v>>>5)&65535;}\n"
         @"const pid=get_pid();log('PvZ2forIOS v3 custom JIT script; pid='+pid);let a=send_command('vAttach;'+pid.toString(16));log('attach='+a);let done=false;\n"
         @"while(!done){let r=send_command('c');log('stop='+r);let tm=/T[0-9a-f]+thread:(?<tid>[0-9a-f]+);/.exec(r);let tid=tm?tm.groups.tid:null;let pm=/20:(?<reg>[0-9a-f]{16});/.exec(r);let xm=/10:(?<reg>[0-9a-f]{16});/.exec(r);let m0=/00:(?<reg>[0-9a-f]{16});/.exec(r);let m1=/01:(?<reg>[0-9a-f]{16});/.exec(r);if(!tid||!pm||!xm||!m0||!m1){log('parse failed; detaching safely');send_command('D');break;}let pc=le64(pm.groups.reg),x16=le64(xm.groups.reg),x0=le64(m0.groups.reg),x1=le64(m1.groups.reg);let at=send_command('m'+pc.toString(16)+',4');let v=at&&at.length>=8?le32(at):0;let brkPc=pc;let pcAlreadyAfter=false;if((v&0xFFE0001F)!==0xD4200000){let prev=pc>=4n?pc-4n:pc;let ph=send_command('m'+prev.toString(16)+',4');let pv=ph&&ph.length>=8?le32(ph):0;if((pv&0xFFE0001F)===0xD4200000){brkPc=prev;v=pv;pcAlreadyAfter=true;log('BRK located at PC-4 (debugger reported post-BRK PC)');}else{log('unexpected stop: pc=0x'+pc.toString(16)+' at='+at+' prev='+ph+'; detaching instead of re-delivering SIGTRAP');send_command('D');break;}}\n"
         @"let imm=brkImm(v);log('BRK imm=0x'+imm.toString(16)+' x16='+x16+' x0=0x'+x0.toString(16)+' x1='+x1);if(imm!==0xf00d){log('not our BRK; detaching safely');send_command('D');break;}if(!pcAlreadyAfter){let pr=send_command('P20='+toLE64(brkPc+4n)+';thread:'+tid+';');log('advancePC='+pr);}if(x16===1n){if(x1===0n){log('prepare requested with zero length');send_command('P0='+toLE64(0n)+';thread:'+tid+';');continue;}let addr=x0;if(addr===0n){let mr=send_command('_M'+x1.toString(16)+',rx');log('allocRX='+mr);if(!mr){send_command('P0='+toLE64(0n)+';thread:'+tid+';');continue;}addr=BigInt('0x'+mr);}let prep=prepare_memory_region(addr,x1);log('prepare='+prep+' addr=0x'+addr.toString(16));let wr=send_command('P0='+toLE64(addr)+';thread:'+tid+';');log('setX0='+wr);continue;}if(x16===0n){let d=send_command('D');log('detach='+d);done=true;break;}log('unknown command '+x16+'; detaching safely');send_command('D');done=true;}\n";

    NSData *scriptData = [script dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64 = [scriptData base64EncodedStringWithOptions:0];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"=" withString:@""];

    NSURLComponents *components = [[NSURLComponents alloc] init];
    components.scheme = @"stikdebug";
    components.host = @"enable-jit";
    components.queryItems = @[
        [NSURLQueryItem queryItemWithName:@"bundle-id" value:bundleID],
        [NSURLQueryItem queryItemWithName:@"pid"
                                    value:[NSString stringWithFormat:@"%d", getpid()]],
        [NSURLQueryItem queryItemWithName:@"script-name" value:@"pvz2forios-v3.js"],
        [NSURLQueryItem queryItemWithName:@"script-data" value:base64],
    ];

    NSURL *url = components.URL;
    if (url == nil) {
        [self appendUI:@"ERROR: failed to construct StikDebug URL."];
        return;
    }

    [self appendUI:
        [NSString stringWithFormat:@"STEP 1: requesting StikDebug with PvZ2forIOS v3 resilient JIT script for PID %d.", getpid()]];

    [[UIApplication sharedApplication]
        openURL:url
        options:@{}
        completionHandler:^(BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self appendUI:
                    success
                        ? @"STEP 1: StikDebug request opened. Wait for it to attach and return here."
                        : @"STEP 1 FAILED: iPadOS could not open StikDebug."];
            });
        }];
}

- (void)prepareRegion {
#if defined(__arm64__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    [self refreshStatus];

    if (!IsDebugged()) {
        [self appendUI:@"STEP 2 BLOCKED: CS_DEBUGGED is NO."];
        return;
    }
    if (gProbe.prepared) {
        [self appendUI:@"STEP 2 SKIPPED: RX region is already prepared."];
        return;
    }

    gProbe.size = static_cast<vm_size_t>(vm_page_size);
    [self appendUI:[NSString stringWithFormat:
        @"STEP 2A: about to execute JIT26PrepareRegion(NULL, %llu). If the app disappears now, the BRK protocol was not handled.",
        (unsigned long long)gProbe.size]];

    void *rx = JIT26PrepareRegion(nullptr, static_cast<size_t>(gProbe.size));

    [self appendUI:[NSString stringWithFormat:
        @"STEP 2B: JIT26PrepareRegion returned %p.", rx]];

    if (rx == nullptr) {
        [self appendUI:@"STEP 2 FAILED: prepare-region returned NULL."];
        [self showResult:@"Prepare failed" message:@"JIT26PrepareRegion returned NULL."];
        return;
    }

    gProbe.rx = rx;
    gProbe.prepared = true;
    [self appendUI:@"STEP 2 SUCCESS: executable RX region prepared."];
    [self refreshStatus];
#else
    [self appendUI:@"STEP 2 FAILED: this is not a physical arm64 iOS device."];
#endif
}

- (void)createAliasAndWrite {
#if defined(__arm64__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    if (!gProbe.prepared || gProbe.rx == nullptr) {
        [self appendUI:@"STEP 3 BLOCKED: run Prepare RX region first."];
        return;
    }
    if (gProbe.codeWritten) {
        [self appendUI:@"STEP 3 SKIPPED: code is already written."];
        return;
    }

    [self appendUI:@"STEP 3A: creating a writable alias of the prepared RX region."];

    vm_address_t writable = 0;
    vm_prot_t currentProtection = VM_PROT_NONE;
    vm_prot_t maximumProtection = VM_PROT_NONE;

    kern_return_t kr = vm_remap(
        mach_task_self(),
        &writable,
        gProbe.size,
        0,
        VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR,
        mach_task_self(),
        reinterpret_cast<vm_address_t>(gProbe.rx),
        false,
        &currentProtection,
        &maximumProtection,
        VM_INHERIT_NONE);

    [self appendUI:[NSString stringWithFormat:
        @"STEP 3B: vm_remap returned %d; RW candidate=0x%llx.",
        kr, (unsigned long long)writable]];

    if (kr != KERN_SUCCESS || writable == 0) {
        [self appendUI:@"STEP 3 FAILED: vm_remap failed."];
        [self showResult:@"RW alias failed"
                 message:[NSString stringWithFormat:@"vm_remap returned %d.", kr]];
        return;
    }

    kr = vm_protect(
        mach_task_self(),
        writable,
        gProbe.size,
        false,
        VM_PROT_READ | VM_PROT_WRITE);

    [self appendUI:[NSString stringWithFormat:
        @"STEP 3C: vm_protect(RW) returned %d.", kr]];

    if (kr != KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), writable, gProbe.size);
        [self appendUI:@"STEP 3 FAILED: could not make alias writable."];
        [self showResult:@"RW protection failed"
                 message:[NSString stringWithFormat:@"vm_protect returned %d.", kr]];
        return;
    }

    gProbe.writable = writable;
    gProbe.aliasReady = true;

    const uint32_t code[] = {0x52800540u, 0xD65F03C0u};
    [self appendUI:@"STEP 3D: writing ARM64 instructions mov w0,#42; ret through RW alias."];
    std::memcpy(reinterpret_cast<void *>(gProbe.writable), code, sizeof(code));
    sys_icache_invalidate(gProbe.rx, sizeof(code));

    gProbe.codeWritten = true;
    [self appendUI:@"STEP 3 SUCCESS: code written and instruction cache invalidated."];
    [self refreshStatus];
#else
    [self appendUI:@"STEP 3 FAILED: this is not a physical arm64 iOS device."];
#endif
}

- (void)detachJIT {
#if defined(__arm64__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    if (!gProbe.codeWritten) {
        [self appendUI:@"STEP 4 BLOCKED: prepare the region and write code first."];
        return;
    }
    if (gProbe.detached) {
        [self appendUI:@"STEP 4 SKIPPED: JIT server already detached."];
        return;
    }
    if (!IsDebugged()) {
        [self appendUI:
            @"STEP 4 BLOCKED: CS_DEBUGGED is already NO. Do not execute another BRK without the script attached."];
        return;
    }

    [self appendUI:
        @"STEP 4A: about to execute JIT26Detach(). If the app disappears now, the detach BRK was not handled."];
    JIT26Detach();
    gProbe.detached = true;
    [self appendUI:@"STEP 4 SUCCESS: detach BRK returned to the app."];
    [self refreshStatus];
#else
    [self appendUI:@"STEP 4 FAILED: this is not a physical arm64 iOS device."];
#endif
}

- (void)executeCode {
#if defined(__arm64__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    if (!gProbe.codeWritten || gProbe.rx == nullptr) {
        [self appendUI:@"STEP 5 BLOCKED: code has not been written yet."];
        return;
    }
    if (!gProbe.detached) {
        [self appendUI:
            @"STEP 5 BLOCKED: detach the JIT server first so this diagnostic follows the documented iOS 26 sequence."];
        return;
    }

    [self appendUI:[NSString stringWithFormat:
        @"STEP 5A: about to branch to generated RX code at %p. If the app disappears now, executable-region preparation or aliasing is the failure point.",
        gProbe.rx]];

    using ProbeFn = int (*)();
    auto fn = reinterpret_cast<ProbeFn>(gProbe.rx);
    const int value = fn();

    gProbe.executed = true;
    gProbe.result = value;
    [self appendUI:[NSString stringWithFormat:
        @"STEP 5B: generated code returned %d.", value]];

    if (value == 42) {
        [self appendUI:
            @"SUCCESS: generated ARM64 code executed and returned 42. iPadOS 26 JIT path is working."];
        [self showResult:@"JIT works"
                 message:@"Generated ARM64 code executed successfully and returned 42."];
    } else {
        [self appendUI:@"STEP 5 FAILED: generated code returned the wrong value."];
        [self showResult:@"Unexpected result"
                 message:[NSString stringWithFormat:@"Generated code returned %d instead of 42.", value]];
    }
    [self refreshStatus];
#else
    [self appendUI:@"STEP 5 FAILED: this is not a physical arm64 iOS device."];
#endif
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
