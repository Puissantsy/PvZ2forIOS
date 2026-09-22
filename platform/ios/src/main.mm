#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
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

@interface PvZ2LiveViewController : UIViewController

@property(nonatomic, strong)
    UIImageView *imageView;
@property(nonatomic, strong)
    UILabel *captionLabel;
@property(nonatomic, strong)
    UIButton *stopButton;
@property(nonatomic, strong)
    NSMutableDictionary<NSValue *, NSNumber *> *touchIds;
@property(nonatomic, strong)
    NSMutableIndexSet *availableTouchIds;
@property(nonatomic, assign)
    NSUInteger sourceWidth;
@property(nonatomic, assign)
    NSUInteger sourceHeight;
@property(nonatomic, assign)
    BOOL inputEnabled;
@property(nonatomic, assign)
    BOOL runFinished;

- (void)updateFrameData:
        (NSData *)data
    width:
        (NSUInteger)width
    height:
        (NSUInteger)height
    frame:
        (NSUInteger)frame;

- (void)finishRunWithMessage:
        (NSString *)message;

@end

static __weak PvZ2LiveViewController *
    gPvZ2LiveController = nil;

@implementation PvZ2LiveViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor =
        UIColor.blackColor;
    self.view.multipleTouchEnabled =
        YES;

    self.touchIds =
        [[NSMutableDictionary alloc] init];
    self.availableTouchIds =
        [NSMutableIndexSet
            indexSetWithIndexesInRange:
                NSMakeRange(0, 32)];

    self.captionLabel =
        [[UILabel alloc] init];
    self.captionLabel.translatesAutoresizingMaskIntoConstraints =
        NO;
    self.captionLabel.textColor =
        UIColor.whiteColor;
    self.captionLabel.textAlignment =
        NSTextAlignmentCenter;
    self.captionLabel.numberOfLines =
        0;
    self.captionLabel.font =
        [UIFont
            monospacedSystemFontOfSize:13.0
            weight:UIFontWeightRegular];
    self.captionLabel.text =
        @"v72 LIVE — starting PvZ2…\nTouches become active as soon as live frames arrive.";

    self.imageView =
        [[UIImageView alloc] init];
    self.imageView.translatesAutoresizingMaskIntoConstraints =
        NO;
    self.imageView.backgroundColor =
        UIColor.blackColor;
    self.imageView.contentMode =
        UIViewContentModeScaleAspectFit;
    self.imageView.userInteractionEnabled =
        YES;
    self.imageView.multipleTouchEnabled =
        YES;

    self.stopButton =
        [UIButton
            buttonWithType:UIButtonTypeSystem];
    self.stopButton.translatesAutoresizingMaskIntoConstraints =
        NO;
    [self.stopButton
        setTitle:@"Stop run"
        forState:UIControlStateNormal];
    self.stopButton.titleLabel.font =
        [UIFont
            boldSystemFontOfSize:18.0];
    [self.stopButton
        addTarget:self
        action:@selector(stopOrClose)
        forControlEvents:UIControlEventTouchUpInside];

    [self.view addSubview:self.captionLabel];
    [self.view addSubview:self.imageView];
    [self.view addSubview:self.stopButton];

    UILayoutGuide *guide =
        self.view.safeAreaLayoutGuide;

    [NSLayoutConstraint
        activateConstraints:@[
            [self.captionLabel.topAnchor
                constraintEqualToAnchor:guide.topAnchor
                constant:8.0],
            [self.captionLabel.leadingAnchor
                constraintEqualToAnchor:guide.leadingAnchor
                constant:12.0],
            [self.captionLabel.trailingAnchor
                constraintEqualToAnchor:guide.trailingAnchor
                constant:-12.0],

            [self.imageView.topAnchor
                constraintEqualToAnchor:self.captionLabel.bottomAnchor
                constant:8.0],
            [self.imageView.leadingAnchor
                constraintEqualToAnchor:guide.leadingAnchor
                constant:8.0],
            [self.imageView.trailingAnchor
                constraintEqualToAnchor:guide.trailingAnchor
                constant:-8.0],

            [self.stopButton.topAnchor
                constraintEqualToAnchor:self.imageView.bottomAnchor
                constant:8.0],
            [self.stopButton.bottomAnchor
                constraintEqualToAnchor:guide.bottomAnchor
                constant:-8.0],
            [self.stopButton.centerXAnchor
                constraintEqualToAnchor:guide.centerXAnchor],
            [self.stopButton.heightAnchor
                constraintEqualToConstant:44.0],
        ]];
}

- (void)stopOrClose {
    if (self.runFinished) {
        [self
            dismissViewControllerAnimated:YES
            completion:nil];
        return;
    }

    self.inputEnabled = NO;
    self.captionLabel.text =
        @"v72 LIVE — stop requested; finishing the current guest frame…";
    self.stopButton.enabled = NO;
    PvZ2RequestInteractiveStop();
}

- (NSInteger)identifierForTouch:
        (UITouch *)touch
    create:
        (BOOL)create {

    NSValue *key =
        [NSValue
            valueWithNonretainedObject:
                touch];

    NSNumber *existing =
        self.touchIds[key];

    if (existing != nil) {
        return existing.integerValue;
    }

    if (!create) {
        return -1;
    }

    const NSUInteger identifier =
        self.availableTouchIds.firstIndex;

    if (identifier == NSNotFound) {
        return -1;
    }

    [self.availableTouchIds
        removeIndex:identifier];

    self.touchIds[key] =
        @(identifier);

    return
        static_cast<NSInteger>(
            identifier);
}

- (void)releaseIdentifierForTouch:
        (UITouch *)touch {

    NSValue *key =
        [NSValue
            valueWithNonretainedObject:
                touch];

    NSNumber *identifier =
        self.touchIds[key];

    if (identifier == nil) {
        return;
    }

    [self.availableTouchIds
        addIndex:
            identifier.unsignedIntegerValue];

    [self.touchIds
        removeObjectForKey:key];
}

- (BOOL)mapTouch:
        (UITouch *)touch
    x:
        (std::int32_t *)x
    y:
        (std::int32_t *)y
    previousX:
        (std::int32_t *)previousX
    previousY:
        (std::int32_t *)previousY {

    if (!self.inputEnabled ||
        self.sourceWidth == 0u ||
        self.sourceHeight == 0u ||
        (touch.view != self.imageView &&
         touch.view != self.view)) {
        return NO;
    }

    const CGSize bounds =
        self.imageView.bounds.size;

    if (bounds.width <= 0.0 ||
        bounds.height <= 0.0) {
        return NO;
    }

    const CGFloat sourceWidth =
        static_cast<CGFloat>(
            self.sourceWidth);
    const CGFloat sourceHeight =
        static_cast<CGFloat>(
            self.sourceHeight);

    const CGFloat scale =
        MIN(
            bounds.width / sourceWidth,
            bounds.height / sourceHeight);

    if (scale <= 0.0) {
        return NO;
    }

    const CGFloat renderedWidth =
        sourceWidth * scale;
    const CGFloat renderedHeight =
        sourceHeight * scale;
    const CGFloat offsetX =
        (bounds.width -
         renderedWidth) *
        0.5;
    const CGFloat offsetY =
        (bounds.height -
         renderedHeight) *
        0.5;

    const CGPoint point =
        [touch
            locationInView:
                self.imageView];

    if (point.x < offsetX ||
        point.y < offsetY ||
        point.x >=
            offsetX + renderedWidth ||
        point.y >=
            offsetY + renderedHeight) {
        return NO;
    }

    CGPoint previous =
        [touch
            previousLocationInView:
                self.imageView];

    previous.x =
        std::clamp<CGFloat>(
            previous.x,
            offsetX,
            offsetX +
                renderedWidth -
                0.001);
    previous.y =
        std::clamp<CGFloat>(
            previous.y,
            offsetY,
            offsetY +
                renderedHeight -
                0.001);

    auto convert =
        [&](CGPoint value,
            std::int32_t& outX,
            std::int32_t& outY) {

            const CGFloat logicalX =
                (value.x - offsetX) /
                scale;
            const CGFloat logicalY =
                (value.y - offsetY) /
                scale;

            outX =
                static_cast<std::int32_t>(
                    std::clamp<long>(
                        std::lround(logicalX),
                        0l,
                        static_cast<long>(
                            self.sourceWidth - 1u)));

            outY =
                static_cast<std::int32_t>(
                    std::clamp<long>(
                        std::lround(logicalY),
                        0l,
                        static_cast<long>(
                            self.sourceHeight - 1u)));
        };

    convert(
        point,
        *x,
        *y);
    convert(
        previous,
        *previousX,
        *previousY);

    return YES;
}

- (void)queueTouches:
        (NSSet<UITouch *> *)touches
    phase:
        (std::uint32_t)phase
    release:
        (BOOL)release {

    for (UITouch *touch in touches) {
        const NSInteger identifier =
            [self
                identifierForTouch:
                    touch
                create:YES];

        if (identifier < 0) {
            continue;
        }

        std::int32_t x = 0;
        std::int32_t y = 0;
        std::int32_t previousX = 0;
        std::int32_t previousY = 0;

        if ([self
                mapTouch:
                    touch
                x:&x
                y:&y
                previousX:&previousX
                previousY:&previousY]) {

            PvZ2QueueTouchEvent(
                static_cast<std::uint32_t>(
                    identifier),
                x,
                y,
                previousX,
                previousY,
                phase,
                touch.timestamp * 1000.0);
        }

        if (release) {
            [self
                releaseIdentifierForTouch:
                    touch];
        }
    }
}

- (void)touchesBegan:
        (NSSet<UITouch *> *)touches
    withEvent:
        (UIEvent *)event {

    [self
        queueTouches:
            touches
        phase:0u
        release:NO];

    [super
        touchesBegan:
            touches
        withEvent:
            event];
}

- (void)touchesMoved:
        (NSSet<UITouch *> *)touches
    withEvent:
        (UIEvent *)event {

    [self
        queueTouches:
            touches
        phase:1u
        release:NO];

    [super
        touchesMoved:
            touches
        withEvent:
            event];
}

- (void)touchesEnded:
        (NSSet<UITouch *> *)touches
    withEvent:
        (UIEvent *)event {

    [self
        queueTouches:
            touches
        phase:3u
        release:YES];

    [super
        touchesEnded:
            touches
        withEvent:
            event];
}

- (void)touchesCancelled:
        (NSSet<UITouch *> *)touches
    withEvent:
        (UIEvent *)event {

    [self
        queueTouches:
            touches
        phase:4u
        release:YES];

    [super
        touchesCancelled:
            touches
        withEvent:
            event];
}

- (void)updateFrameData:
        (NSData *)data
    width:
        (NSUInteger)width
    height:
        (NSUInteger)height
    frame:
        (NSUInteger)frame {

    if (data.length !=
            width * height * 4u ||
        width == 0u ||
        height == 0u) {
        return;
    }

    CGColorSpaceRef colorSpace =
        CGColorSpaceCreateDeviceRGB();

    CGDataProviderRef provider =
        CGDataProviderCreateWithCFData(
            (__bridge CFDataRef)data);

    CGImageRef imageRef =
        CGImageCreate(
            width,
            height,
            8,
            32,
            width * 4u,
            colorSpace,
            kCGBitmapByteOrder32Big |
                kCGImageAlphaLast,
            provider,
            nullptr,
            false,
            kCGRenderingIntentDefault);

    if (imageRef != nullptr) {
        self.imageView.image =
            [UIImage
                imageWithCGImage:
                    imageRef];
        CGImageRelease(imageRef);
    }

    CGDataProviderRelease(provider);
    CGColorSpaceRelease(colorSpace);

    self.sourceWidth = width;
    self.sourceHeight = height;

    if (!self.runFinished) {
        // v71 established useful pixels by frame 3. Avoid accepting an
        // accidental tap on the initial black startup buffers.
        self.inputEnabled =
            frame >= 3u;

        self.captionLabel.text =
            [NSString
                stringWithFormat:
                    @"v72 LIVE — guest frame %lu — %@\nUIKit touch → AndroidUIEventManager (1180×820 logical)",
                    (unsigned long)frame,
                    self.inputEnabled
                        ? @"TOUCH ENABLED"
                        : @"warming up…"];
    }
}

- (void)finishRunWithMessage:
        (NSString *)message {

    self.runFinished = YES;
    self.inputEnabled = NO;
    self.captionLabel.text =
        message ?: @"v72 LIVE — run finished.";
    self.stopButton.enabled = YES;

    [self.stopButton
        setTitle:@"Close"
        forState:UIControlStateNormal];
}

@end

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

@property(nonatomic, strong)
    UISegmentedControl *diagnosticModeControl;

@property(nonatomic, strong)
    PvZ2LiveViewController *liveController;

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
        @"PvZ2forIOS — v72 Live Touch Bridge";

    UILabel *title =
        [[UILabel alloc] init];

    title.translatesAutoresizingMaskIntoConstraints =
        NO;

    title.text =
        @"PvZ2forIOS — v72 Live Touch Bridge";

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
        @"v72 starts the interactive phase. v71 already renders the real first-run/MainMenu screen and survives 600 frames. v72 keeps the zlib + ETC1 fixes, streams the live framebuffer into UIKit, and feeds real iPad touches into AndroidUIEventManager using the exact APK event format. No GameState, resource readiness or UI action is forced.";

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

    self.diagnosticModeControl =
        [[UISegmentedControl alloc]
            initWithItems:
                @[
                    @"V56 Baseline",
                    @"V72 Live Touch",
                    @"V66 Blocking Waits",
                    @"V65 Cond Scheduler",
                    @"Ctype Deep Scout"
                ]];

    self.diagnosticModeControl.translatesAutoresizingMaskIntoConstraints =
        NO;
    self.diagnosticModeControl.selectedSegmentIndex =
        1;

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
                    self.diagnosticModeControl,
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

                [self.diagnosticModeControl.heightAnchor
                    constraintEqualToConstant:
                        34.0],

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
        @"v53 passive — FINAL framebuffer (no state forcing)\nTap Close to inspect exact GameState + preserved v52 diagnostics.";

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

    NSArray<NSString *> *modeNames =
        @[
            @"V56_BASELINE",
            @"V72_LIVE_TOUCH_BRIDGE",
            @"V66_BLOCKING_WAIT_SCHEDULER",
            @"V65_CONDITION_VARIABLE_SCHEDULER",
            @"CTYPE_COMPAT_DEEP_SCOUT"
        ];

    NSInteger modeIndex =
        self.diagnosticModeControl.selectedSegmentIndex;

    if (modeIndex < 0 ||
        modeIndex >=
            (NSInteger)modeNames.count) {
        modeIndex = 0;
    }

    [self
        appendUI:
            [NSString
                stringWithFormat:
                    @"STEP 3: select BOTH files at once: the original PvZ2 1.5.252752 APK and main.7.com.ea.game.pvz2_row.obb. mode=%@. V72 keeps the validated zlib + ETC1 path, opens a live framebuffer view, and queues real UIKit touch phases for AndroidUIEventManager. No GameState, resource readiness or UI action is forced.",
                    modeNames[modeIndex]]];

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

    NSInteger selectedMode =
        self.diagnosticModeControl.selectedSegmentIndex;

    PvZ2DiagnosticMode diagnosticMode =
        PvZ2DiagnosticMode::FullMatrix;
    NSString *diagnosticModeName =
        @"V56_BASELINE";

    if (selectedMode == 1) {
        diagnosticMode =
            PvZ2DiagnosticMode::V72LiveTouchBridge;
        diagnosticModeName =
            @"V72_LIVE_TOUCH_BRIDGE";
    } else if (selectedMode == 2) {
        diagnosticMode =
            PvZ2DiagnosticMode::V66BlockingWaitScheduler;
        diagnosticModeName =
            @"V66_BLOCKING_WAIT_SCHEDULER";
    } else if (selectedMode == 3) {
        diagnosticMode =
            PvZ2DiagnosticMode::V65ConditionVariableScheduler;
        diagnosticModeName =
            @"V65_CONDITION_VARIABLE_SCHEDULER";
    } else if (selectedMode == 4) {
        diagnosticMode =
            PvZ2DiagnosticMode::CtypeCompatDeepScout;
        diagnosticModeName =
            @"CTYPE_COMPAT_DEEP_SCOUT";
    }

    ResetPersistentLog();
    self.logView.text = @"";

    [self
        appendUI:
            [NSString
                stringWithFormat:
                    @"=== PvZ2 v72 Live Touch Bridge Probe started mode=%@; PID=%d ===",
                    diagnosticModeName,
                    getpid()]];

    self.jniRunning =
        YES;

    [self refreshStatus];

    if (diagnosticMode ==
        PvZ2DiagnosticMode::V72LiveTouchBridge) {

        PvZ2ResetInteractiveInput();

        PvZ2LiveViewController *liveController =
            [[PvZ2LiveViewController alloc] init];

        liveController.modalPresentationStyle =
            UIModalPresentationFullScreen;

        self.liveController =
            liveController;
        gPvZ2LiveController =
            liveController;

        [self
            presentViewController:
                liveController
            animated:YES
            completion:nil];
    }

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

                        if (diagnosticMode ==
                                PvZ2DiagnosticMode::V72LiveTouchBridge &&
                            selfRef.liveController != nil) {

                            [selfRef.liveController
                                finishRunWithMessage:
                                    @"v72 LIVE — APK/OBB read failed. Close this view and inspect the log."];
                        }

                        [selfRef refreshStatus];
                    });

                return;
            }

            PvZ2LiveFrameCallback liveFrameCallback;

            if (diagnosticMode ==
                PvZ2DiagnosticMode::V72LiveTouchBridge) {

                liveFrameCallback =
                    [](
                        std::uint32_t frame,
                        std::uint32_t width,
                        std::uint32_t height,
                        const std::uint8_t* rgba,
                        std::size_t rgbaSize) {

                        if (rgba == nullptr ||
                            rgbaSize == 0u) {
                            return;
                        }

                        @autoreleasepool {
                            NSData *copy =
                                [NSData
                                    dataWithBytes:rgba
                                    length:rgbaSize];

                            dispatch_async(
                                dispatch_get_main_queue(),
                                ^{
                                    PvZ2LiveViewController *controller =
                                        gPvZ2LiveController;

                                    if (controller != nil) {
                                        [controller
                                            updateFrameData:
                                                copy
                                            width:
                                                width
                                            height:
                                                height
                                            frame:
                                                frame];
                                    }
                                });
                        }
                    };
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
                    },
                    diagnosticMode,
                    liveFrameCallback);

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
                                    @"STEP 3C: JNI_OnLoad=%@ | GameAppInit returned=%@ result=%u | lifecycle=%u | firstDraw reached=%@ returned=%@ | frames=%u | adaptiveStop=%@ | GameState manager=0x%08x current=%d pending=%d requests=%llu applies=%llu | hostGLES=%@ | richestFrame=%u nonBlack=%llu | lastNonBlack=%u pixels=%llu",
                                    result.returned_from_jni_onload ? @"YES" : @"NO",
                                    result.returned_game_app_initialize ? @"YES" : @"NO",
                                    result.game_app_initialize_return & 0xffu,
                                    result.lifecycle_calls_completed,
                                    result.reached_first_draw_frame ? @"YES" : @"NO",
                                    result.returned_first_draw_frame ? @"YES" : @"NO",
                                    result.draw_frames_completed,
                                    result.adaptive_frame_stop ? @"YES" : @"NO",
                                    result.game_state_manager,
                                    result.game_state_current,
                                    result.game_state_pending,
                                    (unsigned long long)result.game_state_request_calls,
                                    (unsigned long long)result.game_state_apply_calls,
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

                    if (!result.startup_logo_summary.empty()) {
                        [selfRef
                            appendUI:
                                [NSString
                                    stringWithFormat:
                                        @"STEP 3C4: %@",
                                        NSStringFromStd(
                                            result.startup_logo_summary)]];
                    }

                    if (!result.startup_resource_group_summary.empty()) {
                        [selfRef
                            appendUI:
                                [NSString
                                    stringWithFormat:
                                        @"STEP 3C5: %@",
                                        NSStringFromStd(
                                            result.startup_resource_group_summary)]];
                    }

                    if (!result.diagnostic_matrix_summary.empty()) {
                        [selfRef
                            appendUI:
                                [NSString
                                    stringWithFormat:
                                        @"STEP 3C6: %@",
                                        NSStringFromStd(
                                            result.diagnostic_matrix_summary)]];
                    }

                    if (!result.ctype_deep_scout_summary.empty()) {
                        [selfRef
                            appendUI:
                                [NSString
                                    stringWithFormat:
                                        @"STEP 3C7: %@",
                                        NSStringFromStd(
                                            result.ctype_deep_scout_summary)]];
                    }

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
                                @"SUCCESS STEP 3: PvZ2 completed the selected diagnostic run. v72 preserves scheduler/zlib/ETC1 fixes and adds a live UIKit touch bridge without forcing guest state."];

                        if (diagnosticMode ==
                                PvZ2DiagnosticMode::V72LiveTouchBridge &&
                            selfRef.liveController != nil) {

                            [selfRef.liveController
                                finishRunWithMessage:
                                    [NSString
                                        stringWithFormat:
                                            @"v72 LIVE — run finished after %u guest frames.\nClose to inspect the log. Touch delivery is recorded as V72 UI EVENTS.",
                                            result.draw_frames_completed]];

                        } else if (!result.final_frame_png_path.empty()) {
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
                                    @"PvZ2 v66 diagnostic run returned"
                                message:
                                    [NSString
                                        stringWithFormat:
                                            @"PvZ2 completed its v56 Diagnostic Matrix run.\n\nGameAppInitialize: %u\nLifecycle calls completed: %u\nFrames returned: %u\nHost GLES active: %@\nRichest sampled frame: %u (%llu non-black pixels)\nConstructors: %u/%u\nJNI_OnLoad: 0x%08x\n\nInspect V56 REGISTRY DIAGNOSIS / REGISTRY WRITE / TARGET LOOKUP / SCOUT / DIAGNOSTIC MATRIX SUMMARY plus preserved v55-v52 diagnostics in the full log.",
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

                        if (diagnosticMode ==
                                PvZ2DiagnosticMode::V72LiveTouchBridge &&
                            selfRef.liveController != nil) {

                            [selfRef.liveController
                                finishRunWithMessage:
                                    [NSString
                                        stringWithFormat:
                                            @"v72 LIVE — guest run stopped.\n%@\nClose to inspect the full log.",
                                            message]];

                        } else {
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
