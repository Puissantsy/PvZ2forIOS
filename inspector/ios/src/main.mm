#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

#include <string>

#include "inspector_core.hpp"

namespace {

NSString *NSStringFromStd(const std::string& value) {
    return [NSString stringWithUTF8String:value.c_str()] ?: @"(invalid UTF-8)";
}

NSString *DocumentsPath() {
    NSArray<NSURL *> *urls =
        [[NSFileManager defaultManager]
            URLsForDirectory:NSDocumentDirectory
                   inDomains:NSUserDomainMask];
    return urls.firstObject.path;
}

NSString *ReportDirectoryPath() {
    return [DocumentsPath() stringByAppendingPathComponent:@"PvZ2InspectorReport"];
}

void WriteUtf8(NSString *path, const std::string& text) {
    NSData *data =
        [NSData dataWithBytes:text.data()
                      length:text.size()];
    [data writeToFile:path atomically:YES];
}

NSArray<NSURL *> *ExistingReportURLs() {
    NSString *root = ReportDirectoryPath();
    NSArray<NSString *> *names = @[
        @"summary.json",
        @"report.txt",
        @"addresses.csv",
        @"annotated-log.txt"
    ];

    NSMutableArray<NSURL *> *urls = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];

    for (NSString *name in names) {
        NSString *path = [root stringByAppendingPathComponent:name];
        if ([fm fileExistsAtPath:path]) {
            [urls addObject:[NSURL fileURLWithPath:path]];
        }
    }
    return urls;
}

} // namespace

@interface InspectorViewController :
    UIViewController <UIDocumentPickerDelegate>

@property(nonatomic, strong) UILabel *statusLabel;
@property(nonatomic, strong) UITextView *outputView;
@property(nonatomic, strong) UIButton *analyseButton;
@property(nonatomic, strong) UIButton *shareButton;

@property(nonatomic, strong) NSData *apkData;
@property(nonatomic, copy) NSString *apkName;
@property(nonatomic, copy) NSString *logText;
@property(nonatomic, copy) NSString *logName;

@property(nonatomic, assign) NSInteger pickerMode;
@property(nonatomic, assign) BOOL analysing;

@end

@implementation InspectorViewController

- (UIButton *)makeButton:(NSString *)title selector:(SEL)selector {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.translatesAutoresizingMaskIntoConstraints = NO;
    [button setTitle:title forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:16.0];
    button.titleLabel.numberOfLines = 2;
    button.titleLabel.textAlignment = NSTextAlignmentCenter;
    [button addTarget:self
               action:selector
     forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.title = @"PvZ2 Inspector Lab v1.1";

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"PvZ2 Inspector Lab v1.1";
    title.font = [UIFont boldSystemFontOfSize:27.0];
    title.numberOfLines = 0;

    UILabel *explanation = [[UILabel alloc] init];
    explanation.translatesAutoresizingMaskIntoConstraints = NO;
    explanation.numberOfLines = 0;
    explanation.font = [UIFont systemFontOfSize:14.5];
    explanation.text =
        @"This auxiliary app does NOT launch PvZ2. It statically inspects the "
         "original ARMv7 libPVZ2.so inside the APK, parses its ELF layout, "
         "dynamic imports, relocations and .ARM.exidx function boundaries, "
         "validates the exact GameStateMgr profile used by the v53 probe, "
         "then resolves raw guest hex addresses from a full probe log. "
         "No JIT or StikDebug is required.";

    UIButton *apkButton =
        [self makeButton:@"1. Select PvZ2 APK"
                selector:@selector(selectApk)];

    UIButton *logButton =
        [self makeButton:@"2. Select full log\n(optional)"
                selector:@selector(selectLog)];

    self.analyseButton =
        [self makeButton:@"3. Analyse"
                selector:@selector(analyse)];

    UIStackView *mainButtons =
        [[UIStackView alloc]
            initWithArrangedSubviews:@[
                apkButton,
                logButton,
                self.analyseButton
            ]];
    mainButtons.translatesAutoresizingMaskIntoConstraints = NO;
    mainButtons.axis = UILayoutConstraintAxisHorizontal;
    mainButtons.spacing = 10.0;
    mainButtons.distribution = UIStackViewDistributionFillEqually;

    UIButton *copyButton =
        [self makeButton:@"Copy summary"
                selector:@selector(copySummary)];

    self.shareButton =
        [self makeButton:@"Share reports"
                selector:@selector(shareReports)];

    UIStackView *utilityButtons =
        [[UIStackView alloc]
            initWithArrangedSubviews:@[
                copyButton,
                self.shareButton
            ]];
    utilityButtons.translatesAutoresizingMaskIntoConstraints = NO;
    utilityButtons.axis = UILayoutConstraintAxisHorizontal;
    utilityButtons.spacing = 10.0;
    utilityButtons.distribution = UIStackViewDistributionFillEqually;

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font =
        [UIFont monospacedSystemFontOfSize:12.5
                                   weight:UIFontWeightRegular];

    self.outputView = [[UITextView alloc] init];
    self.outputView.translatesAutoresizingMaskIntoConstraints = NO;
    self.outputView.editable = NO;
    self.outputView.font =
        [UIFont monospacedSystemFontOfSize:11.0
                                   weight:UIFontWeightRegular];
    self.outputView.layer.borderWidth = 1.0;
    self.outputView.layer.borderColor = UIColor.separatorColor.CGColor;
    self.outputView.layer.cornerRadius = 8.0;

    UIStackView *stack =
        [[UIStackView alloc]
            initWithArrangedSubviews:@[
                title,
                explanation,
                self.statusLabel,
                mainButtons,
                utilityButtons,
                self.outputView
            ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 11.0;

    [self.view addSubview:stack];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:18.0],
        [stack.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-18.0],
        [stack.topAnchor constraintEqualToAnchor:safe.topAnchor constant:14.0],
        [stack.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-14.0],
        [self.outputView.heightAnchor constraintGreaterThanOrEqualToConstant:280.0],
        [mainButtons.heightAnchor constraintEqualToConstant:58.0],
        [utilityButtons.heightAnchor constraintEqualToConstant:48.0]
    ]];

    self.logText = @"";
    [self refreshStatus];
}

- (void)refreshStatus {
    NSString *apk =
        self.apkData != nil
            ? [NSString stringWithFormat:@"%@ (%llu bytes)",
                self.apkName ?: @"APK",
                (unsigned long long)self.apkData.length]
            : @"not selected";

    NSString *log =
        self.logText.length > 0
            ? [NSString stringWithFormat:@"%@ (%lu chars)",
                self.logName ?: @"log",
                (unsigned long)self.logText.length]
            : @"not selected — static analysis only";

    NSString *reports =
        [[NSFileManager defaultManager]
            fileExistsAtPath:ReportDirectoryPath()]
            ? ReportDirectoryPath()
            : @"not generated yet";

    self.statusLabel.text =
        [NSString stringWithFormat:
            @"APK: %@\nLog: %@\nReports: %@",
            apk,
            log,
            reports];

    self.analyseButton.enabled =
        self.apkData != nil && !self.analysing;

    self.shareButton.enabled =
        ExistingReportURLs().count > 0;
}

- (void)openPickerWithMode:(NSInteger)mode {
    self.pickerMode = mode;

    NSArray<UTType *> *types =
        mode == 1
            ? @[UTTypeData]
            : @[UTTypePlainText, UTTypeData];

    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc]
            initForOpeningContentTypes:types
            asCopy:YES];

    picker.delegate = self;
    picker.allowsMultipleSelection = NO;

    [self presentViewController:picker
                       animated:YES
                     completion:nil];
}

- (void)selectApk {
    [self openPickerWithMode:1];
}

- (void)selectLog {
    [self openPickerWithMode:2];
}

- (void)documentPicker:
        (UIDocumentPickerViewController *)controller
didPickDocumentsAtURLs:
        (NSArray<NSURL *> *)urls {

    NSURL *url = urls.firstObject;
    if (url == nil) return;

    const BOOL scoped =
        [url startAccessingSecurityScopedResource];

    NSError *error = nil;

    if (self.pickerMode == 1) {
        NSData *data =
            [NSData dataWithContentsOfURL:url
                                  options:NSDataReadingMappedIfSafe
                                    error:&error];

        if (data != nil) {
            self.apkData = data;
            self.apkName = url.lastPathComponent;
            self.outputView.text =
                [NSString stringWithFormat:
                    @"Selected APK: %@\n\n"
                     "Select a full probe log if you want raw PC/LR/"
                     "returnPC/callerLR addresses resolved too, then tap Analyse.",
                    self.apkName];
        }
    } else {
        NSString *text =
            [NSString stringWithContentsOfURL:url
                                     encoding:NSUTF8StringEncoding
                                        error:&error];

        if (text == nil) {
            NSData *data = [NSData dataWithContentsOfURL:url];
            if (data != nil) {
                text =
                    [[NSString alloc]
                        initWithData:data
                           encoding:NSUTF8StringEncoding];
            }
        }

        if (text != nil) {
            self.logText = text;
            self.logName = url.lastPathComponent;
            self.outputView.text =
                [NSString stringWithFormat:
                    @"Selected log: %@\n%lu characters.\n\n"
                     "The inspector will classify every 7-8 digit hex address, "
                     "rank PC/LR/caller addresses and add neutral .ARM.exidx "
                     "function boundaries where stripped symbols are unavailable.",
                    self.logName,
                    (unsigned long)self.logText.length];
        }
    }

    if (scoped) {
        [url stopAccessingSecurityScopedResource];
    }

    if (error != nil) {
        self.outputView.text =
            [NSString stringWithFormat:
                @"Could not read %@:\n%@",
                url.lastPathComponent,
                error.localizedDescription];
    }

    [self refreshStatus];
}

- (void)analyse {
    if (self.apkData == nil || self.analysing) return;

    self.analysing = YES;
    [self refreshStatus];

    self.outputView.text =
        @"Analysing APK...\n"
         "This app is not executing libPVZ2.so. "
         "It is building a static address map and, if supplied, "
         "cross-referencing the runtime log.";

    NSData *apk = self.apkData;
    NSString *log = self.logText ?: @"";

    dispatch_async(
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        ^{
            const auto *bytes =
                static_cast<const std::uint8_t *>(apk.bytes);

            std::string logStd =
                log.length > 0
                    ? std::string(log.UTF8String ?: "")
                    : std::string();

            PvZ2InspectorResult result =
                InspectPvZ2ApkAndLog(
                    bytes,
                    apk.length,
                    logStd);

            NSString *root = ReportDirectoryPath();

            if (result.ok) {
                NSFileManager *fm = [NSFileManager defaultManager];
                [fm removeItemAtPath:root error:nil];
                [fm createDirectoryAtPath:root
              withIntermediateDirectories:YES
                               attributes:nil
                                    error:nil];

                WriteUtf8(
                    [root stringByAppendingPathComponent:@"summary.json"],
                    result.summary_json);

                WriteUtf8(
                    [root stringByAppendingPathComponent:@"report.txt"],
                    result.report);

                WriteUtf8(
                    [root stringByAppendingPathComponent:@"addresses.csv"],
                    result.addresses_csv);

                if (!result.annotated_log.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"annotated-log.txt"],
                        result.annotated_log);
                }
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                self.analysing = NO;

                if (result.ok) {
                    self.outputView.text =
                        [NSString stringWithFormat:
                            @"%@\n"
                             "Reports written to:\n%@\n\n"
                             "Files:\n"
                             "• report.txt — full ELF/import/relocation/address report\n"
                             "• addresses.csv — every hex address from the log, ranked and classified\n"
                             "• summary.json — machine-readable summary\n"
                             "%@",
                            NSStringFromStd(result.summary),
                            root,
                            result.annotated_log.empty()
                                ? @""
                                : @"• annotated-log.txt — original log with resolved control-flow addresses\n"];
                } else {
                    self.outputView.text =
                        [NSString stringWithFormat:
                            @"Analysis failed:\n%@",
                            NSStringFromStd(result.message)];
                }

                [self refreshStatus];
            });
        });
}

- (void)copySummary {
    UIPasteboard.generalPasteboard.string =
        self.outputView.text ?: @"";
}

- (void)shareReports {
    NSArray<NSURL *> *urls = ExistingReportURLs();
    if (urls.count == 0) return;

    UIActivityViewController *activity =
        [[UIActivityViewController alloc]
            initWithActivityItems:urls
            applicationActivities:nil];

    activity.popoverPresentationController.sourceView =
        self.shareButton;

    activity.popoverPresentationController.sourceRect =
        self.shareButton.bounds;

    [self presentViewController:activity
                       animated:YES
                     completion:nil];
}

@end

@interface InspectorAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation InspectorAppDelegate

- (BOOL)application:
        (UIApplication *)application
didFinishLaunchingWithOptions:
        (NSDictionary *)launchOptions {

    self.window =
        [[UIWindow alloc]
            initWithFrame:UIScreen.mainScreen.bounds];

    InspectorViewController *root =
        [[InspectorViewController alloc] init];

    UINavigationController *nav =
        [[UINavigationController alloc]
            initWithRootViewController:root];

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
            NSStringFromClass([InspectorAppDelegate class]));
    }
}
