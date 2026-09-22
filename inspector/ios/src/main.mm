#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

#include <string>

#include "inspector_core.hpp"
#include "macho_inspector.hpp"

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
        @"annotated-log.txt",
        @"startup-diagnosis.txt",
        @"matrix-diagnosis.txt",
        @"v57-plan.txt",
        @"v61-crash-diagnosis.txt",
        @"next-probe-plan.txt",
        @"critical-log-excerpt.txt",
        @"v68-resource-stall-diagnosis.txt",
        @"v69-plan.txt",
        @"v68-critical-excerpt.txt",
        @"ios-reference-report.txt",
        @"android-ios-shared-strings.csv",
        @"objc-classes.csv",
        @"objc-methods.csv",
        @"objc-ivars.csv",
        @"ios-import-calls.csv",
        @"pthread-reference.txt"
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
@property(nonatomic, strong) NSData *ipaData;
@property(nonatomic, copy) NSString *ipaName;
@property(nonatomic, strong) NSData *logData;
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
    self.title = @"PvZ2 Inspector Lab v2.2-alpha";

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"PvZ2 Inspector Lab v2.2-alpha";
    title.font = [UIFont boldSystemFontOfSize:27.0];
    title.numberOfLines = 0;

    UILabel *explanation = [[UILabel alloc] init];
    explanation.translatesAutoresizingMaskIntoConstraints = NO;
    explanation.numberOfLines = 0;
    explanation.font = [UIFont systemFontOfSize:14.5];
    explanation.text =
        @"Inspector v2.2 keeps the complete Android ELF/log analysis and "
         "adds a dedicated v74 display-geometry/UI-platform diagnosis plus "
         "the static iOS-reference path for the historical PvZ2 IPA. "
         "Select the Android APK, optionally the decrypted iOS 1.5.252123 IPA "
         "and a runtime log. The IPA analyzer discovers the Payload Mach-O, "
         "parses ARMv7 load commands, encryption state, dylibs, segments, "
         "sections and LC_FUNCTION_STARTS. No JIT or StikDebug is required.";

    UIButton *apkButton =
        [self makeButton:@"1. Select PvZ2 APK"
                selector:@selector(selectApk)];

    UIButton *ipaButton =
        [self makeButton:@"2. Select iOS IPA\n(optional)"
                selector:@selector(selectIpa)];

    UIButton *logButton =
        [self makeButton:@"3. Select full log\n(optional)"
                selector:@selector(selectLog)];

    self.analyseButton =
        [self makeButton:@"4. Analyse"
                selector:@selector(analyse)];

    UIStackView *mainButtons =
        [[UIStackView alloc]
            initWithArrangedSubviews:@[
                apkButton,
                ipaButton,
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

    self.logData = nil;
    [self refreshStatus];
}

- (void)refreshStatus {
    NSString *apk =
        self.apkData != nil
            ? [NSString stringWithFormat:@"%@ (%llu bytes)",
                self.apkName ?: @"APK",
                (unsigned long long)self.apkData.length]
            : @"not selected";

    NSString *ipa =
        self.ipaData != nil
            ? [NSString stringWithFormat:@"%@ (%llu bytes)",
                self.ipaName ?: @"IPA",
                (unsigned long long)self.ipaData.length]
            : @"not selected";

    NSString *log =
        self.logData.length > 0
            ? [NSString stringWithFormat:@"%@ (%llu bytes)",
                self.logName ?: @"log",
                (unsigned long long)self.logData.length]
            : @"not selected — static analysis only";

    NSString *reports =
        [[NSFileManager defaultManager]
            fileExistsAtPath:ReportDirectoryPath()]
            ? ReportDirectoryPath()
            : @"not generated yet";

    self.statusLabel.text =
        [NSString stringWithFormat:
            @"APK: %@\niOS IPA: %@\nLog: %@\nReports: %@",
            apk,
            ipa,
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
        (mode == 1 || mode == 3)
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

- (void)selectIpa {
    [self openPickerWithMode:3];
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
                     "Optionally select the historical iOS IPA and/or a full "
                     "probe log, then tap Analyse.",
                    self.apkName];
        }
    } else if (self.pickerMode == 3) {
        NSData *data =
            [NSData dataWithContentsOfURL:url
                                  options:NSDataReadingMappedIfSafe
                                    error:&error];

        if (data != nil) {
            self.ipaData = data;
            self.ipaName = url.lastPathComponent;
            self.outputView.text =
                [NSString stringWithFormat:
                    @"Selected iOS reference IPA: %@\n%llu bytes.\n\n"
                     "Inspector v2 will locate the direct Payload/*.app ARMv7 "
                     "Mach-O and write ios-reference-report.txt.",
                    self.ipaName,
                    (unsigned long long)self.ipaData.length];
        }
    } else {
        NSData *data =
            [NSData dataWithContentsOfURL:url
                                  options:NSDataReadingMappedIfSafe
                                    error:&error];

        if (data != nil) {
            self.logData = data;
            self.logName = url.lastPathComponent;
            self.outputView.text =
                [NSString stringWithFormat:
                    @"Selected log: %@\n%llu bytes.\n\n"
                     "Large logs are scanned completely for v61 worker/pump/crash "
                     "and v68 TaskResource lifecycle events. Generic address ranking "
                     "is sampled above 24 MiB and "
                     "the full annotated-log copy is skipped to avoid duplicating "
                     "a 75 MiB scheduling loop in memory and on disk.",
                    self.logName,
                    (unsigned long long)self.logData.length];
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
    NSData *ipa = self.ipaData;
    NSData *logData = self.logData;

    dispatch_async(
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        ^{
            const auto *bytes =
                static_cast<const std::uint8_t *>(apk.bytes);

            std::string logStd;
            if (logData.length > 0) {
                logStd.assign(
                    static_cast<const char *>(logData.bytes),
                    static_cast<std::size_t>(logData.length));
            }

            PvZ2InspectorResult result =
                InspectPvZ2ApkAndLog(
                    bytes,
                    apk.length,
                    logStd);

            PvZ2IpaInspectorResult ipaResult;
            if (ipa.length > 0) {
                ipaResult =
                    InspectPvZ2IpaReference(
                        static_cast<const std::uint8_t *>(ipa.bytes),
                        static_cast<std::size_t>(ipa.length),
                        static_cast<const std::uint8_t *>(apk.bytes),
                        static_cast<std::size_t>(apk.length));
            }

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

                if (!result.startup_diagnosis.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"startup-diagnosis.txt"],
                        result.startup_diagnosis);
                }

                if (!result.matrix_diagnosis.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"matrix-diagnosis.txt"],
                        result.matrix_diagnosis);
                }

                if (!result.v57_plan.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"v57-plan.txt"],
                        result.v57_plan);
                }

                if (!result.v61_crash_diagnosis.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"v61-crash-diagnosis.txt"],
                        result.v61_crash_diagnosis);
                }

                if (!result.next_probe_plan.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"next-probe-plan.txt"],
                        result.next_probe_plan);
                }

                if (!result.critical_log_excerpt.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"critical-log-excerpt.txt"],
                        result.critical_log_excerpt);
                }

                if (!result.v68_resource_stall_diagnosis.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"v68-resource-stall-diagnosis.txt"],
                        result.v68_resource_stall_diagnosis);
                }

                if (!result.v69_plan.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"v69-plan.txt"],
                        result.v69_plan);
                }

                if (!result.v68_critical_excerpt.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"v68-critical-excerpt.txt"],
                        result.v68_critical_excerpt);
                }

                if (!result.v74_display_diagnosis.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"v74-display-geometry-diagnosis.txt"],
                        result.v74_display_diagnosis);
                }

                if (!result.v75_display_plan.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"v75-display-plan.txt"],
                        result.v75_display_plan);
                }

                if (!result.v74_display_critical_excerpt.empty()) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"v74-display-critical-excerpt.txt"],
                        result.v74_display_critical_excerpt);
                }

                if (ipa.length > 0 && ipaResult.ok) {
                    WriteUtf8(
                        [root stringByAppendingPathComponent:@"ios-reference-report.txt"],
                        ipaResult.report);

                    if (!ipaResult.shared_strings_csv.empty()) {
                        WriteUtf8(
                            [root stringByAppendingPathComponent:@"android-ios-shared-strings.csv"],
                            ipaResult.shared_strings_csv);
                    }

                    if (!ipaResult.objc_classes_csv.empty()) {
                        WriteUtf8(
                            [root stringByAppendingPathComponent:@"objc-classes.csv"],
                            ipaResult.objc_classes_csv);
                    }

                    if (!ipaResult.objc_methods_csv.empty()) {
                        WriteUtf8(
                            [root stringByAppendingPathComponent:@"objc-methods.csv"],
                            ipaResult.objc_methods_csv);
                    }

                    if (!ipaResult.objc_ivars_csv.empty()) {
                        WriteUtf8(
                            [root stringByAppendingPathComponent:@"objc-ivars.csv"],
                            ipaResult.objc_ivars_csv);
                    }

                    if (!ipaResult.ios_import_calls_csv.empty()) {
                        WriteUtf8(
                            [root stringByAppendingPathComponent:@"ios-import-calls.csv"],
                            ipaResult.ios_import_calls_csv);
                    }

                    if (!ipaResult.pthread_reference.empty()) {
                        WriteUtf8(
                            [root stringByAppendingPathComponent:@"pthread-reference.txt"],
                            ipaResult.pthread_reference);
                    }
                }
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                self.analysing = NO;

                if (result.ok) {
                    self.outputView.text =
                        [NSString stringWithFormat:
                            @"%@\n"
                             "%@"
                             "Reports written to:\n%@\n\n"
                             "Files:\n"
                             "• report.txt — full ELF/import/relocation/address report\n"
                             "• addresses.csv — every hex address from the log, ranked and classified\n"
                             "• summary.json — machine-readable summary\n"
                             "%@"
                             "%@"
                             "%@"
                             "%@"
                             "%@"
                             "%@"
                             "%@"
                             "%@"
                             "%@"
                             "%@"
                             "%@"
                             "%@"
                             "%@"
                             "%@",
                            NSStringFromStd(result.summary),
                            ipa.length == 0
                                ? @""
                                : (ipaResult.ok
                                    ? [NSString stringWithFormat:@"iOS reference: %@\n", NSStringFromStd(ipaResult.summary)]
                                    : [NSString stringWithFormat:@"iOS reference analysis failed: %@\n", NSStringFromStd(ipaResult.message)]),
                            root,
                            result.annotated_log.empty()
                                ? @""
                                : @"• annotated-log.txt — original log with resolved control-flow addresses\n",
                            result.startup_diagnosis.empty()
                                ? @""
                                : @"• startup-diagnosis.txt — automatic v54 gate/NaN/object-correlation diagnosis\n",
                            result.matrix_diagnosis.empty()
                                ? @""
                                : @"• matrix-diagnosis.txt — v55/v56 registry, trie, Gate-C and ctype ABI diagnosis\n",
                            result.v57_plan.empty()
                                ? @""
                                : @"• v57-plan.txt — historical v57 plan retained for compatibility\n",
                            result.v61_crash_diagnosis.empty()
                                ? @""
                                : @"• v61-crash-diagnosis.txt — worker/pump/virtual-dispatch diagnosis\n",
                            result.next_probe_plan.empty()
                                ? @""
                                : @"• next-probe-plan.txt — batched TaskResource provenance + bounded scheduler plan\n",
                            result.critical_log_excerpt.empty()
                                ? @""
                                : @"• critical-log-excerpt.txt — compact worker-7/crash/tail evidence from huge logs\n",
                            result.v74_display_diagnosis.empty()
                                ? @""
                                : @"• v74-display-geometry-diagnosis.txt — Retina/FBO/viewport/UI-package root-cause classification\n",
                            result.v75_display_plan.empty()
                                ? @""
                                : @"• v75-display-plan.txt — batched baseline/UI-iPad/scale-reference A/B plan\n",
                            result.v74_display_critical_excerpt.empty()
                                ? @""
                                : @"• v74-display-critical-excerpt.txt — compact geometry and UI-selection evidence\n",
                            (ipa.length > 0 && ipaResult.ok)
                                ? @"• ios-reference-report.txt — ARMv7 Mach-O/load-command/framework/reference-marker report\n"
                                : @"",
                            (ipa.length > 0 && ipaResult.ok && !ipaResult.shared_strings_csv.empty())
                                ? @"• android-ios-shared-strings.csv — exact strings shared by libPVZ2.so and the iOS Mach-O\n"
                                : @"",
                            (ipa.length > 0 && ipaResult.ok && !ipaResult.objc_classes_csv.empty())
                                ? @"• objc-classes.csv / objc-methods.csv / objc-ivars.csv — iOS Objective-C layout, selectors, IMPs and ivar offsets\n"
                                : @"",
                            (ipa.length > 0 && ipaResult.ok && !ipaResult.ios_import_calls_csv.empty())
                                ? @"• ios-import-calls.csv / pthread-reference.txt — resolved Mach-O import stubs, call-sites and caller function starts\n"
                                : @""];
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
