#import "save_backups.hpp"
#import <CommonCrypto/CommonDigest.h>

namespace {

static NSString *const kDomain = @"PvZ2forIOS.Backups";
static NSString *const kManifest = @"snapshot-info.plist";
static const unsigned long long kFileLimit = 64ull * 1024ull * 1024ull;
static const unsigned long long kSnapshotLimit = 128ull * 1024ull * 1024ull;
// v165: 512 was an arbitrary per-tree limit and rejected existing QA +
// production saves. Keep the independent per-file and total-byte bounds,
// but support real multi-profile user directories with many small files.
static const NSUInteger kMaxSaveFiles = 16384u;

NSError *MakeError(NSString *description) {
    return [NSError errorWithDomain:kDomain code:1 userInfo:@{
        NSLocalizedDescriptionKey: description ?: @"Save backup operation failed"
    }];
}

NSURL *SupportParent() {
    return [[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory
                                                   inDomains:NSUserDomainMask].firstObject;
}

NSURL *LiveRoot() {
    return [SupportParent() URLByAppendingPathComponent:@"PvZ2forIOS" isDirectory:YES];
}

NSURL *DocumentsChild(NSString *name) {
    NSURL *documents = [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory
                                                              inDomains:NSUserDomainMask].firstObject;
    return [documents URLByAppendingPathComponent:name isDirectory:YES];
}

BOOL IsSaveRoot(NSString *name) {
    return [name isEqualToString:@"config-v1.txt"] ||
           [name isEqualToString:@"UserData"] ||
           [name hasPrefix:@"UserData-"];
}

BOOL IsSafeRelativePath(NSString *path) {
    if (path.length == 0 || [path hasPrefix:@"/"] || [path containsString:@"\\"]) return NO;
    for (NSString *component in [path pathComponents]) {
        if ([component isEqualToString:@"."] || [component isEqualToString:@".."] ||
            component.length == 0) return NO;
    }
    return IsSaveRoot([path pathComponents].firstObject);
}

NSString *HashFile(NSURL *file, unsigned long long *length, NSError **error) {
    NSDictionary *attr = [[NSFileManager defaultManager] attributesOfItemAtPath:file.path error:error];
    if (!attr || ![attr[NSFileType] isEqualToString:NSFileTypeRegular]) {
        if (error && !*error) *error = MakeError(@"Backup contains an unsupported file type");
        return nil;
    }
    unsigned long long size = [attr[NSFileSize] unsignedLongLongValue];
    if (size > kFileLimit) {
        if (error) *error = MakeError(@"A save file exceeds the 64 MiB safety limit");
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfURL:file options:NSDataReadingMappedIfSafe error:error];
    if (!data || (unsigned long long)data.length != size) {
        if (error && !*error) *error = MakeError(@"Incomplete backup file read");
        return nil;
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    if (length) *length = size;
    return hex;
}

// A manifest ties all USERFS roots and the premium sidecar to one consistent
// snapshot. Never accept traversal, symlinks, extra files, or partial copies.
NSArray<NSDictionary *> *Inventory(NSURL *snapshot,
                                   NSArray<NSString *> *roots,
                                   NSError **error) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSDictionary *> *files = [NSMutableArray array];
    unsigned long long total = 0;
    for (NSString *root in roots) {
        if (![root isKindOfClass:[NSString class]] ||
            !IsSaveRoot(root) || [root containsString:@"/"] ||
            [root containsString:@"\\"] || [root isEqualToString:@"."] ||
            [root isEqualToString:@".."]) {
            if (error) *error = MakeError(@"Unrecognized save root");
            return nil;
        }
        NSURL *url = [snapshot URLByAppendingPathComponent:root];
        NSDictionary *attributes = [fm attributesOfItemAtPath:url.path error:error];
        if (!attributes || [attributes[NSFileType] isEqualToString:NSFileTypeSymbolicLink] ||
            ([root isEqualToString:@"config-v1.txt"] !=
             [attributes[NSFileType] isEqualToString:NSFileTypeRegular])) {
            if (error && !*error) *error = MakeError(@"Missing or symbolic-linked save root");
            return nil;
        }
        NSMutableArray<NSURL *> *candidates = [NSMutableArray array];
        if ([attributes[NSFileType] isEqualToString:NSFileTypeRegular]) {
            [candidates addObject:url];
        } else if ([attributes[NSFileType] isEqualToString:NSFileTypeDirectory]) {
            NSDirectoryEnumerator<NSURL *> *enumerator =
                [fm enumeratorAtURL:url includingPropertiesForKeys:nil
                           options:0 errorHandler:^BOOL(NSURL *failed, NSError *failure) {
                               if (error) *error = failure;
                               return NO;
                           }];
            for (NSURL *entry in enumerator) {
                NSDictionary *a = [fm attributesOfItemAtPath:entry.path error:error];
                if (!a || [a[NSFileType] isEqualToString:NSFileTypeSymbolicLink]) {
                    if (error && !*error) *error = MakeError(@"Save tree contains a symbolic link");
                    return nil;
                }
                if ([a[NSFileType] isEqualToString:NSFileTypeRegular]) [candidates addObject:entry];
                else if (![a[NSFileType] isEqualToString:NSFileTypeDirectory]) {
                    if (error) *error = MakeError(@"Unsupported entry in save tree");
                    return nil;
                }
            }
            if (error && *error) return nil;
        } else {
            if (error) *error = MakeError(@"Unsupported save root type");
            return nil;
        }
        for (NSURL *entry in candidates) {
            // Explicitly separate unsafe path data from high but legitimate
            // file counts. The old combined message prevented diagnosis.
            NSString *prefix = [snapshot.path stringByAppendingString:@"/"];
            if (![entry.path hasPrefix:prefix]) {
                if (error) *error = MakeError([NSString stringWithFormat:
                    @"Inventory path escaped save root: %@", entry.lastPathComponent]);
                return nil;
            }
            NSString *relative = [entry.path substringFromIndex:prefix.length];
            if (!IsSafeRelativePath(relative)) {
                if (error) *error = MakeError([NSString stringWithFormat:
                    @"Invalid save relative path in root %@: %@", root, relative]);
                return nil;
            }
            if (files.count >= kMaxSaveFiles) {
                if (error) *error = MakeError([NSString stringWithFormat:
                    @"Save inventory file count exceeded: %lu (limit %lu; root %@)",
                    (unsigned long)files.count,
                    (unsigned long)kMaxSaveFiles, root]);
                return nil;
            }
            unsigned long long size = 0;
            NSString *hash = HashFile(entry, &size, error);
            if (!hash) return nil;
            total += size;
            if (total > kSnapshotLimit) {
                if (error) *error = MakeError(@"Save tree exceeds 128 MiB safety limit");
                return nil;
            }
            [files addObject:@{@"path": relative, @"size": @(size), @"sha256": hash}];
        }
    }
    [files sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"path"] compare:b[@"path"]];
    }];
    return files;
}

BOOL ValidateSnapshot(NSURL *snapshot, NSDictionary **outManifest, NSError **error) {
    NSURL *manifestURL = [snapshot URLByAppendingPathComponent:kManifest];
    NSDictionary *manifest = [NSDictionary dictionaryWithContentsOfURL:manifestURL];
    if (![manifest isKindOfClass:[NSDictionary class]] ||
        ![manifest[@"format"] isEqualToString:@"pvz2forios-save-v1"] ||
        ![manifest[@"roots"] isKindOfClass:[NSArray class]] ||
        ![manifest[@"files"] isKindOfClass:[NSArray class]]) {
        if (error) *error = MakeError(@"Snapshot manifest missing or incompatible");
        return NO;
    }
    NSArray *roots = manifest[@"roots"];
    // Never allow a copied manifest to smuggle non-string roots. Existing
    // users may legitimately have multiple former QA save directories.
    for (id root in roots) {
        if (![root isKindOfClass:[NSString class]] || !IsSaveRoot(root) ||
            [root containsString:@"/"] || [root containsString:@"\\"]) {
            if (error) *error = MakeError(@"Invalid root name in snapshot manifest");
            return NO;
        }
    }
    if (roots.count == 0 || roots.count > 128 ||
        [[NSSet setWithArray:roots] count] != roots.count) {
        if (error) *error = MakeError(@"Invalid snapshot root inventory");
        return NO;
    }
    NSArray *actual = Inventory(snapshot, roots, error);
    if (!actual || ![actual isEqualToArray:manifest[@"files"]]) {
        if (error && !*error) *error = MakeError(@"Snapshot integrity mismatch; nothing restored");
        return NO;
    }
    if (outManifest) *outManifest = manifest;
    return YES;
}

void PruneLocalSnapshots(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *directory = DocumentsChild(@"PvZ2Backups");
    NSArray<NSURL *> *children = [fm contentsOfDirectoryAtURL:directory
                                   includingPropertiesForKeys:nil options:0 error:nil];
    NSMutableArray<NSURL *> *snapshots = [NSMutableArray array];
    for (NSURL *item in children) {
        if ([item.lastPathComponent hasPrefix:@"save-"] &&
            [fm fileExistsAtPath:[item URLByAppendingPathComponent:kManifest].path]) {
            [snapshots addObject:item];
        }
    }
    [snapshots sortUsingComparator:^NSComparisonResult(NSURL *a, NSURL *b) {
        return [b.lastPathComponent compare:a.lastPathComponent];
    }];
    // Local rotation never affects snapshots already copied to iCloud Drive.
    for (NSUInteger i = 12; i < snapshots.count; i++) {
        [fm removeItemAtURL:snapshots[i] error:nil];
    }
}

} // namespace

NSURL *PVZSaveCreateSnapshot(NSString *reason, NSError **error) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *source = LiveRoot();
    NSArray<NSURL *> *children = [fm contentsOfDirectoryAtURL:source
                                   includingPropertiesForKeys:nil options:0 error:nil];
    NSMutableArray<NSString *> *roots = [NSMutableArray array];
    for (NSURL *child in children) {
        if (IsSaveRoot(child.lastPathComponent)) [roots addObject:child.lastPathComponent];
    }
    if (roots.count == 0) {
        if (error) *error = MakeError(@"No existing game save to snapshot yet");
        return nil;
    }
    [roots sortUsingSelector:@selector(compare:)];
    NSURL *backups = DocumentsChild(@"PvZ2Backups");
    if (![fm createDirectoryAtURL:backups withIntermediateDirectories:YES
                      attributes:nil error:error]) return nil;
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    fmt.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    fmt.dateFormat = @"yyyyMMdd-HHmmss-SSS";
    NSString *stamp = [fmt stringFromDate:[NSDate date]];
    NSString *safeReason = [reason isEqualToString:@"poststop"] ? @"poststop" :
                           ([reason isEqualToString:@"prerestore"] ? @"prerestore" : @"prelaunch");
    NSString *filename = [NSString stringWithFormat:@"save-%@-%@-%@", stamp,
                          safeReason, [NSUUID UUID].UUIDString];
    NSURL *temporary = [backups URLByAppendingPathComponent:
                        [@".creating-" stringByAppendingString:[NSUUID UUID].UUIDString] isDirectory:YES];
    NSURL *destination = [backups URLByAppendingPathComponent:filename isDirectory:YES];
    if (![fm createDirectoryAtURL:temporary withIntermediateDirectories:NO
                      attributes:nil error:error]) return nil;
    NSArray *sourceInventory = Inventory(source, roots, error);
    if (!sourceInventory) {
        [fm removeItemAtURL:temporary error:nil];
        return nil;
    }
    BOOL succeeded = NO;
    do {
        BOOL copySucceeded = YES;
        for (NSString *root in roots) {
            if (![fm copyItemAtURL:[source URLByAppendingPathComponent:root]
                           toURL:[temporary URLByAppendingPathComponent:root] error:error]) {
                copySucceeded = NO;
                break;
            }
        }
        if (!copySucceeded) break;
        // The inventory catches failed or partial copies before publication.
        BOOL allCopied = YES;
        for (NSString *root in roots) {
            if (![fm fileExistsAtPath:[temporary URLByAppendingPathComponent:root].path]) allCopied = NO;
        }
        if (!allCopied) break;
        NSArray *files = Inventory(temporary, roots, error);
        if (!files || ![files isEqualToArray:sourceInventory]) {
            if (error && !*error) *error = MakeError(@"Save changed during snapshot; retry after guest stop");
            break;
        }
        NSDictionary *manifest = @{@"format": @"pvz2forios-save-v1",
                                   @"createdUTC": @([NSDate date].timeIntervalSince1970),
                                   @"roots": roots, @"files": files};
        if (![manifest writeToURL:[temporary URLByAppendingPathComponent:kManifest] atomically:YES]) {
            if (error) *error = MakeError(@"Unable to write snapshot manifest");
            break;
        }
        if (!ValidateSnapshot(temporary, nil, error)) break;
        if (![fm moveItemAtURL:temporary toURL:destination error:error]) break;
        succeeded = YES;
    } while (NO);
    if (!succeeded) {
        [fm removeItemAtURL:temporary error:nil];
        if (error && !*error) *error = MakeError(@"Incomplete snapshot creation");
        return nil;
    }
    PruneLocalSnapshots();
    return destination;
}

NSArray<NSURL *> *PVZSavePendingRestores(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *inbox = DocumentsChild(@"PvZ2RestoreInbox");
    [fm createDirectoryAtURL:inbox withIntermediateDirectories:YES attributes:nil error:nil];
    NSArray<NSURL *> *children = [fm contentsOfDirectoryAtURL:inbox
                                   includingPropertiesForKeys:nil options:0 error:nil];
    NSMutableArray<NSURL *> *pending = [NSMutableArray array];
    for (NSURL *item in children) {
        if (![item.lastPathComponent hasPrefix:@"Restored-"] &&
            [fm fileExistsAtPath:[item URLByAppendingPathComponent:kManifest].path]) {
            [pending addObject:item];
        }
    }
    [pending sortUsingComparator:^NSComparisonResult(NSURL *a, NSURL *b) {
        return [b.lastPathComponent compare:a.lastPathComponent];
    }];
    return pending;
}

BOOL PVZSaveRestoreSnapshot(NSURL *snapshot, NSError **error) {
    // Caller must guarantee that the guest is not running. Never mutate live
    // files in response to background notifications or a Files copy alone.
    NSDictionary *manifest = nil;
    if (!ValidateSnapshot(snapshot, &manifest, error)) return NO;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *support = SupportParent();
    NSURL *live = LiveRoot();
    // An independently validated safety backup must precede all mutations.
    BOOL haveCurrent = NO;
    NSArray *existing = [fm contentsOfDirectoryAtURL:live
                        includingPropertiesForKeys:nil options:0 error:nil];
    for (NSURL *child in existing) if (IsSaveRoot(child.lastPathComponent)) haveCurrent = YES;
    if (haveCurrent && !PVZSaveCreateSnapshot(@"prerestore", error)) return NO;

    NSString *uuid = [NSUUID UUID].UUIDString;
    NSURL *stage = [support URLByAppendingPathComponent:
                    [@"PvZ2Restore-stage-" stringByAppendingString:uuid] isDirectory:YES];
    NSURL *previous = [support URLByAppendingPathComponent:
                       [@"PvZ2Restore-rollback-" stringByAppendingString:uuid] isDirectory:YES];
    if (![fm createDirectoryAtURL:stage withIntermediateDirectories:YES attributes:nil error:error] ||
        ![fm createDirectoryAtURL:previous withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    BOOL copied = YES;
    for (NSString *root in manifest[@"roots"]) {
        if (![fm copyItemAtURL:[snapshot URLByAppendingPathComponent:root]
                       toURL:[stage URLByAppendingPathComponent:root] error:error]) {
            copied = NO;
            break;
        }
    }
    if (!copied || ![Inventory(stage, manifest[@"roots"], error)
                      isEqualToArray:manifest[@"files"]]) {
        [fm removeItemAtURL:stage error:nil];
        [fm removeItemAtURL:previous error:nil];
        if (error && !*error) *error = MakeError(@"Restore staging validation failed");
        return NO;
    }
    [fm createDirectoryAtURL:live withIntermediateDirectories:YES attributes:nil error:nil];
    NSMutableArray<NSString *> *oldRoots = [NSMutableArray array];
    NSMutableArray<NSString *> *installed = [NSMutableArray array];
    BOOL ok = YES;
    NSArray<NSURL *> *liveChildren = [fm contentsOfDirectoryAtURL:live
                                  includingPropertiesForKeys:nil options:0 error:nil];
    for (NSURL *item in liveChildren) {
        NSString *name = item.lastPathComponent;
        if (!IsSaveRoot(name)) continue;
        if (![fm moveItemAtURL:item toURL:[previous URLByAppendingPathComponent:name] error:error]) {
            ok = NO;
            break;
        }
        [oldRoots addObject:name];
    }
    if (ok) for (NSString *root in manifest[@"roots"]) {
        if (![fm moveItemAtURL:[stage URLByAppendingPathComponent:root]
                        toURL:[live URLByAppendingPathComponent:root] error:error]) {
            ok = NO;
            break;
        }
        [installed addObject:root];
    }
    if (!ok) {
        for (NSString *root in installed) [fm removeItemAtURL:[live URLByAppendingPathComponent:root] error:nil];
        for (NSString *root in oldRoots) {
            [fm moveItemAtURL:[previous URLByAppendingPathComponent:root]
                         toURL:[live URLByAppendingPathComponent:root] error:nil];
        }
        [fm removeItemAtURL:stage error:nil];
        // Keep rollback directory on disk if any individual rollback failed.
        return NO;
    }
    [fm removeItemAtURL:stage error:nil];
    [fm removeItemAtURL:previous error:nil];
    // Do not delete the restore inbox copy. Rename it so it won't prompt again.
    NSURL *done = [snapshot.URLByDeletingLastPathComponent URLByAppendingPathComponent:
                    [@"Restored-" stringByAppendingString:snapshot.lastPathComponent]];
    [fm moveItemAtURL:snapshot toURL:done error:nil];
    return YES;
}