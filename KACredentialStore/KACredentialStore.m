//
//  KACredentialStore.m
//  KACredentialStore
//
//  Created by Kevin Almanza on 12/6/14.
//

#import "KACredentialStore.h"
@import LocalAuthentication;

static NSString * const authReason = @"Please verify your identity to retreive your account info";

@implementation KACredentialPair
@end

@interface KACredentialStore ()
{
    NSArray *allSecItemsForDomain;
    LAContext *authContext;
}
@property (nonatomic, strong) NSData *secItemDomain;
@end

@implementation KACredentialStore

- (instancetype)init
{
    self = [super init];
    if (self) {
        
        authContext = [[LAContext alloc] init];
        NSError *error = nil;
        _deviceCanAuthorizeWithBioMetrics = [authContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
        
        OSStatus status;
        allSecItemsForDomain = [self queryForAllItemsInDomainStatus:&status];
        _userHasExistingCredentials = (status == noErr);
    }
    return self;
}

- (NSData *)secItemDomain
{
    if (!_secItemDomain) {
        _secItemDomain = [@"com.KACredentialStore" dataUsingEncoding:NSUTF8StringEncoding];
    }
    return _secItemDomain;
}

- (NSMutableDictionary *)domainDictionary
{
    NSMutableDictionary *query = [NSMutableDictionary new];
    query[(__bridge  id)(kSecClass)] = (__bridge id)(kSecClassInternetPassword);
    query[(__bridge  id)(kSecAttrSecurityDomain)] = self.secItemDomain;
    return query;
}

- (BOOL)setPassword:(NSString *)password forAccount:(NSString *)userAccount
{
    BOOL success = NO;
    
    if (!(password.length && userAccount.length)) {
        [[NSException exceptionWithName:@"KACredentialStoreException" reason:@"password or account was empty"  userInfo:@{@"password":password ? password : @"", @"userAccount":userAccount ? userAccount : @""}] raise];
    }
    
    OSStatus status;
    NSString *passwordForAccount = [self passwordForAccount:userAccount status:&status];
    
    if (status == errSecItemNotFound) {
        
        [self addPassword:password ForAccount:userAccount status:&status];
    
    } else if (passwordForAccount.length) {
        
        [self updatePassword:password forAccount:userAccount status:&status];
        
    } else {
        [[NSException exceptionWithName:@"KACredentialStoreException" reason:@"could not find existing account or create new entry for account"  userInfo:nil] raise];
    }
    
    success = (status == noErr);
    return success;
}

- (BOOL)removeAccount:(NSString *)account
{
    BOOL success = NO;
    
    if (!(account.length)) {
        [[NSException exceptionWithName:@"KACredentialStoreException" reason:@"account was empty in removeAccount: method" userInfo:@{@"account":account ? account : @""}] raise];
    }
    OSStatus status;
    [self deleteAccount:account status:&status];
    
    return success;
}

- (NSMutableArray *)credentialsForAuthenticatedUser
{
    if (!_deviceCanAuthorizeWithBioMetrics) {
        [[NSException exceptionWithName:@"KACredentialStoreException" reason:@"user cannot authorize with biometrics and cannot use this class" userInfo:nil] raise];
    }
    
    NSMutableArray *creds = [NSMutableArray new];
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    
    [authContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:authReason reply:^(BOOL success, NSError *error) {
        if (success) {
            [allSecItemsForDomain enumerateObjectsUsingBlock:^(NSDictionary *obj, NSUInteger idx, BOOL *stop) {
                NSString *account = [NSString stringWithUTF8String:[obj[(__bridge id) kSecAttrAccount] bytes]];
                if (account.length) {
                    NSString *password = [self passwordForAccount:account status:nil];
                    KACredentialPair *pair = [[KACredentialPair alloc] init];
                    pair.accountName = account;
                    pair.password = password;
                    [creds addObject:pair];
                }
            }];
        }
        dispatch_semaphore_signal(semaphore);
    }];
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    
    return creds;
}

- (void)credentialsForAuthenticatedUserWithCompletion:(void (^)(BOOL, NSArray *, NSError *))completion
{
    if (!_deviceCanAuthorizeWithBioMetrics) {
        [[NSException exceptionWithName:@"KACredentialStoreException" reason:@"user cannot authorize with biometrics and cannot use this class" userInfo:nil] raise];
    }
    
    NSMutableArray *creds = [NSMutableArray new];
    
    [authContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:authReason reply:^(BOOL success, NSError *error) {
        if (success) {
            [allSecItemsForDomain enumerateObjectsUsingBlock:^(NSDictionary *obj, NSUInteger idx, BOOL *stop) {
                NSString *account = [NSString stringWithUTF8String:[obj[(__bridge id) kSecAttrAccount] bytes]];
                if (account.length) {
                    NSString *password = [self passwordForAccount:account status:nil];
                    KACredentialPair *pair = [[KACredentialPair alloc] init];
                    pair.accountName = account;
                    pair.password = password;
                    [creds addObject:pair];
                }
            }];
        }
        if (completion) {
            completion(success, creds, error);
        }
    }];
}

- (NSString *)passwordForAccount:(NSString *)account status:(OSStatus *)status
{
    CFDataRef *result;
    NSMutableDictionary *accountQuery = [self domainDictionary];
    accountQuery[(__bridge __strong id)(kSecAttrAccount)] = [account dataUsingEncoding:NSUTF8StringEncoding];
    accountQuery[(__bridge __strong id)(kSecReturnData)] = (__bridge id)(kCFBooleanTrue);
    OSStatus localStatus = SecItemCopyMatching((__bridge CFDictionaryRef)(accountQuery), (CFTypeRef *)&result);
    if (status) {
        *status = localStatus;
    }
    NSString *password;
    if (localStatus == noErr) {
        NSData *passwordData = CFBridgingRelease(result);
        password = [NSString stringWithUTF8String:passwordData.bytes];
    }
    return password;
}

- (void)addPassword:(NSString *)password ForAccount:(NSString *)account status:(OSStatus *)status
{
    NSMutableDictionary *accountQuery = [self domainDictionary];
    accountQuery[(__bridge  id)(kSecAttrAccount)] = [account dataUsingEncoding:NSUTF8StringEncoding];
    accountQuery[(__bridge  id)(kSecValueData)] = [password dataUsingEncoding:NSUTF8StringEncoding];
    OSStatus localStatus;
    localStatus = SecItemAdd((__bridge CFDictionaryRef)(accountQuery), nil);
    if (status) {
        *status = localStatus;
    }
}

- (void)updatePassword:(NSString *)newPassword forAccount:(NSString *)account status:(OSStatus *)status
{
    NSMutableDictionary *accountQuery = [self domainDictionary];
    accountQuery[(__bridge  id)(kSecAttrAccount)] = [account dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary *updatedAttributes = [NSMutableDictionary new];
    updatedAttributes[(__bridge __strong id)(kSecValueData)] = [newPassword dataUsingEncoding:NSUTF8StringEncoding];
    OSStatus localStatus;
    localStatus = SecItemUpdate((__bridge CFDictionaryRef)(accountQuery), (__bridge CFDictionaryRef)(updatedAttributes));
    if (status) {
        *status = localStatus;
    }
}

- (void)deleteAccount:(NSString *)account status:(OSStatus *)status
{
    NSMutableDictionary *accountQuery = [self domainDictionary];
    accountQuery[(__bridge  id)(kSecAttrAccount)] = [account dataUsingEncoding:NSUTF8StringEncoding];
    
    OSStatus localStatus;
    localStatus = SecItemDelete((__bridge CFDictionaryRef)accountQuery);
    if (status) {
        *status = localStatus;
    }
}

- (NSArray *)queryForAllItemsInDomainStatus:(OSStatus *)status
{
    CFArrayRef cfResults;
    NSArray *results;
    NSMutableDictionary *query = [self domainDictionary];
    query[(__bridge  id)(kSecMatchLimit)] = (__bridge id)(kSecMatchLimitAll);
    query[(__bridge  id)(kSecReturnAttributes)] = (__bridge id)(kCFBooleanTrue);
    OSStatus localStatus;
    localStatus = SecItemCopyMatching((__bridge CFDictionaryRef)(query), (CFTypeRef *)&cfResults);
    if (localStatus == noErr) {
        results = CFBridgingRelease(cfResults);
    }
    if (status) {
        *status = localStatus;
    }
    
    return results;
}

@end
