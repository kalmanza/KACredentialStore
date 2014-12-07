//
//  KACredentialStore.h
//
//  This class allows you to perform synchonous processing of touchID
//  verification.  After being verified the users credentials are
//  passed as pairs to the sender.
//
//  Use the two properties to determine if the user can use the service
//  and if the user has anything to fetch from the service.
//
//  Created by Kevin Almanza on 12/6/14.
//

#import <Foundation/Foundation.h>

@interface KACredentialPair : NSObject

@property (nonatomic, copy) NSString *accountName;

@property (nonatomic, copy) NSString *password;

@end



@interface KACredentialStore : NSObject

@property (nonatomic) BOOL userHasExistingCredentials;

@property (nonatomic) BOOL deviceCanAuthorizeWithBioMetrics;


/*
 * This method will set a password for an account in the apps keychain
 * or will update the existing account entry with the password
 */

- (BOOL)setPassword:(NSString *)password forAccount:(NSString *)userAccount;



/*
 * This will remove an account from the keychain
 */

- (BOOL)removeAccount:(NSString *)account;


/*
 * This will return all credential pairs for the user after he has finished
 * attempting to authenticating himself
 */

- (NSArray *)credentialsForAuthenticatedUser;



/*
 * This will asynchronously perform a block you provide it after the user
 * has attempted to authenticate
 */

- (void)credentialsForAuthenticatedUserWithCompletion:(void(^)(BOOL success, NSArray *credentials, NSError *error))completion;


@end
