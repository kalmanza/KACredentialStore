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
//    This program is free software; you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation; either version 2 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License along
//    with this program; if not, write to the Free Software Foundation, Inc.,
//    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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
