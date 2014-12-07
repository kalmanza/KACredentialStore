//
//  ViewController.m
//
//  Created by Kevin Almanza on 12/6/14.
//

#import "ViewController.h"
#import "KACredentialStore.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}
// this should be a better experience but it's just for fun tests right now
- (IBAction)loginAction:(id)sender
{
    KACredentialStore *bioLogin = [[KACredentialStore alloc] init];
    if (![bioLogin deviceCanAuthorizeWithBioMetrics]) {
        return;
    }
    if (bioLogin.userHasExistingCredentials) {
        
        if (self.password.text.length && self.account.text.length) {
            [bioLogin setPassword:self.password.text forAccount:self.account.text];
        } else {
            NSArray *creds = [bioLogin credentialsForAuthenticatedUser];
            KACredentialPair *firstPair = [creds firstObject];
            if (firstPair) {
                self.account.text = firstPair.accountName;
                self.password.text = firstPair.password;
            }
        }
    } else {
        BOOL success;
        if (self.password.text.length && self.account.text.length) {
             success = [bioLogin setPassword:self.password.text forAccount:self.account.text];
        }
        if (success) {
            NSLog(@"save/update worked");
        } else {
            NSLog(@"FAIL");
        }
    }
}

@end
