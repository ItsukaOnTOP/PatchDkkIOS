#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

%hook HttpAsynConnection

- (BOOL)shouldTrustProtectionSpace:(id)arg1 {
    return YES;
}

- (void)startRequest:(NSMutableURLRequest *)request {
    NSString *origURL = request.URL.absoluteString;

    if ([origURL containsString:@"ishin-global.aktsk.com"]) {
        NSString *newURL = [origURL stringByReplacingOccurrencesOfString:@"ishin-global.aktsk.com"
                                                               withString:@"dokkan-transcend.com"];
        NSURL *url = [NSURL URLWithString:newURL];
        [request setURL:url];
        origURL = newURL;
    }

    if ([origURL containsString:@"//user/mydata"]) {
        NSString *newURL = [origURL stringByReplacingOccurrencesOfString:@"//user/mydata"
                                                               withString:@"/user/mydata"];
        [request setURL:[NSURL URLWithString:newURL]];
        origURL = newURL;
    }

    if ([origURL containsString:@"//cards"]) {
        NSString *newURL = [origURL stringByReplacingOccurrencesOfString:@"//cards"
                                                               withString:@"/cards"];
        [request setURL:[NSURL URLWithString:newURL]];
    }

    %orig(request);
}

%end
