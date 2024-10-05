# ddns-route53

`ddns-route53` is a utility for creating a dynamic DNS ("DDNS") solution for zones hosted by [AWS Route53](https://aws.amazon.com/route53/). Other hosting providers are **not supported**.

## Overview

`ddns-route53` works by first attempting to identify the public IPv4 or IPv6 address it is running at, using several possible algorithms set in its configuration. Once its address(es) are determined, it compares the result with applicable resource records hosted in a [Route53](https://aws.amazon.com/route53/)-hosted zone and, if they differ, update the zone to match.

## Building

1. Install the rust compiler, using either your distribution's sources or https://www.rust-lang.org/tools/install
1. Download the `ddns-route53` source from GitHub, or check it out using git:
   ```
   git clone https://github.com/ansible/ansible.git
   ```
1. Enter into the directory where you downloaded it, and run
   ```
   cargo build --release
   ```
1. Wait for it to download dependencies and compile the tool (this can take a few minutes).
1. Once done, you'll find the utility at `target/release/ddns-route53`.

## AWS configuration

Querying and updating a [Route53](https://aws.amazon.com/route53/) zone requires an IAM identity with appropriate permissions.

### Example Route53/IAM configuration

The following example shows how to create an IAM user with limited permissions use by `ddns-route53`.

 1. Determine the "Zone ID" for your [Route53](https://aws.amazon.com/route53/)-hosted DNS zone:
    1. Log into the [Route53 console](https://console.aws.amazon.com/iam/home) as a user with sufficient administrative rights.
    1. In the Dashboard, click on "Hosted zones".
    1. Select the DNS zone for which you want a dynamic-DNS update.
    1. Expand "Hosted zone details".
    1. Make note of the "Hosted zone ID" — you'll need it again later.
 1. Create an IAM user that can update the zone:
    1. Log into the [IAM console](https://console.aws.amazon.com/iam/home) as a user with sufficient administrative rights.
    1. In the Dashboard, find "Access Management" and click on "Policies".
    1. Click "Create policy"
    1. Under the Policy editor, click on "JSON", and add the following content:
        ```json
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "route53:ChangeResourceRecordSets",
                    "Resource": "arn:aws:route53:::hostedzone/Z01234567890ABCDEFGHI",
                    "Condition": {
                        "ForAllValues:StringEquals": {
                            "route53:ChangeResourceRecordSetsNormalizedRecordNames": "home.example.com",
                            "route53:ChangeResourceRecordSetsRecordTypes": [
                                "A",
                                "AAAA"
                            ]
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Action": "route53:ListResourceRecordSets",
                    "Resource": "arn:aws:route53:::hostedzone/Z01234567890ABCDEFGHI"
                },
                {
                    "Effect": "Allow",
                    "Action": "route53:GetChange",
                    "Resource": "arn:aws:route53:::change/*"
                }
            ]
        }
        ```

        > The `"NormalizedRecordNames"` entry above should be changed to match the fully-qualified domain name of the record you want maintained.

        > The `"Resource"` entries above must be updated to give the "ARN" of your zone, which is comprised of `"arn:aws:route53:::hostedzone/"` followed by your zone ID. If your Zone ID is `Z12345` (for example), then its ARN is `"arn:aws:route53:::hostedzone/Z12345"` — so that's what you should put under the `"Resource"` sections of the IAM policy.
    1. Click "Next"
    1. Set a suitable policy name; e.g. `DynamicDNS-home.example.com`
    1. Scroll down to the bottom and click "Create Policy"
    
    1. In the Dashboard, find "Access Management" and click on "Users".
    1. Click on "Create user"
    1. Enter a suitable name into the "User name" field; for example `ddns-user`. Then click "Next"
        > Other options on this page can be skipped.
    1. On the "Set Permissions" page under "Permissions options", select "Attach policies directly"
    1. Under "Permissions policies", enter the policy name you chose above; that will filter the list of available policies to just those containing the name you gave; find your policy, and place a checkmark in the box next to its name
    1. Click "Next"
    1. Click "Create user"
 1. Create an access key for your IAM user
    1. Log into the [IAM console](https://console.aws.amazon.com/iam/home) as a user with sufficient administrative rights.
    1. In the Dashboard, find "Access Management" and click on "Users".
    1. Click on the user you created
    1. Click on the "Security credentials" tab
    1. Under "Access keys", click on "Create access key"
    1. Under use case, select "Other", and click "Next"
    1. (Optionally) Set a description, such as `DDNS update key`.
    1. Click "Create access key"
    1. Make note of the "Access key" and the "Secret access key", or use the "Download .csv file" button — you'll need these to setup the client configuration (below)
       > Always keep your AWS IAM credentials confidential!

## Client configuration

A template configuration file is available at [`example/ddns-route53.conf`](example/ddns-route53.conf). (It uses the [TOML](https://toml.io/en/) file format.)

At a minimum, you should set the following:
 * The `host_name` value
 * The `aws_route53_zone_id`
   > This value is _technically_ optional, because `ddns-route53` can determine this dynamically; however that requires the extra `ListHostedZones` permission, which the example above omits.
 * You'll either need to specify the `aws_access_key_id` and `aws_secret_access_key` values for the IAM user you created, or else you'll need to [make them available to the local user under which you will run `ddns-route53`](https://docs.aws.amazon.com/sdkref/latest/guide/access-iam-users.html#stepauthIamUser). 

Various other configuration options exist; see [`example/ddns-route53.conf`](example/ddns-route53.conf) for more.

## Running

If the configuration file is in your current directory and is named `ddns-route53.conf`, then you can run the tool directly with no arguments:
```
ddns-route53
```

Alternatively, if your file has a different name or location, you can run it as:
```
ddns-route53 -c /path/to/config/file
```

This tool is a simple, "fire and forget" utility. That is, it checks your current IP address _right now_ and updates Route53 if it differs. It **does not** recheck later.

If you want to run it periodically, you can use a third-party scheduler to do so. For example, the Windows Task Scheduler, Mac iCal, Mac launchd, and Unix/Linux cron jobs, and Linux systemd can all be configured to run `ddns-route53` periodically.


## License

[MIT](https://opensource.org/license/mit) or [Apache-2.0](https://opensource.org/license/apache-2-0) at the user's choice.