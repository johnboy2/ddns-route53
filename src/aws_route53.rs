use aws_config::profile::ProfileFileCredentialsProvider;
use aws_sdk_route53::config::Credentials;
use aws_sdk_route53::Client;
use aws_types::region::Region;


pub async fn get_client(
    aws_profile: &Option<String>,
    aws_access_key_id: &Option<String>,
    aws_secret_access_key: &Option<String>,
    aws_region: &Option<String>,
) -> Client {
    let sdk_config = ::aws_config::load_from_env().await;
    let mut config_builder = ::aws_sdk_route53::config::Builder::from(&sdk_config);

    if aws_region.is_some() {
        let region = Region::new(aws_region.as_ref().unwrap().to_owned());
        config_builder.set_region(Some(region));
    }

    if aws_access_key_id.is_some() && aws_secret_access_key.is_some() {
        let creds = Credentials::new(
            aws_access_key_id.as_ref().unwrap(), 
            aws_secret_access_key.as_ref().unwrap(), 
            None,
            None,
            "configfile"
        );
        config_builder = config_builder.credentials_provider(creds);
    } else if aws_profile.is_some() {
        let profile = ProfileFileCredentialsProvider::builder()
            .profile_name(aws_profile.as_ref().unwrap())
            .build()
        ;
        config_builder = config_builder.credentials_provider(profile);
    }

    let config = config_builder.build();
    let client = Client::from_conf(config);

    client   
}

