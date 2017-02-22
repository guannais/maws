# maws
Active Directory - ADFS - MFA Login - AWS Shell console interactive
Fork from https://github.com/yulshub/yaws

# Requirements
* bash 3+
* jq https://stedolan.github.io/jq/download/
* bash aws cli https://github.com/aws/aws-cli
* python3
* python3 bs module
* python3 boto module
* python3 argparse module

# Instructions

1 This is a fork from https://github.com/yulshub/yaws with a python development using AWS STS Asumme Role.
2 Configure vars:
* alias_roles_dic
* regions_roles_dic (if required)
* domain
* login_domain

# Run
```bash
python aws-adfs-saml-mfa.py