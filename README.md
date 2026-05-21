# dshield-honeypot-aws

Terraform deployment of a [DShield / SANS ISC](https://github.com/DShield-ISC/dshield) honeypot on AWS EC2.

The honeypot exposes SSH, Telnet, and HTTP decoy services to the internet and forwards connection logs to the SANS Internet Storm Center global threat intelligence platform.

## Architecture

```
Internet
    |
    +-- :22   SSH decoy   --+
    +-- :23   Telnet decoy  +---> EC2 (t3.nano) ---> SANS ISC logs
    +-- :80   HTTP decoy  --+

    :12222  Admin SSH --------> your IP only
```

## Requirements

- Terraform >= 1.5
- AWS credentials configured (`aws configure` or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`)
- SANS ISC account: https://isc.sans.edu/register.html
- DShield API key: https://isc.sans.edu/myaccount.html

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

terraform init
terraform plan
terraform apply
```

## Variables

| Name | Description | Required |
|------|-------------|----------|
| `aws_region` | AWS region | no (default: `eu-west-3`) |
| `admin_ip` | Your public IP for admin SSH access | yes |
| `ssh_public_key` | SSH public key content | yes |
| `dshield_email` | SANS ISC account email | yes |
| `dshield_apikey` | DShield API key | yes |

## Estimated cost

| Resource | Type | ~$/month |
|----------|------|----------|
| EC2 | t3.nano | $4 |
| Elastic IP | - | $3 |
| EBS | 20 GB gp3 | $1.6 |
| **Total** | | **~$9** |

## After deployment

```bash
# Get SSH command
terraform output ssh_command

# Check DShield service
ssh -p 12222 admin@<ip> "sudo systemctl status dshield"
```

Data appears on https://isc.sans.edu/myreports.html within 24 hours.

## Teardown

```bash
terraform destroy
```

## References

- DShield project: https://github.com/DShield-ISC/dshield
- SANS ISC Diary (Pi Zero): https://isc.sans.edu/diary/26260
- SANS ISC dashboard: https://isc.sans.edu/myreports.html
