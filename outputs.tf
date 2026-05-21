output "honeypot_public_ip" {
  description = "Honeypot public IP address - register this on isc.sans.edu"
  value       = aws_eip.honeypot.public_ip
}

output "ssh_command" {
  description = "Admin SSH command"
  value       = "ssh -p 12222 admin@${aws_eip.honeypot.public_ip}"
}

output "sans_dashboard" {
  description = "SANS ISC reporting dashboard"
  value       = "https://isc.sans.edu/myreports.html"
}
