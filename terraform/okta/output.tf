output "app_client_id" {
  value = okta_app_oauth.example.client_id
}

output "app_client_secret" {
  value = okta_app_oauth.example.client_secret
  sensitive = true
}